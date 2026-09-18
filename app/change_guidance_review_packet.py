from __future__ import annotations

"""Human-review packets for change-guidance calibration and drift.

The packet joins P9 shadow calibration with P10 longitudinal drift to produce
bounded, deterministic review artifacts. It never mutates production policy,
weights, thresholds, ranking, workflow ordering, evidence, Admission, or
validation behavior.
"""

import hashlib
from typing import Any, Mapping

from change_guidance_calibration import (
    CHANGE_GUIDANCE_CALIBRATION_RULE_VERSION,
    CHANGE_GUIDANCE_CALIBRATION_VERSION,
    change_guidance_calibration_report,
)
from change_guidance_drift import (
    CHANGE_GUIDANCE_DRIFT_RULE_VERSION,
    CHANGE_GUIDANCE_DRIFT_VERSION,
    change_guidance_drift_report,
)
from core import Database

CHANGE_GUIDANCE_REVIEW_PACKET_VERSION = "1.0.0"
CHANGE_GUIDANCE_REVIEW_PACKET_RULE_VERSION = "2026.09.18.1"
MAX_PACKETS = 100


def _proposal_id(
    signal_type: str,
    *,
    target: str,
    calibration_status: str,
    drift_status: str,
    anchor_at: str,
) -> str:
    material = "|".join(
        [
            CHANGE_GUIDANCE_REVIEW_PACKET_RULE_VERSION,
            str(target or "*"),
            signal_type,
            calibration_status,
            drift_status,
            anchor_at,
        ]
    )
    return "CGRP-" + hashlib.sha256(
        material.encode("utf-8", "replace")
    ).hexdigest()[:16]


def _slice_rows(
    rows: Any,
    *,
    signal_type: str,
    key: str,
    limit: int = 8,
) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        return []
    selected = [
        dict(row)
        for row in rows
        if isinstance(row, Mapping)
        and str(row.get("signal_type") or "") == signal_type
    ]
    selected.sort(
        key=lambda row: (
            -int(row.get("feedback_count") or 0),
            str(row.get(key) or ""),
        )
    )
    return selected[: max(1, int(limit))]


def _proposal_direction(
    calibration_status: str,
    drift_status: str,
) -> tuple[str, str]:
    """Return a non-executable human-review direction and rationale."""
    if (
        calibration_status == "utility_watch"
        and drift_status in {"stable", "utility_improvement_watch"}
    ):
        return (
            "consider_manual_promotion_review",
            "Explicit usefulness is strong and longitudinal monitoring is stable or improving. Review whether a separately tested production policy change is warranted.",
        )
    if (
        calibration_status == "noise_watch"
        and drift_status == "noise_increase_watch"
    ):
        return (
            "consider_manual_noise_mitigation_review",
            "Explicit noise is elevated and has increased longitudinally. Review extraction/provenance and whether a separate production mitigation proposal is warranted.",
        )
    if drift_status == "utility_decline_watch":
        return (
            "consider_manual_regression_review",
            "Longitudinal usefulness declined materially. Review signal semantics, cohort mix, and recent implementation/deployment changes before any production action.",
        )
    return (
        "retain_shadow_monitoring",
        "Evidence does not support a conservative promotion or mitigation review direction yet; continue collecting explicit feedback.",
    )


def change_guidance_review_packets(
    db: Database,
    *,
    target: str = "",
    calibration_limit: int = 5000,
    drift_limit: int = 5000,
    window_days: int = 30,
    max_packets: int = MAX_PACKETS,
) -> dict[str, Any]:
    """Join P9/P10 reports into deterministic, non-executable review packets."""
    calibration = change_guidance_calibration_report(
        db,
        target=str(target or ""),
        limit=calibration_limit,
    )
    drift = change_guidance_drift_report(
        db,
        target=str(target or ""),
        window_days=window_days,
        limit=drift_limit,
    )

    calibration_by_signal = {
        str(row.get("signal_type") or ""): dict(row)
        for row in calibration.get("signals", [])
        if isinstance(row, Mapping)
        and str(row.get("signal_type") or "").strip()
    }
    drift_by_signal = {
        str(row.get("signal_type") or ""): dict(row)
        for row in drift.get("signals", [])
        if isinstance(row, Mapping)
        and str(row.get("signal_type") or "").strip()
    }

    packets: list[dict[str, Any]] = []
    for signal_type in sorted(set(calibration_by_signal) | set(drift_by_signal)):
        cal = calibration_by_signal.get(signal_type, {})
        trend = drift_by_signal.get(signal_type, {})
        calibration_status = str(
            cal.get("shadow_status") or "insufficient_feedback"
        )
        drift_status = str(
            trend.get("drift_status") or "insufficient_history"
        )
        feedback_count = int(cal.get("feedback_count") or 0)
        calibration_ready = (
            feedback_count
            >= int(calibration.get("minimum_feedback_per_signal") or 5)
            and calibration_status != "insufficient_feedback"
        )
        history_ready = bool(trend.get("history_sufficient"))
        direction, rationale = _proposal_direction(
            calibration_status,
            drift_status,
        )
        ready = bool(
            calibration_ready
            and history_ready
            and direction != "retain_shadow_monitoring"
        )
        review_status = (
            "ready_for_manual_review"
            if ready
            else "collect_more_data"
        )

        target_slices = _slice_rows(
            drift.get("recent_target_slices"),
            signal_type=signal_type,
            key="target",
        )
        family_slices = _slice_rows(
            drift.get("recent_family_slices"),
            signal_type=signal_type,
            key="family",
        )
        anchor_at = str(drift.get("anchor_at") or "")
        packet_id = _proposal_id(
            signal_type,
            target=str(target or ""),
            calibration_status=calibration_status,
            drift_status=drift_status,
            anchor_at=anchor_at,
        )
        packets.append(
            {
                "proposal_id": packet_id,
                "signal_type": signal_type,
                "review_status": review_status,
                "proposal_direction": direction,
                "review_rationale": rationale,
                "calibration": {
                    "shadow_status": calibration_status,
                    "feedback_count": feedback_count,
                    "task_count": int(cal.get("task_count") or 0),
                    "feedback_coverage": cal.get("feedback_coverage"),
                    "useful_rate": cal.get("useful_rate"),
                    "useful_rate_wilson_95": cal.get("useful_rate_wilson_95"),
                    "noisy_rate": cal.get("noisy_rate"),
                    "noisy_rate_wilson_95": cal.get("noisy_rate_wilson_95"),
                    "families": list(cal.get("families") or [])[:20],
                },
                "drift": {
                    "drift_status": drift_status,
                    "history_sufficient": history_ready,
                    "previous": dict(trend.get("previous") or {}),
                    "recent": dict(trend.get("recent") or {}),
                    "useful_rate_delta_recent_minus_previous": trend.get(
                        "useful_rate_delta_recent_minus_previous"
                    ),
                    "noisy_rate_delta_recent_minus_previous": trend.get(
                        "noisy_rate_delta_recent_minus_previous"
                    ),
                    "anchor_at": anchor_at,
                    "window_days": int(drift.get("window_days") or window_days),
                },
                "recent_target_slices": target_slices,
                "recent_family_slices": family_slices,
                "review_checklist": [
                    "Verify explicit feedback provenance and inspect representative task notes/audit events.",
                    "Check whether recent target/family composition explains the observed calibration or drift.",
                    "Review the underlying Derived Change extraction/provenance behavior for this signal type.",
                    "If a production policy change is still desired, create a separate explicit code/config proposal with independent tests and review.",
                    "Re-run shadow calibration and longitudinal drift after any separately reviewed production change before drawing new conclusions.",
                ],
                "prohibited_automatic_actions": [
                    "do not edit Meta Ranker weights",
                    "do not edit thresholds",
                    "do not change Queue score",
                    "do not change Investigation Workflow task ordering",
                    "do not mark Evidence Gap requirements present",
                    "do not change Admission or target-evidence confidence",
                    "do not change validation eligibility or approvals",
                    "do not execute network requests",
                ],
                "production_change_allowed": False,
                "automatic_activation": False,
                "requires_separate_policy_change": True,
                "requires_human_review": True,
            }
        )

    direction_order = {
        "consider_manual_noise_mitigation_review": 0,
        "consider_manual_regression_review": 1,
        "consider_manual_promotion_review": 2,
        "retain_shadow_monitoring": 3,
    }
    packets.sort(
        key=lambda row: (
            0 if row.get("review_status") == "ready_for_manual_review" else 1,
            direction_order.get(str(row.get("proposal_direction") or ""), 9),
            -int(row.get("calibration", {}).get("feedback_count") or 0),
            str(row.get("signal_type") or ""),
        )
    )
    packets = packets[: max(1, min(int(max_packets or MAX_PACKETS), MAX_PACKETS))]
    ready_count = sum(
        row.get("review_status") == "ready_for_manual_review"
        for row in packets
    )

    return {
        "version": CHANGE_GUIDANCE_REVIEW_PACKET_VERSION,
        "rule_version": CHANGE_GUIDANCE_REVIEW_PACKET_RULE_VERSION,
        "target": str(target or ""),
        "activation": "human_review_only",
        "packet_count": len(packets),
        "ready_for_manual_review_count": ready_count,
        "collect_more_data_count": len(packets) - ready_count,
        "packets": packets,
        "source_reports": {
            "calibration": {
                "version": CHANGE_GUIDANCE_CALIBRATION_VERSION,
                "rule_version": CHANGE_GUIDANCE_CALIBRATION_RULE_VERSION,
                "activation": str(calibration.get("activation") or "shadow_only"),
            },
            "drift": {
                "version": CHANGE_GUIDANCE_DRIFT_VERSION,
                "rule_version": CHANGE_GUIDANCE_DRIFT_RULE_VERSION,
                "activation": str(drift.get("activation") or "monitoring_only"),
                "anchor_at": str(drift.get("anchor_at") or ""),
                "window_days": int(drift.get("window_days") or window_days),
            },
        },
        "interpretation": {
            "proposal_is_not_policy_change": True,
            "proposal_is_not_numeric_weight_or_threshold": True,
            "proposal_is_not_causal_conclusion": True,
            "manual_review_is_required": True,
            "separate_explicit_policy_change_is_required": True,
            "automatic_activation": False,
        },
        "safety": {
            "human_review_only": True,
            "may_change_meta_ranker_weights": False,
            "may_change_thresholds": False,
            "may_change_queue_score": False,
            "may_change_task_ordering": False,
            "may_change_target_evidence": False,
            "may_change_admission": False,
            "may_change_validation": False,
            "network_requests": False,
        },
        "limitations": [
            "Packets summarize subjective, non-randomized analyst feedback and descriptive drift; they are not vulnerability labels or causal evidence.",
            "A ready packet requires both sufficient P9 calibration feedback and sufficient P10 longitudinal history.",
            "Proposal directions intentionally contain no numeric weight, threshold, patch, or executable configuration.",
            "Target/family slices help inspect cohort composition but do not establish that a signal itself caused the observed outcome.",
            "Any production change requires a separate explicit code/config change, independent tests, review, and normal merge controls.",
        ],
    }


__all__ = [
    "CHANGE_GUIDANCE_REVIEW_PACKET_VERSION",
    "CHANGE_GUIDANCE_REVIEW_PACKET_RULE_VERSION",
    "change_guidance_review_packets",
]
