from __future__ import annotations

"""Compatibility surface for the authenticated API plus vulnerability intelligence.

The established API server remains in ``api_server_core``.  This module keeps the
public ``api_server`` import contract and adds one read-only Investigation Queue
endpoint without changing existing routes or authentication semantics.
"""

import urllib.parse
from typing import Any

import api_server_core as _base
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
from change_guidance_evaluation import (
    CHANGE_GUIDANCE_EVALUATION_RULE_VERSION,
    CHANGE_GUIDANCE_EVALUATION_VERSION,
    change_guidance_evaluation,
)
from change_guidance_review_packet import (
    CHANGE_GUIDANCE_REVIEW_PACKET_RULE_VERSION,
    CHANGE_GUIDANCE_REVIEW_PACKET_VERSION,
    change_guidance_review_packets,
)
from change_guidance_policy_proposal import (
    CHANGE_GUIDANCE_POLICY_PROPOSAL_RULE_VERSION,
    CHANGE_GUIDANCE_POLICY_PROPOSAL_VERSION,
    list_policy_change_proposals,
)
from correlation_engine import (
    CORRELATION_ENGINE_VERSION,
    CORRELATION_RULE_VERSION,
    investigation_queue,
)
from derived_change_advisory import (
    DERIVED_CHANGE_ADVISORY_RULE_VERSION,
    DERIVED_CHANGE_ADVISORY_VERSION,
)
from meta_ranker import META_RANKER_VERSION, META_RANKER_RULE_VERSION


INVESTIGATION_API_VERSION = "1.7.0"

for _name, _value in vars(_base).items():
    if _name not in {
        "__name__",
        "__loader__",
        "__package__",
        "__spec__",
        "__file__",
        "__cached__",
        "__builtins__",
    }:
        globals()[_name] = _value


_ORIGINAL_DO_GET = getattr(_base, "_VI_ORIGINAL_API_DO_GET", _base.APIHandler.do_GET)
_base._VI_ORIGINAL_API_DO_GET = _ORIGINAL_DO_GET


def _latest_analysis_id(db: Any) -> str:
    latest = db.one(
        "SELECT id FROM analysis_runs WHERE status='success' "
        "ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1"
    )
    return str(latest["id"]) if latest else ""


def investigation_queue_payload(
    db: Any,
    *,
    analysis_id: str = "",
    target: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """Return the stable API envelope for the cluster-deduplicated queue."""
    selected_analysis = str(analysis_id or "").strip() or _latest_analysis_id(db)
    bounded_limit = max(1, min(500, int(limit or 50)))
    items = (
        investigation_queue(
            db,
            selected_analysis,
            target=str(target or "").strip() or None,
            limit=bounded_limit,
        )
        if selected_analysis
        else []
    )
    if hasattr(db, "all") and hasattr(db, "one"):
        evaluation = change_guidance_evaluation(
            db,
            target=str(target or "").strip(),
            limit=500,
        )
        calibration = change_guidance_calibration_report(
            db,
            target=str(target or "").strip(),
            limit=5000,
        )
        drift = change_guidance_drift_report(
            db,
            target=str(target or "").strip(),
            window_days=30,
            limit=5000,
        )
        review_packets = change_guidance_review_packets(
            db,
            target=str(target or "").strip(),
            max_packets=100,
            calibration_report=calibration,
            drift_report=drift,
        )
        policy_proposals = list_policy_change_proposals(
            db,
            target=str(target or "").strip(),
            limit=100,
        )
    else:
        evaluation = {
            "version": CHANGE_GUIDANCE_EVALUATION_VERSION,
            "rule_version": CHANGE_GUIDANCE_EVALUATION_RULE_VERSION,
            "case_count": 0,
            "comparison_ready": False,
            "unavailable": True,
            "reason": "database evaluation interface unavailable",
        }
        calibration = {
            "version": CHANGE_GUIDANCE_CALIBRATION_VERSION,
            "rule_version": CHANGE_GUIDANCE_CALIBRATION_RULE_VERSION,
            "activation": "shadow_only",
            "task_count": 0,
            "feedback_count": 0,
            "signal_count": 0,
            "unavailable": True,
            "reason": "database calibration interface unavailable",
        }
        drift = {
            "version": CHANGE_GUIDANCE_DRIFT_VERSION,
            "rule_version": CHANGE_GUIDANCE_DRIFT_RULE_VERSION,
            "activation": "monitoring_only",
            "feedback_count": 0,
            "signal_count": 0,
            "unavailable": True,
            "reason": "database drift-monitor interface unavailable",
        }
        review_packets = {
            "version": CHANGE_GUIDANCE_REVIEW_PACKET_VERSION,
            "rule_version": CHANGE_GUIDANCE_REVIEW_PACKET_RULE_VERSION,
            "activation": "human_review_only",
            "packet_count": 0,
            "ready_for_manual_review_count": 0,
            "packets": [],
            "unavailable": True,
            "reason": "database review-packet interface unavailable",
        }
        policy_proposals = []
    return {
        "api_version": INVESTIGATION_API_VERSION,
        "analysis_id": selected_analysis,
        "target": str(target or "").strip() or None,
        "count": len(items),
        "items": items,
        "change_guidance_evaluation": evaluation,
        "change_guidance_calibration": calibration,
        "change_guidance_drift": drift,
        "change_guidance_review_packets": review_packets,
        "change_guidance_policy_proposals": policy_proposals,
        "engines": {
            "meta_ranker": {
                "version": META_RANKER_VERSION,
                "rule_version": META_RANKER_RULE_VERSION,
            },
            "correlation": {
                "version": CORRELATION_ENGINE_VERSION,
                "rule_version": CORRELATION_RULE_VERSION,
            },
            "derived_change_advisory": {
                "version": DERIVED_CHANGE_ADVISORY_VERSION,
                "rule_version": DERIVED_CHANGE_ADVISORY_RULE_VERSION,
            },
            "change_guidance_evaluation": {
                "version": CHANGE_GUIDANCE_EVALUATION_VERSION,
                "rule_version": CHANGE_GUIDANCE_EVALUATION_RULE_VERSION,
            },
            "change_guidance_calibration": {
                "version": CHANGE_GUIDANCE_CALIBRATION_VERSION,
                "rule_version": CHANGE_GUIDANCE_CALIBRATION_RULE_VERSION,
                "activation": "shadow_only",
            },
            "change_guidance_drift": {
                "version": CHANGE_GUIDANCE_DRIFT_VERSION,
                "rule_version": CHANGE_GUIDANCE_DRIFT_RULE_VERSION,
                "activation": "monitoring_only",
            },
            "change_guidance_review_packets": {
                "version": CHANGE_GUIDANCE_REVIEW_PACKET_VERSION,
                "rule_version": CHANGE_GUIDANCE_REVIEW_PACKET_RULE_VERSION,
                "activation": "human_review_only",
            },
            "change_guidance_policy_proposals": {
                "version": CHANGE_GUIDANCE_POLICY_PROPOSAL_VERSION,
                "rule_version": CHANGE_GUIDANCE_POLICY_PROPOSAL_RULE_VERSION,
                "activation": "proposal_only",
            },
        },
        "safety": {
            "status": "investigation_queue_not_confirmed",
            "queue_is_not_vulnerability_confirmation": True,
            "correlation_cannot_satisfy_admission": True,
            "derived_change_is_advisory_only": True,
            "derived_change_cannot_satisfy_admission": True,
            "derived_change_is_not_double_counted_in_queue_score": True,
            "change_guidance_evaluation_is_observational_only": True,
            "change_guidance_evaluation_is_non_causal": True,
            "change_guidance_evaluation_cannot_auto_tune": True,
            "change_task_feedback_is_observational_only": True,
            "change_task_feedback_cannot_auto_tune": True,
            "change_task_feedback_is_not_target_evidence": True,
            "change_guidance_calibration_is_shadow_only": True,
            "change_guidance_calibration_cannot_auto_tune": True,
            "change_guidance_calibration_cannot_change_weights_or_thresholds": True,
            "change_guidance_drift_is_monitoring_only": True,
            "change_guidance_drift_cannot_auto_tune": True,
            "change_guidance_drift_cannot_change_weights_thresholds_or_ordering": True,
            "change_guidance_review_packets_are_human_review_only": True,
            "change_guidance_review_packets_are_non_executable": True,
            "change_guidance_review_packets_require_separate_policy_change": True,
            "change_guidance_policy_proposals_are_versioned_and_audited": True,
            "change_guidance_policy_proposals_have_no_apply_endpoint": True,
            "change_guidance_policy_proposals_cannot_change_production": True,
            "target_evidence_confidence_uses_target_observations_only": True,
        },
    }


def _do_get_with_investigation_queue(self: Any) -> None:
    path = urllib.parse.urlsplit(self.path).path
    if path != "/api/v1/analysis/investigation-queue":
        _ORIGINAL_DO_GET(self)
        return

    auth = self.auth("viewer")
    if not auth:
        return

    query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
    analysis_id = str((query.get("analysis_id") or [""])[0]).strip()
    target = str((query.get("target") or [""])[0]).strip()
    limit = _base.parse_int((query.get("limit") or [50])[0], 50, 1, 500)
    db = self.db()
    try:
        payload = investigation_queue_payload(
            db,
            analysis_id=analysis_id,
            target=target,
            limit=limit,
        )
    finally:
        db.close()
    self.send_json(payload)


_base.APIHandler.do_GET = _do_get_with_investigation_queue
APIHandler = _base.APIHandler
