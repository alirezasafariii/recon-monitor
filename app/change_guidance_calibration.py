from __future__ import annotations

"""Shadow-only calibration report for explicit change-guided task feedback.

This module summarizes analyst-recorded usefulness and terminal outcomes by
Derived Change Advisory signal type. It never modifies production weights,
thresholds, ranking, Admission, Evidence Gap, validation, or task ordering.
"""

import math
from collections import defaultdict
from typing import Any, Mapping

from core import Database, safe_json_loads

CHANGE_GUIDANCE_CALIBRATION_VERSION = "1.0.0"
CHANGE_GUIDANCE_CALIBRATION_RULE_VERSION = "2026.09.18.1"
_MIN_FEEDBACK_PER_SIGNAL = 5
_MAX_TASKS = 5000


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(float(numerator) / float(denominator), 4)


def _wilson_interval(positive: int, total: int, z: float = 1.96) -> list[float] | None:
    if total <= 0:
        return None
    p = float(positive) / float(total)
    z2 = z * z
    denominator = 1.0 + z2 / total
    centre = (p + z2 / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt((p * (1.0 - p) + z2 / (4.0 * total)) / total)
        / denominator
    )
    return [
        round(max(0.0, centre - margin), 4),
        round(min(1.0, centre + margin), 4),
    ]


def _feedback(details: Mapping[str, Any]) -> Mapping[str, Any]:
    value = details.get("analyst_feedback")
    return value if isinstance(value, Mapping) else {}


def _shadow_status(
    *,
    feedback_count: int,
    useful_count: int,
    noisy_count: int,
) -> tuple[str, str]:
    if feedback_count < _MIN_FEEDBACK_PER_SIGNAL:
        return (
            "insufficient_feedback",
            "Collect more explicit analyst ratings before drawing a signal-quality conclusion.",
        )

    useful_rate = useful_count / feedback_count
    noisy_rate = noisy_count / feedback_count
    if noisy_count >= 2 and noisy_rate >= 0.40:
        return (
            "noise_watch",
            "Review signal extraction/provenance for recurring noise; do not change production weight automatically.",
        )
    if useful_count >= 3 and useful_rate >= 0.60 and noisy_rate <= 0.20:
        return (
            "utility_watch",
            "Signal has encouraging explicit feedback; retain for observation and human review only.",
        )
    return (
        "mixed",
        "Feedback is mixed; keep current production behavior unchanged and continue collecting ratings.",
    )


def change_guidance_calibration_report(
    db: Database,
    *,
    target: str = "",
    limit: int = _MAX_TASKS,
) -> dict[str, Any]:
    """Build a bounded shadow calibration report from explicit task feedback."""
    bounded_limit = max(1, min(int(limit or _MAX_TASKS), _MAX_TASKS))
    params: list[Any] = []
    sql = (
        "SELECT t.task_id,t.task_type,t.status,t.details_json,t.created_at,t.updated_at,"
        "c.case_id,c.target,c.primary_family "
        "FROM case_autopilot_tasks t "
        "JOIN security_cases c ON c.case_id=t.case_id "
        "WHERE t.task_id LIKE 'task-change-%' "
    )
    if target:
        sql += "AND c.target=? "
        params.append(str(target))
    sql += "ORDER BY t.updated_at DESC,t.task_id DESC LIMIT ?"
    params.append(bounded_limit)

    grouped: dict[str, dict[str, Any]] = {}
    family_grouped: dict[tuple[str, str], dict[str, Any]] = {}
    total_tasks = 0
    terminal_tasks = 0
    explicit_feedback = 0
    unknown_signal_tasks = 0

    for raw in db.all(sql, tuple(params)):
        row = dict(raw)
        details = safe_json_loads(row.get("details_json"), {}, expected_type=dict)
        if (
            str(details.get("source") or "") != "derived_change_advisory"
            or not bool(details.get("advisory_only"))
        ):
            continue
        total_tasks += 1
        status = str(row.get("status") or "open")
        if status in {"completed", "skipped"}:
            terminal_tasks += 1

        signal_type = str(details.get("signal_type") or "").strip()
        if not signal_type:
            unknown_signal_tasks += 1
            signal_type = "unknown"

        feedback = _feedback(details)
        usefulness = str(feedback.get("usefulness") or "").strip().lower()
        has_feedback = usefulness in {"useful", "neutral", "noisy"}
        if has_feedback:
            explicit_feedback += 1

        bucket = grouped.setdefault(
            signal_type,
            {
                "signal_type": signal_type,
                "task_count": 0,
                "completed_count": 0,
                "skipped_count": 0,
                "open_count": 0,
                "feedback_count": 0,
                "useful_count": 0,
                "neutral_count": 0,
                "noisy_count": 0,
                "families": set(),
            },
        )
        bucket["task_count"] += 1
        if status == "completed":
            bucket["completed_count"] += 1
        elif status == "skipped":
            bucket["skipped_count"] += 1
        else:
            bucket["open_count"] += 1
        if has_feedback:
            bucket["feedback_count"] += 1
            bucket[f"{usefulness}_count"] += 1
        family = str(row.get("primary_family") or "").strip() or "unknown"
        bucket["families"].add(family)

        family_key = (signal_type, family)
        family_bucket = family_grouped.setdefault(
            family_key,
            {
                "signal_type": signal_type,
                "family": family,
                "task_count": 0,
                "feedback_count": 0,
                "useful_count": 0,
                "neutral_count": 0,
                "noisy_count": 0,
            },
        )
        family_bucket["task_count"] += 1
        if has_feedback:
            family_bucket["feedback_count"] += 1
            family_bucket[f"{usefulness}_count"] += 1

    signal_rows: list[dict[str, Any]] = []
    for signal_type, bucket in sorted(grouped.items()):
        feedback_count = int(bucket["feedback_count"])
        useful_count = int(bucket["useful_count"])
        neutral_count = int(bucket["neutral_count"])
        noisy_count = int(bucket["noisy_count"])
        status, recommendation = _shadow_status(
            feedback_count=feedback_count,
            useful_count=useful_count,
            noisy_count=noisy_count,
        )
        signal_rows.append(
            {
                "signal_type": signal_type,
                "task_count": int(bucket["task_count"]),
                "terminal_count": int(bucket["completed_count"]) + int(bucket["skipped_count"]),
                "terminal_rate": _ratio(
                    int(bucket["completed_count"]) + int(bucket["skipped_count"]),
                    int(bucket["task_count"]),
                ),
                "completed_count": int(bucket["completed_count"]),
                "skipped_count": int(bucket["skipped_count"]),
                "open_count": int(bucket["open_count"]),
                "feedback_count": feedback_count,
                "feedback_coverage": _ratio(feedback_count, int(bucket["task_count"])),
                "useful_count": useful_count,
                "useful_rate": _ratio(useful_count, feedback_count),
                "useful_rate_wilson_95": _wilson_interval(useful_count, feedback_count),
                "neutral_count": neutral_count,
                "neutral_rate": _ratio(neutral_count, feedback_count),
                "noisy_count": noisy_count,
                "noisy_rate": _ratio(noisy_count, feedback_count),
                "noisy_rate_wilson_95": _wilson_interval(noisy_count, feedback_count),
                "family_count": len(bucket["families"]),
                "families": sorted(bucket["families"])[:20],
                "shadow_status": status,
                "review_recommendation": recommendation,
                "production_change_allowed": False,
            }
        )

    family_rows: list[dict[str, Any]] = []
    for (_signal_type, _family), bucket in sorted(family_grouped.items()):
        feedback_count = int(bucket["feedback_count"])
        useful_count = int(bucket["useful_count"])
        noisy_count = int(bucket["noisy_count"])
        status, recommendation = _shadow_status(
            feedback_count=feedback_count,
            useful_count=useful_count,
            noisy_count=noisy_count,
        )
        family_rows.append(
            {
                "signal_type": str(bucket["signal_type"]),
                "family": str(bucket["family"]),
                "task_count": int(bucket["task_count"]),
                "feedback_count": feedback_count,
                "useful_rate": _ratio(useful_count, feedback_count),
                "neutral_rate": _ratio(int(bucket["neutral_count"]), feedback_count),
                "noisy_rate": _ratio(noisy_count, feedback_count),
                "shadow_status": status,
                "review_recommendation": recommendation,
                "production_change_allowed": False,
            }
        )

    status_counts: dict[str, int] = defaultdict(int)
    for row in signal_rows:
        status_counts[str(row["shadow_status"])] += 1

    return {
        "version": CHANGE_GUIDANCE_CALIBRATION_VERSION,
        "rule_version": CHANGE_GUIDANCE_CALIBRATION_RULE_VERSION,
        "target": str(target or ""),
        "activation": "shadow_only",
        "task_count": total_tasks,
        "terminal_task_count": terminal_tasks,
        "terminal_rate": _ratio(terminal_tasks, total_tasks),
        "feedback_count": explicit_feedback,
        "feedback_coverage": _ratio(explicit_feedback, total_tasks),
        "unknown_signal_task_count": unknown_signal_tasks,
        "minimum_feedback_per_signal": _MIN_FEEDBACK_PER_SIGNAL,
        "signal_count": len(signal_rows),
        "status_counts": dict(sorted(status_counts.items())),
        "signals": signal_rows,
        "signal_family_slices": family_rows[:200],
        "interpretation": {
            "causal": False,
            "production_activation": False,
            "auto_tuning": False,
            "threshold_learning": False,
            "weight_learning": False,
            "human_review_required": True,
            "feedback_source": "explicit analyst task usefulness only",
        },
        "safety": {
            "shadow_only": True,
            "may_change_meta_ranker_weights": False,
            "may_change_queue_score": False,
            "may_change_task_ordering": False,
            "may_change_target_evidence": False,
            "may_change_admission": False,
            "may_change_validation": False,
            "network_requests": False,
        },
        "limitations": [
            "Analyst usefulness feedback is subjective workflow telemetry, not a vulnerability label.",
            "Feedback is not randomized and can be missing non-randomly; signal cohorts may differ by target, family, and analyst behavior.",
            "Signal status is suppressed as insufficient_feedback until at least five explicit ratings exist for that signal type.",
            "Utility/noise watch statuses are review prompts only and never change production weights or thresholds automatically.",
            "The report uses the latest persisted feedback per task; prior rating edits remain available through audit events, not as independent calibration samples.",
        ],
    }


__all__ = [
    "CHANGE_GUIDANCE_CALIBRATION_VERSION",
    "CHANGE_GUIDANCE_CALIBRATION_RULE_VERSION",
    "change_guidance_calibration_report",
]
