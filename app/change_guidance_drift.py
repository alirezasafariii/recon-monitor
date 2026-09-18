from __future__ import annotations

"""Longitudinal shadow monitoring for change-guidance signal quality.

The report compares explicit analyst usefulness feedback across two adjacent,
equal-duration windows anchored to the latest recorded feedback timestamp.
It is read-only monitoring: no production weight, threshold, ranking, workflow,
Admission, Evidence Gap, or validation behavior can be changed by this module.
"""

import datetime as dt
import math
from collections import defaultdict
from typing import Any, Mapping

from core import Database, safe_json_loads

CHANGE_GUIDANCE_DRIFT_VERSION = "1.0.0"
CHANGE_GUIDANCE_DRIFT_RULE_VERSION = "2026.09.18.1"
DEFAULT_WINDOW_DAYS = 30
MIN_FEEDBACK_PER_WINDOW = 5
MIN_SLICE_FEEDBACK = 3
MAX_TASKS = 5000


def _parse_time(value: Any) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(float(numerator) / float(denominator), 4)


def _delta(left: float | None, right: float | None) -> float | None:
    if left is None or right is None:
        return None
    return round(float(left) - float(right), 4)


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


def _empty_counts() -> dict[str, int]:
    return {
        "feedback_count": 0,
        "useful_count": 0,
        "neutral_count": 0,
        "noisy_count": 0,
        "completed_count": 0,
        "skipped_count": 0,
    }


def _add_sample(bucket: dict[str, int], sample: Mapping[str, Any]) -> None:
    bucket["feedback_count"] += 1
    usefulness = str(sample.get("usefulness") or "")
    if usefulness in {"useful", "neutral", "noisy"}:
        bucket[f"{usefulness}_count"] += 1
    status = str(sample.get("status") or "")
    if status in {"completed", "skipped"}:
        bucket[f"{status}_count"] += 1


def _window_summary(bucket: Mapping[str, int]) -> dict[str, Any]:
    feedback_count = int(bucket.get("feedback_count") or 0)
    useful_count = int(bucket.get("useful_count") or 0)
    neutral_count = int(bucket.get("neutral_count") or 0)
    noisy_count = int(bucket.get("noisy_count") or 0)
    return {
        "feedback_count": feedback_count,
        "useful_count": useful_count,
        "useful_rate": _rate(useful_count, feedback_count),
        "useful_rate_wilson_95": _wilson_interval(useful_count, feedback_count),
        "neutral_count": neutral_count,
        "neutral_rate": _rate(neutral_count, feedback_count),
        "noisy_count": noisy_count,
        "noisy_rate": _rate(noisy_count, feedback_count),
        "noisy_rate_wilson_95": _wilson_interval(noisy_count, feedback_count),
        "completed_count": int(bucket.get("completed_count") or 0),
        "skipped_count": int(bucket.get("skipped_count") or 0),
    }


def _drift_status(
    previous: Mapping[str, Any],
    recent: Mapping[str, Any],
) -> tuple[str, str]:
    previous_count = int(previous.get("feedback_count") or 0)
    recent_count = int(recent.get("feedback_count") or 0)
    if previous_count < MIN_FEEDBACK_PER_WINDOW or recent_count < MIN_FEEDBACK_PER_WINDOW:
        return (
            "insufficient_history",
            "Collect at least five explicit ratings in both adjacent windows before interpreting longitudinal change.",
        )

    previous_useful = float(previous.get("useful_rate") or 0.0)
    recent_useful = float(recent.get("useful_rate") or 0.0)
    previous_noisy = float(previous.get("noisy_rate") or 0.0)
    recent_noisy = float(recent.get("noisy_rate") or 0.0)
    useful_delta = recent_useful - previous_useful
    noisy_delta = recent_noisy - previous_noisy

    if int(recent.get("noisy_count") or 0) >= 2 and noisy_delta >= 0.25:
        return (
            "noise_increase_watch",
            "Recent explicit noisy feedback increased materially; review extraction/provenance and cohort composition without changing production automatically.",
        )
    if previous_useful >= 0.50 and useful_delta <= -0.25:
        return (
            "utility_decline_watch",
            "Recent explicit useful feedback declined materially; review signal semantics and affected targets/families without automatic tuning.",
        )
    if recent_useful >= 0.60 and useful_delta >= 0.25 and recent_noisy <= 0.20:
        return (
            "utility_improvement_watch",
            "Recent explicit useful feedback increased materially; continue observing before considering any human-reviewed production proposal.",
        )
    if abs(useful_delta) <= 0.15 and abs(noisy_delta) <= 0.15:
        return (
            "stable",
            "Observed usefulness/noise rates are broadly stable across the two windows; continue monitoring.",
        )
    return (
        "mixed_shift",
        "Observed rates shifted without meeting a conservative watch condition; inspect target/family slices and continue collecting feedback.",
    )


def _slice_rows(
    samples: list[dict[str, Any]],
    *,
    key: str,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, int]] = {}
    for sample in samples:
        signal_type = str(sample.get("signal_type") or "unknown")
        slice_value = str(sample.get(key) or "unknown")
        bucket = grouped.setdefault((signal_type, slice_value), _empty_counts())
        _add_sample(bucket, sample)

    rows: list[dict[str, Any]] = []
    for (signal_type, slice_value), bucket in sorted(grouped.items()):
        summary = _window_summary(bucket)
        rows.append(
            {
                "signal_type": signal_type,
                key: slice_value,
                **summary,
                "sample_sufficient": int(summary["feedback_count"]) >= MIN_SLICE_FEEDBACK,
                "minimum_feedback": MIN_SLICE_FEEDBACK,
                "production_change_allowed": False,
            }
        )
    return rows


def change_guidance_drift_report(
    db: Database,
    *,
    target: str = "",
    window_days: int = DEFAULT_WINDOW_DAYS,
    limit: int = MAX_TASKS,
) -> dict[str, Any]:
    """Compare adjacent feedback windows for each Derived Change signal type."""
    bounded_window_days = max(7, min(int(window_days or DEFAULT_WINDOW_DAYS), 180))
    bounded_limit = max(1, min(int(limit or MAX_TASKS), MAX_TASKS))
    params: list[Any] = []
    sql = (
        "SELECT t.task_id,t.status,t.details_json,t.updated_at,"
        "c.target,c.primary_family "
        "FROM case_autopilot_tasks t "
        "JOIN security_cases c ON c.case_id=t.case_id "
        "WHERE t.task_id LIKE 'task-change-%' "
    )
    if target:
        sql += "AND c.target=? "
        params.append(str(target))
    sql += "ORDER BY t.updated_at DESC,t.task_id DESC LIMIT ?"
    params.append(bounded_limit)

    samples: list[dict[str, Any]] = []
    missing_feedback_timestamp_count = 0
    for raw in db.all(sql, tuple(params)):
        row = dict(raw)
        details = safe_json_loads(row.get("details_json"), {}, expected_type=dict)
        if (
            str(details.get("source") or "") != "derived_change_advisory"
            or not bool(details.get("advisory_only"))
        ):
            continue
        feedback = details.get("analyst_feedback")
        if not isinstance(feedback, Mapping):
            continue
        usefulness = str(feedback.get("usefulness") or "").strip().lower()
        if usefulness not in {"useful", "neutral", "noisy"}:
            continue
        recorded_at = _parse_time(feedback.get("recorded_at"))
        if recorded_at is None:
            missing_feedback_timestamp_count += 1
            continue
        samples.append(
            {
                "task_id": str(row.get("task_id") or ""),
                "signal_type": str(details.get("signal_type") or "").strip() or "unknown",
                "target": str(row.get("target") or "").strip() or "unknown",
                "family": str(row.get("primary_family") or "").strip() or "unknown",
                "status": str(row.get("status") or "open"),
                "usefulness": usefulness,
                "recorded_at": recorded_at,
            }
        )

    if not samples:
        return {
            "version": CHANGE_GUIDANCE_DRIFT_VERSION,
            "rule_version": CHANGE_GUIDANCE_DRIFT_RULE_VERSION,
            "target": str(target or ""),
            "activation": "monitoring_only",
            "window_days": bounded_window_days,
            "feedback_count": 0,
            "signal_count": 0,
            "anchor_at": "",
            "previous_window": {},
            "recent_window": {},
            "status_counts": {},
            "signals": [],
            "recent_target_slices": [],
            "recent_family_slices": [],
            "missing_feedback_timestamp_count": missing_feedback_timestamp_count,
            "interpretation": {
                "causal": False,
                "production_activation": False,
                "auto_tuning": False,
                "trend_is_not_significance_test": True,
                "human_review_required": True,
            },
            "safety": {
                "monitoring_only": True,
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
                "No explicit feedback with a valid recorded_at timestamp is available for longitudinal monitoring."
            ],
        }

    anchor = max(sample["recorded_at"] for sample in samples)
    recent_start = anchor - dt.timedelta(days=bounded_window_days)
    previous_start = recent_start - dt.timedelta(days=bounded_window_days)

    previous_samples = [
        sample
        for sample in samples
        if previous_start <= sample["recorded_at"] < recent_start
    ]
    recent_samples = [
        sample
        for sample in samples
        if recent_start <= sample["recorded_at"] <= anchor
    ]

    by_signal: dict[str, dict[str, dict[str, int]]] = {}
    for window_name, window_samples in (
        ("previous", previous_samples),
        ("recent", recent_samples),
    ):
        for sample in window_samples:
            signal_type = str(sample.get("signal_type") or "unknown")
            signal_bucket = by_signal.setdefault(
                signal_type,
                {"previous": _empty_counts(), "recent": _empty_counts()},
            )
            _add_sample(signal_bucket[window_name], sample)

    signal_rows: list[dict[str, Any]] = []
    status_counts: dict[str, int] = defaultdict(int)
    for signal_type in sorted(by_signal):
        previous = _window_summary(by_signal[signal_type]["previous"])
        recent = _window_summary(by_signal[signal_type]["recent"])
        status, recommendation = _drift_status(previous, recent)
        status_counts[status] += 1
        useful_delta = _delta(
            recent.get("useful_rate"),
            previous.get("useful_rate"),
        )
        noisy_delta = _delta(
            recent.get("noisy_rate"),
            previous.get("noisy_rate"),
        )
        signal_rows.append(
            {
                "signal_type": signal_type,
                "previous": previous,
                "recent": recent,
                "useful_rate_delta_recent_minus_previous": useful_delta,
                "noisy_rate_delta_recent_minus_previous": noisy_delta,
                "drift_status": status,
                "review_recommendation": recommendation,
                "history_sufficient": (
                    int(previous.get("feedback_count") or 0) >= MIN_FEEDBACK_PER_WINDOW
                    and int(recent.get("feedback_count") or 0) >= MIN_FEEDBACK_PER_WINDOW
                ),
                "production_change_allowed": False,
            }
        )

    return {
        "version": CHANGE_GUIDANCE_DRIFT_VERSION,
        "rule_version": CHANGE_GUIDANCE_DRIFT_RULE_VERSION,
        "target": str(target or ""),
        "activation": "monitoring_only",
        "window_days": bounded_window_days,
        "feedback_count": len(samples),
        "signal_count": len(signal_rows),
        "anchor_at": _iso(anchor),
        "previous_window": {
            "start": _iso(previous_start),
            "end_exclusive": _iso(recent_start),
            "feedback_count": len(previous_samples),
        },
        "recent_window": {
            "start": _iso(recent_start),
            "end_inclusive": _iso(anchor),
            "feedback_count": len(recent_samples),
        },
        "minimum_feedback_per_window": MIN_FEEDBACK_PER_WINDOW,
        "minimum_feedback_per_slice": MIN_SLICE_FEEDBACK,
        "status_counts": dict(sorted(status_counts.items())),
        "signals": signal_rows,
        "recent_target_slices": _slice_rows(recent_samples, key="target")[:300],
        "recent_family_slices": _slice_rows(recent_samples, key="family")[:300],
        "missing_feedback_timestamp_count": missing_feedback_timestamp_count,
        "interpretation": {
            "causal": False,
            "production_activation": False,
            "auto_tuning": False,
            "trend_is_not_significance_test": True,
            "human_review_required": True,
            "anchor_definition": "latest explicit analyst feedback recorded_at timestamp",
            "window_definition": "two adjacent equal-duration UTC windows ending at the latest explicit feedback timestamp",
        },
        "safety": {
            "monitoring_only": True,
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
            "Drift statuses are descriptive monitoring prompts, not statistical significance tests or causal conclusions.",
            "Feedback is subjective and not randomized; target, family, analyst, and deployment mix can change between windows.",
            "A signal remains insufficient_history until both adjacent windows contain at least five explicit ratings.",
            "Target/family slices are descriptive only and require at least three recent ratings to be considered sample-sufficient.",
            "The latest explicit rating per task is used; edited-rating history remains audit data and is not counted as multiple samples.",
            "No production weight, threshold, ranking, task ordering, Evidence Gap, Admission, or validation behavior can be changed by this report.",
        ],
    }


__all__ = [
    "CHANGE_GUIDANCE_DRIFT_VERSION",
    "CHANGE_GUIDANCE_DRIFT_RULE_VERSION",
    "DEFAULT_WINDOW_DAYS",
    "change_guidance_drift_report",
]
