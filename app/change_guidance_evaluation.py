from __future__ import annotations

"""Observational evaluation for change-guided Investigation Workflow cases.

This module measures workflow outcomes from already-persisted local case/task/event
state. It is deliberately non-causal and does not tune ranking, admission,
validation, or workflow behavior.
"""

import datetime as dt
import statistics
from typing import Any, Mapping

from core import Database, safe_json_loads

CHANGE_GUIDANCE_EVALUATION_VERSION = "1.0.0"
CHANGE_GUIDANCE_EVALUATION_RULE_VERSION = "2026.09.18.1"
CLUSTER_CASE_PREFIX = "investigation-cluster:"
_MIN_COMPARISON_CASES_PER_COHORT = 5
_MAX_CASES = 500


def _loads(value: Any, default: Any) -> Any:
    return safe_json_loads(value, default, expected_type=type(default))


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


def _hours_between(start: Any, end: Any) -> float | None:
    left = _parse_time(start)
    right = _parse_time(end)
    if left is None or right is None or right < left:
        return None
    return round((right - left).total_seconds() / 3600.0, 3)


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    return round(float(statistics.median(values)), 3)


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def case_change_guidance_metrics(db: Database, case_id: str) -> dict[str, Any]:
    case = db.one(
        "SELECT case_id,case_key,target,state,created_at,updated_at FROM security_cases WHERE case_id=?",
        (case_id,),
    )
    if not case:
        return {
            "case_id": case_id,
            "available": False,
            "reason": "case not found",
        }

    events = [
        dict(row)
        for row in db.all(
            "SELECT event_type,actor,details_json,created_at FROM security_case_events "
            "WHERE case_id=? ORDER BY created_at ASC,id ASC",
            (case_id,),
        )
    ]
    snapshots = [
        dict(row)
        for row in db.all(
            "SELECT coverage,created_at FROM evidence_gap_snapshots "
            "WHERE case_id=? ORDER BY created_at ASC,id ASC",
            (case_id,),
        )
    ]
    tasks = [
        dict(row)
        for row in db.all(
            "SELECT task_id,task_type,status,details_json,created_at,updated_at "
            "FROM case_autopilot_tasks WHERE case_id=? ORDER BY created_at ASC,rank ASC",
            (case_id,),
        )
    ]

    start_event = next(
        (
            row for row in events
            if str(row.get("event_type") or "") == "investigation_cluster_started"
        ),
        None,
    )
    start_at = (
        str(start_event.get("created_at") or "")
        if start_event
        else str(case["created_at"] or "")
    )

    guided_events = [
        row
        for row in events
        if str(row.get("event_type") or "") == "investigation_change_guidance_refreshed"
    ]
    guided_tasks = []
    base_tasks = []
    for row in tasks:
        details = _loads(row.get("details_json"), {})
        is_guided = (
            str(row.get("task_id") or "").startswith("task-change-")
            or (
                isinstance(details, Mapping)
                and str(details.get("source") or "") == "derived_change_advisory"
            )
        )
        (guided_tasks if is_guided else base_tasks).append(row)

    guided = bool(guided_events or guided_tasks)
    guidance_first_at = ""
    if guided_events:
        guidance_first_at = str(guided_events[0].get("created_at") or "")
    elif guided_tasks:
        guidance_first_at = str(guided_tasks[0].get("created_at") or "")

    initial_coverage = int(snapshots[0]["coverage"] or 0) if snapshots else None
    latest_coverage = int(snapshots[-1]["coverage"] or 0) if snapshots else None
    coverage_delta = (
        latest_coverage - initial_coverage
        if initial_coverage is not None and latest_coverage is not None
        else None
    )
    first_gain = None
    if initial_coverage is not None:
        first_gain = next(
            (
                row for row in snapshots
                if int(row.get("coverage") or 0) > initial_coverage
            ),
            None,
        )
    first_gain_at = str(first_gain.get("created_at") or "") if first_gain else ""
    time_to_first_gain_hours = _hours_between(start_at, first_gain_at)

    decision_event = None
    for row in events:
        if str(row.get("event_type") or "") == "investigation_cluster_decision":
            decision_event = row
            break
    decision = ""
    decision_at = ""
    if decision_event:
        details = _loads(decision_event.get("details_json"), {})
        decision = str(details.get("decision") or "") if isinstance(details, Mapping) else ""
        decision_at = str(decision_event.get("created_at") or "")
    time_to_decision_hours = _hours_between(start_at, decision_at)

    evidence_gain = bool(coverage_delta is not None and coverage_delta > 0)
    decided = bool(decision)
    rejected_or_duplicate = decision in {"rejected", "duplicate"}
    confirmed = decision == "confirmed_by_analyst"
    needs_more = decision == "needs_more_evidence"

    return {
        "case_id": str(case["case_id"]),
        "target": str(case["target"] or ""),
        "case_key": str(case["case_key"] or ""),
        "state": str(case["state"] or ""),
        "available": True,
        "change_guided": guided,
        "start_at": start_at,
        "guidance_first_at": guidance_first_at,
        "initial_coverage": initial_coverage,
        "latest_coverage": latest_coverage,
        "coverage_delta": coverage_delta,
        "evidence_gain": evidence_gain,
        "first_evidence_gain_at": first_gain_at,
        "time_to_first_evidence_gain_hours": time_to_first_gain_hours,
        "decision": decision,
        "decision_at": decision_at,
        "decided": decided,
        "time_to_decision_hours": time_to_decision_hours,
        "confirmed": confirmed,
        "rejected_or_duplicate": rejected_or_duplicate,
        "needs_more_evidence": needs_more,
        "guided_task_count": len(guided_tasks),
        "base_task_count": len(base_tasks),
        "snapshot_count": len(snapshots),
        "event_count": len(events),
    }


def _cohort_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    count = len(rows)
    coverage_deltas = [
        float(row["coverage_delta"])
        for row in rows
        if row.get("coverage_delta") is not None
    ]
    first_gain_hours = [
        float(row["time_to_first_evidence_gain_hours"])
        for row in rows
        if row.get("time_to_first_evidence_gain_hours") is not None
    ]
    decision_hours = [
        float(row["time_to_decision_hours"])
        for row in rows
        if row.get("time_to_decision_hours") is not None
    ]
    evidence_gain_count = sum(bool(row.get("evidence_gain")) for row in rows)
    decided_count = sum(bool(row.get("decided")) for row in rows)
    confirmed_count = sum(bool(row.get("confirmed")) for row in rows)
    rejected_count = sum(bool(row.get("rejected_or_duplicate")) for row in rows)
    needs_more_count = sum(bool(row.get("needs_more_evidence")) for row in rows)
    return {
        "case_count": count,
        "evidence_gain_count": evidence_gain_count,
        "evidence_gain_rate": _rate(evidence_gain_count, count),
        "median_coverage_delta": _median(coverage_deltas),
        "observed_first_gain_count": len(first_gain_hours),
        "median_time_to_first_evidence_gain_hours": _median(first_gain_hours),
        "decided_count": decided_count,
        "decision_rate": _rate(decided_count, count),
        "observed_decision_time_count": len(decision_hours),
        "median_time_to_decision_hours": _median(decision_hours),
        "confirmed_count": confirmed_count,
        "confirmed_rate": _rate(confirmed_count, count),
        "rejected_or_duplicate_count": rejected_count,
        "rejected_or_duplicate_rate": _rate(rejected_count, count),
        "needs_more_evidence_count": needs_more_count,
        "needs_more_evidence_rate": _rate(needs_more_count, count),
    }


def _delta(left: Any, right: Any, *, digits: int = 4) -> float | None:
    if left is None or right is None:
        return None
    return round(float(left) - float(right), digits)


def change_guidance_evaluation(
    db: Database,
    *,
    target: str = "",
    limit: int = _MAX_CASES,
) -> dict[str, Any]:
    """Return a bounded observational comparison of guided vs non-guided cases."""
    bounded_limit = max(1, min(int(limit or _MAX_CASES), _MAX_CASES))
    params: list[Any] = [CLUSTER_CASE_PREFIX + "%"]
    sql = (
        "SELECT case_id FROM security_cases "
        "WHERE case_key LIKE ? "
    )
    if target:
        sql += "AND target=? "
        params.append(target)
    sql += "ORDER BY created_at DESC LIMIT ?"
    params.append(bounded_limit)

    rows: list[dict[str, Any]] = []
    for row in db.all(sql, tuple(params)):
        metrics = case_change_guidance_metrics(db, str(row["case_id"]))
        if metrics.get("available"):
            rows.append(metrics)

    guided = [row for row in rows if bool(row.get("change_guided"))]
    control = [row for row in rows if not bool(row.get("change_guided"))]
    guided_summary = _cohort_summary(guided)
    control_summary = _cohort_summary(control)
    comparison_ready = (
        len(guided) >= _MIN_COMPARISON_CASES_PER_COHORT
        and len(control) >= _MIN_COMPARISON_CASES_PER_COHORT
    )

    deltas = {
        "evidence_gain_rate": _delta(
            guided_summary["evidence_gain_rate"],
            control_summary["evidence_gain_rate"],
        ),
        "median_coverage_delta": _delta(
            guided_summary["median_coverage_delta"],
            control_summary["median_coverage_delta"],
        ),
        "median_time_to_first_evidence_gain_hours": _delta(
            guided_summary["median_time_to_first_evidence_gain_hours"],
            control_summary["median_time_to_first_evidence_gain_hours"],
        ),
        "decision_rate": _delta(
            guided_summary["decision_rate"],
            control_summary["decision_rate"],
        ),
        "median_time_to_decision_hours": _delta(
            guided_summary["median_time_to_decision_hours"],
            control_summary["median_time_to_decision_hours"],
        ),
        "rejected_or_duplicate_rate": _delta(
            guided_summary["rejected_or_duplicate_rate"],
            control_summary["rejected_or_duplicate_rate"],
        ),
    }

    return {
        "version": CHANGE_GUIDANCE_EVALUATION_VERSION,
        "rule_version": CHANGE_GUIDANCE_EVALUATION_RULE_VERSION,
        "target": target,
        "case_count": len(rows),
        "guided": guided_summary,
        "control": control_summary,
        "comparison_ready": comparison_ready,
        "minimum_cases_per_cohort": _MIN_COMPARISON_CASES_PER_COHORT,
        "directional_deltas_guided_minus_control": deltas if comparison_ready else {},
        "recent_cases": rows[:50],
        "interpretation": {
            "causal": False,
            "auto_tuning": False,
            "winner_selection": False,
            "task_completion_observed": False,
            "evidence_gain_definition": "latest evidence-gap coverage exceeds the first persisted coverage snapshot",
            "decision_definition": "first investigation_cluster_decision event",
        },
        "limitations": [
            "Cohorts are observational and are not randomized; differences must not be interpreted as causal impact.",
            "Change-guided routing depends on available Recon changes and case surface, so cohort composition can differ materially.",
            "Task completion is not explicitly modeled in the current task lifecycle; this evaluator does not infer completion from task disappearance.",
            "Time metrics are reported only when the corresponding persisted event/snapshot exists.",
            "This evaluator does not change ranking, Admission, Evidence Gap, validation eligibility, or workflow task ordering.",
        ],
    }


__all__ = [
    "CHANGE_GUIDANCE_EVALUATION_VERSION",
    "CHANGE_GUIDANCE_EVALUATION_RULE_VERSION",
    "case_change_guidance_metrics",
    "change_guidance_evaluation",
]
