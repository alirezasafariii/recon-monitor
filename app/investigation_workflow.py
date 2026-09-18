from __future__ import annotations

"""Bridge Investigation Queue clusters into the existing case/validation workflow.

This module intentionally does not create a second case system and does not perform
active validation.  It links a correlation cluster to the existing Security Case,
Evidence Gap, Case Autopilot and Safe Validation engines.  Analyst decisions are
written back only to already-promoted Potential Findings, so proximity-only hidden
hypotheses can never be turned into confirmed vulnerabilities by this bridge.
"""

import hashlib
from typing import Any, Mapping

from bug_candidates import set_bug_candidate_decision
from core import Database, ReconError, json_dumps, parse_int, safe_json_loads, utc_now
from correlation_engine import investigation_queue
from product_platform import case_detail, set_case_state
from safe_validation import validation_eligibility
from workspace_v7 import case_autopilot, evidence_gap_for_case


INVESTIGATION_WORKFLOW_VERSION = "1.2.0"
CLUSTER_CASE_PREFIX = "investigation-cluster:"
CHANGE_TASK_TERMINAL_STATUSES = ("completed", "skipped")
CHANGE_TASK_USEFULNESS = ("useful", "neutral", "noisy")
CLUSTER_DECISIONS = (
    "needs_more_evidence",
    "confirmed_by_analyst",
    "rejected",
    "duplicate",
)


def cluster_case_key(cluster_id: str) -> str:
    value = str(cluster_id or "").strip()
    if not value:
        raise ReconError("Investigation cluster id is required")
    return CLUSTER_CASE_PREFIX + value


def cluster_case_id(target: str, cluster_id: str) -> str:
    key = cluster_case_key(cluster_id)
    return "CASE-" + hashlib.sha256(f"{target}|{key}".encode("utf-8", "replace")).hexdigest()[:12].upper()


def find_cluster_case(db: Database, *, target: str, cluster_id: str) -> dict[str, Any] | None:
    row = db.one(
        "SELECT * FROM security_cases WHERE target=? AND case_key=?",
        (str(target or ""), cluster_case_key(cluster_id)),
    )
    return dict(row) if row else None


def _queue_item(
    db: Database,
    *,
    analysis_id: str,
    cluster_id: str,
    target: str = "",
) -> dict[str, Any]:
    items = investigation_queue(db, analysis_id, target=target or None, limit=500)
    for item in items:
        if str(item.get("cluster_id") or "") == str(cluster_id):
            return dict(item)
    raise ReconError("Investigation cluster is not available in the selected analysis context")


def _cluster_hypotheses(db: Database, analysis_id: str, item: Mapping[str, Any]) -> list[dict[str, Any]]:
    ids = [str(value) for value in item.get("hypothesis_ids", []) if str(value).strip()]
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    return [
        dict(row)
        for row in db.all(
            "SELECT hypothesis_id,source_run_id,target,endpoint,alert_id,bug_family,state,promoted_candidate_id "
            f"FROM analysis_hypotheses WHERE analysis_id=? AND hypothesis_id IN ({placeholders})",
            (analysis_id, *ids),
        )
    ]


def _cluster_candidates(
    db: Database,
    analysis_id: str,
    item: Mapping[str, Any],
    hypotheses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    target = str(item.get("target") or "")
    candidate_ids = {
        str(row.get("promoted_candidate_id") or "")
        for row in hypotheses
        if str(row.get("promoted_candidate_id") or "").strip()
    }
    endpoints = [str(value) for value in item.get("endpoints", []) if str(value).strip()]
    clauses: list[str] = []
    params: list[Any] = [analysis_id, target]
    if candidate_ids:
        placeholders = ",".join("?" for _ in candidate_ids)
        clauses.append(f"candidate_id IN ({placeholders})")
        params.extend(sorted(candidate_ids))
    if endpoints:
        placeholders = ",".join("?" for _ in endpoints)
        clauses.append(f"endpoint IN ({placeholders})")
        params.extend(endpoints)
    if not clauses:
        return []
    rows = db.all(
        "SELECT candidate_id,source_run_id,alert_id,target,endpoint,bug_family,bug_variant,title,summary,"
        "candidate_state,analyst_decision,priority_score,investigation_value,evidence_strength,evidence_coverage "
        "FROM bug_candidates WHERE analysis_id=? AND target=? AND (" + " OR ".join(clauses) + ") "
        "ORDER BY investigation_value DESC,priority_score DESC",
        tuple(params),
    )
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        item_row = dict(row)
        candidate_id = str(item_row.get("candidate_id") or "")
        if candidate_id and candidate_id not in seen:
            seen.add(candidate_id)
            out.append(item_row)
    return out


def _queue_item_for_case(db: Database, case: Mapping[str, Any]) -> dict[str, Any]:
    case_key = str(case.get("case_key") or "")
    analysis_id = str(case.get("analysis_id") or "")
    target = str(case.get("target") or "")
    if not analysis_id or not case_key.startswith(CLUSTER_CASE_PREFIX):
        return {}
    cluster_id = case_key[len(CLUSTER_CASE_PREFIX):]
    if not cluster_id:
        return {}
    try:
        return _queue_item(
            db,
            analysis_id=analysis_id,
            cluster_id=cluster_id,
            target=target,
        )
    except ReconError:
        return {}


def _change_guidance(
    item: Mapping[str, Any],
    gap: Mapping[str, Any],
) -> dict[str, Any]:
    """Prioritize analyst review from P5 change provenance without creating evidence."""
    score = parse_int(item.get("derived_change_score"), 0, 0, 100)
    raw_matches = item.get("derived_change_matches")
    matches = [
        dict(row)
        for row in raw_matches[:12]
        if isinstance(row, Mapping)
    ] if isinstance(raw_matches, list) else []
    matches = [
        row
        for row in matches
        if str(row.get("signal_type") or "").strip()
        and str(row.get("item") or "").strip()
    ]

    base = {
        "available": bool(score and matches),
        "score": score,
        "matched_signal_count": parse_int(
            item.get("derived_change_matched_signals"),
            len(matches),
            0,
            5000,
        ),
        "signal_types": sorted(
            {
                str(row.get("signal_type") or "")
                for row in matches
                if str(row.get("signal_type") or "").strip()
            }
        )[:12],
        "prioritized_requirements": [],
        "tasks": [],
        "why_now": [],
        "advisory_only": True,
        "safety": {
            "counts_as_evidence": False,
            "changes_evidence_coverage": False,
            "changes_admission": False,
            "changes_validation_eligibility": False,
            "can_execute_validation": False,
            "network_requests": False,
        },
    }
    if not base["available"]:
        return base

    requirements = [
        dict(row)
        for row in gap.get("requirements", [])
        if isinstance(row, Mapping)
        and str(row.get("status") or "") == "missing"
    ]
    missing_by_key = {
        str(row.get("key") or ""): row
        for row in requirements
        if str(row.get("key") or "").strip()
    }
    family = str(item.get("primary_family") or "")
    focus: list[str] = []

    signal_types = set(base["signal_types"])
    if any(value.startswith("source_map_source_") for value in signal_types):
        focus.extend(["expected_behavior", "endpoint", "auth_boundary", "evidence"])
    if any(value.startswith("javascript_chunk_") for value in signal_types):
        focus.extend(["endpoint", "evidence", "comparable_response"])
    if family == "broken_object_authorization":
        focus.extend(["ownership_map", "second_identity", "comparable_response"])
    elif family == "broken_function_authorization":
        focus.extend(["role_map", "authenticated_context", "comparable_response"])
    elif family == "graphql_authorization":
        focus.extend(["operation_context", "auth_boundary", "comparable_response"])
    elif family == "websocket_authorization":
        focus.extend(["channel_context", "auth_boundary", "comparable_response"])

    focus.extend(str(row.get("key") or "") for row in requirements)
    prioritized: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for key in focus:
        if not key or key in seen_keys or key not in missing_by_key:
            continue
        seen_keys.add(key)
        row = missing_by_key[key]
        prioritized.append(
            {
                "key": key,
                "label": str(row.get("label") or key),
                "why": str(row.get("why") or ""),
                "status": "missing",
            }
        )
        if len(prioritized) >= 5:
            break
    base["prioritized_requirements"] = prioritized

    tasks: list[dict[str, Any]] = []
    for row in matches[:2]:
        signal_type = str(row.get("signal_type") or "")
        change = str(row.get("change") or "")
        changed_item = str(row.get("item") or "")[:240]
        reasons = [
            str(value)[:500]
            for value in row.get("reasons", [])[:3]
            if str(value).strip()
        ] if isinstance(row.get("reasons"), list) else []

        if signal_type.startswith("source_map_source_"):
            if change == "added":
                title = (
                    f"Review newly surfaced source module {changed_item} and map any "
                    "endpoint or security-boundary changes to existing case evidence."
                )
            elif change == "removed":
                title = (
                    f"Review removed source module {changed_item} as a deployment/code-move "
                    "signal before assuming any endpoint or control disappeared."
                )
            else:
                title = (
                    f"Review changed source module {changed_item} against the current "
                    "hypothesis and document which security assumptions actually changed."
                )
        elif signal_type.startswith("javascript_chunk_"):
            if change == "added":
                title = (
                    f"Review newly referenced JavaScript chunk {changed_item} using existing "
                    "artifacts and map any new endpoint/auth-flow references."
                )
            elif change == "removed":
                title = (
                    f"Review removed JavaScript chunk reference {changed_item}; verify code "
                    "movement or deprecation from stored artifacts before treating the surface as gone."
                )
            else:
                title = (
                    f"Review changed JavaScript chunk reference {changed_item} and map affected "
                    "client-side routes or auth flows from stored artifacts."
                )
        else:
            title = (
                f"Review recent Recon change {changed_item} as a pointer for the current "
                "investigation without treating it as target evidence."
            )
        tasks.append(
            {
                "rank": len(tasks) + 1,
                "type": "change_review",
                "title": title,
                "status": "open",
                "advisory_only": True,
                "signal_type": signal_type,
                "item": changed_item,
                "item_key": str(row.get("item_key") or "")[:2000],
                "reasons": reasons,
            }
        )
        base["why_now"].extend(reasons)

    if prioritized:
        first = prioritized[0]
        tasks.append(
            {
                "rank": len(tasks) + 1,
                "type": "evidence_priority",
                "title": (
                    "Use the recent change only to prioritize this existing evidence gap: "
                    f"{first['label']}."
                ),
                "status": "open",
                "advisory_only": True,
                "requirement_key": first["key"],
                "reasons": [first["why"]] if first["why"] else [],
            }
        )

    base["tasks"] = tasks[:3]
    base["why_now"] = list(dict.fromkeys(base["why_now"]))[:8]
    return base


def _merge_change_guidance(
    gap: Mapping[str, Any],
    autopilot: Mapping[str, Any],
    guidance: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    gap_out = dict(gap)
    autopilot_out = dict(autopilot)
    prioritized = [
        dict(row)
        for row in guidance.get("prioritized_requirements", [])
        if isinstance(row, Mapping)
    ]
    gap_out["change_prioritized_requirements"] = prioritized
    gap_out["change_aware_next_actions"] = [
        str(row.get("title") or "")
        for row in guidance.get("tasks", [])
        if isinstance(row, Mapping) and str(row.get("title") or "").strip()
    ]
    gap_out["change_advisory_score"] = int(guidance.get("score") or 0)
    gap_out["change_context_is_advisory_only"] = True

    merged: list[dict[str, Any]] = []
    seen_titles: set[str] = set()
    for raw in list(guidance.get("tasks", [])) + list(autopilot.get("tasks", [])):
        if not isinstance(raw, Mapping):
            continue
        task = dict(raw)
        title = str(task.get("title") or "").strip()
        if not title or title in seen_titles:
            continue
        seen_titles.add(title)
        task["rank"] = len(merged) + 1
        merged.append(task)
    autopilot_out["tasks"] = merged
    autopilot_out["change_guidance"] = dict(guidance)
    autopilot_out["change_aware"] = bool(guidance.get("available"))
    autopilot_out["change_context_does_not_change_autopilot_score"] = True
    return gap_out, autopilot_out


def _change_task_id(case_id: str, task: Mapping[str, Any]) -> str:
    identity = "|".join(
        [
            case_id,
            str(task.get("type") or ""),
            str(task.get("signal_type") or ""),
            str(task.get("item_key") or ""),
            str(task.get("requirement_key") or ""),
            str(task.get("title") or ""),
        ]
    )
    return "task-change-" + hashlib.sha256(
        identity.encode("utf-8", "replace")
    ).hexdigest()[:16]


def _change_task_lifecycle_rows(db: Database, case_id: str) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row in db.all(
        "SELECT task_id,task_type,title,rank,status,details_json,created_at,updated_at "
        "FROM case_autopilot_tasks WHERE case_id=? AND task_id LIKE 'task-change-%' "
        "ORDER BY rank,created_at",
        (case_id,),
    ):
        item = dict(row)
        details = safe_json_loads(
            item.get("details_json"),
            {},
            expected_type=dict,
        )
        feedback = (
            dict(details.get("analyst_feedback"))
            if isinstance(details.get("analyst_feedback"), Mapping)
            else {}
        )
        rows[str(item.get("task_id") or "")] = {
            "task_id": str(item.get("task_id") or ""),
            "type": str(item.get("task_type") or ""),
            "title": str(item.get("title") or ""),
            "rank": int(item.get("rank") or 0),
            "status": str(item.get("status") or "open"),
            "feedback_usefulness": str(feedback.get("usefulness") or ""),
            "feedback_note": str(feedback.get("note") or ""),
            "feedback_actor": str(feedback.get("actor") or ""),
            "feedback_recorded_at": str(feedback.get("recorded_at") or ""),
            "updated_at": str(item.get("updated_at") or ""),
            "details": details,
        }
    return rows


def _apply_change_task_lifecycle(
    db: Database,
    case_id: str,
    guidance: Mapping[str, Any],
    autopilot: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    lifecycle = _change_task_lifecycle_rows(db, case_id)
    guidance_out = dict(guidance)
    autopilot_out = dict(autopilot)

    guidance_tasks: list[dict[str, Any]] = []
    for raw in guidance.get("tasks", []):
        if not isinstance(raw, Mapping):
            continue
        task = dict(raw)
        task_id = _change_task_id(case_id, task)
        persisted = lifecycle.get(task_id, {})
        task["task_id"] = task_id
        task["status"] = str(persisted.get("status") or task.get("status") or "open")
        task["feedback_usefulness"] = str(persisted.get("feedback_usefulness") or "")
        task["feedback_note"] = str(persisted.get("feedback_note") or "")
        guidance_tasks.append(task)
    guidance_out["tasks"] = guidance_tasks

    autopilot_tasks: list[dict[str, Any]] = []
    for raw in autopilot.get("tasks", []):
        if not isinstance(raw, Mapping):
            continue
        task = dict(raw)
        if bool(task.get("advisory_only")):
            task_id = _change_task_id(case_id, task)
            persisted = lifecycle.get(task_id, {})
            task["task_id"] = task_id
            task["status"] = str(persisted.get("status") or task.get("status") or "open")
            task["feedback_usefulness"] = str(persisted.get("feedback_usefulness") or "")
            task["feedback_note"] = str(persisted.get("feedback_note") or "")
        autopilot_tasks.append(task)
    autopilot_out["tasks"] = autopilot_tasks

    lifecycle_rows = sorted(
        lifecycle.values(),
        key=lambda row: (int(row.get("rank") or 0), str(row.get("task_id") or "")),
    )
    return guidance_out, autopilot_out, lifecycle_rows


def record_change_task_feedback(
    db: Database,
    case_id: str,
    task_id: str,
    *,
    status: str,
    usefulness: str,
    note: str = "",
    actor: str = "analyst",
) -> dict[str, Any]:
    case_value = str(case_id or "").strip()
    task_value = str(task_id or "").strip()
    status_value = str(status or "").strip().lower()
    usefulness_value = str(usefulness or "").strip().lower()
    if not case_value or not task_value:
        raise ReconError("Change-guided task case and task ids are required")
    if not task_value.startswith("task-change-"):
        raise ReconError("Only change-guided tasks accept this feedback action")
    if status_value not in CHANGE_TASK_TERMINAL_STATUSES:
        raise ReconError(f"Unsupported change-guided task status: {status_value}")
    if usefulness_value not in CHANGE_TASK_USEFULNESS:
        raise ReconError(f"Unsupported change-guided usefulness rating: {usefulness_value}")

    case = db.one("SELECT target FROM security_cases WHERE case_id=?", (case_value,))
    if not case:
        raise ReconError(f"Security case not found: {case_value}")
    row = db.one(
        "SELECT task_id,status,details_json FROM case_autopilot_tasks "
        "WHERE case_id=? AND task_id=?",
        (case_value, task_value),
    )
    if not row:
        raise ReconError("Change-guided task not found for this case")
    details = safe_json_loads(row["details_json"], {}, expected_type=dict)
    if (
        str(details.get("source") or "") != "derived_change_advisory"
        or not bool(details.get("advisory_only"))
    ):
        raise ReconError("Task is not a Derived Change Advisory review task")

    current_status = str(row["status"] or "open")
    if current_status in CHANGE_TASK_TERMINAL_STATUSES and current_status != status_value:
        raise ReconError(
            f"Terminal change-guided task cannot transition from {current_status} to {status_value}"
        )
    if current_status not in ("open", *CHANGE_TASK_TERMINAL_STATUSES):
        raise ReconError(f"Unsupported existing task status: {current_status}")

    now = utc_now()
    clean_note = str(note or "").strip()[:1000]
    details["analyst_feedback"] = {
        "status": status_value,
        "usefulness": usefulness_value,
        "note": clean_note,
        "actor": str(actor or "analyst")[:200],
        "recorded_at": now,
    }
    details["feedback_is_target_evidence"] = False
    details["feedback_can_auto_tune"] = False
    db.execute(
        "UPDATE case_autopilot_tasks SET status=?,details_json=?,updated_at=? "
        "WHERE case_id=? AND task_id=?",
        (status_value, json_dumps(details), now, case_value, task_value),
    )
    event_details = {
        "task_id": task_value,
        "task_status": status_value,
        "usefulness": usefulness_value,
        "note": clean_note,
        "signal_type": str(details.get("signal_type") or ""),
        "item_key": str(details.get("item_key") or ""),
        "status": "analyst_feedback_observational_only",
        "counts_as_evidence": False,
        "can_auto_tune": False,
    }
    db.execute(
        "INSERT INTO security_case_events("
        "case_id,event_type,actor,details_json,created_at"
        ") VALUES(?,?,?,?,?)",
        (
            case_value,
            "investigation_change_task_feedback",
            str(actor or "analyst")[:200],
            json_dumps(event_details),
            now,
        ),
    )
    db.audit(
        "investigation_change_task_feedback",
        actor=str(actor or "analyst")[:200],
        target=str(case["target"] or ""),
        entity_type="case_autopilot_task",
        entity_value=task_value,
        details={
            "case_id": case_value,
            "task_status": status_value,
            "usefulness": usefulness_value,
            "counts_as_evidence": False,
            "can_auto_tune": False,
        },
    )
    return {
        "case_id": case_value,
        "task_id": task_value,
        "status": status_value,
        "usefulness": usefulness_value,
        "note": clean_note,
        "updated_at": now,
        "safety": {
            "counts_as_target_evidence": False,
            "changes_admission": False,
            "changes_validation_eligibility": False,
            "auto_tuning": False,
            "network_requests": False,
        },
    }


def _persist_change_advisory_tasks(
    db: Database,
    case_id: str,
    guidance: Mapping[str, Any],
    *,
    actor: str,
) -> None:
    # Refresh open advisory tasks only. Terminal analyst outcomes are preserved
    # across workflow refreshes so lifecycle feedback cannot be erased.
    db.execute(
        "DELETE FROM case_autopilot_tasks "
        "WHERE case_id=? AND task_id LIKE 'task-change-%' AND status='open'",
        (case_id,),
    )
    tasks = [
        dict(row)
        for row in guidance.get("tasks", [])
        if isinstance(row, Mapping)
        and str(row.get("title") or "").strip()
    ]
    if not tasks:
        return

    db.execute(
        "UPDATE case_autopilot_tasks SET rank=rank+? "
        "WHERE case_id=? AND status='open'",
        (len(tasks), case_id),
    )
    now = utc_now()
    for index, task in enumerate(tasks, start=1):
        task_id = _change_task_id(case_id, task)
        existing = db.one(
            "SELECT status FROM case_autopilot_tasks WHERE case_id=? AND task_id=?",
            (case_id, task_id),
        )
        if existing and str(existing["status"] or "") in CHANGE_TASK_TERMINAL_STATUSES:
            continue
        details = {
            "source": "derived_change_advisory",
            "advisory_only": True,
            "counts_as_evidence": False,
            "changes_evidence_coverage": False,
            "changes_admission": False,
            "can_execute_validation": False,
            "signal_type": task.get("signal_type"),
            "item": task.get("item"),
            "item_key": task.get("item_key"),
            "requirement_key": task.get("requirement_key"),
            "reasons": task.get("reasons", []),
        }
        db.execute(
            "INSERT OR REPLACE INTO case_autopilot_tasks("
            "task_id,case_id,task_type,title,rank,status,details_json,created_at,updated_at"
            ") VALUES(?,?,?,?,?,'open',?,?,?)",
            (
                task_id,
                case_id,
                str(task.get("type") or "change_review"),
                str(task.get("title") or ""),
                index,
                json_dumps(details),
                now,
                now,
            ),
        )

    db.execute(
        "INSERT INTO security_case_events("
        "case_id,event_type,actor,details_json,created_at"
        ") VALUES(?,?,?,?,?)",
        (
            case_id,
            "investigation_change_guidance_refreshed",
            actor,
            json_dumps(
                {
                    "advisory_score": int(guidance.get("score") or 0),
                    "task_count": len(tasks),
                    "prioritized_requirements": [
                        str(row.get("key") or "")
                        for row in guidance.get("prioritized_requirements", [])
                        if isinstance(row, Mapping)
                    ],
                    "status": "advisory_only_not_evidence",
                }
            ),
            now,
        ),
    )


def _workflow_snapshot_for_case(
    db: Database,
    case: Mapping[str, Any],
    *,
    item: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    case_id = str(case.get("case_id") or "")
    detail = case_detail(db, case_id)
    gap = evidence_gap_for_case(db, case_id, persist=False)
    autopilot = case_autopilot(db, case_id, actor="investigation-preview", persist=False)
    queue_item = dict(item) if isinstance(item, Mapping) else _queue_item_for_case(db, case)
    guidance = _change_guidance(queue_item, gap) if queue_item else _change_guidance({}, gap)
    gap, autopilot = _merge_change_guidance(gap, autopilot, guidance)
    guidance, autopilot, change_task_lifecycle = _apply_change_task_lifecycle(
        db,
        case_id,
        guidance,
        autopilot,
    )
    eligibility = validation_eligibility(db, case_id)
    family = str(case.get("primary_family") or "")
    primary_candidates = [
        row for row in detail.get("candidates", [])
        if str(row.get("bug_family") or "") == family
    ]
    return {
        "status": "started",
        "case": dict(detail.get("case") or case),
        "case_id": case_id,
        "evidence": gap,
        "autopilot": autopilot,
        "validation": eligibility,
        "change_guidance": guidance,
        "change_task_lifecycle": change_task_lifecycle,
        "candidate_count": len(detail.get("candidates", [])),
        "primary_candidate_count": len(primary_candidates),
        "primary_candidate_ids": [str(row.get("candidate_id") or "") for row in primary_candidates],
        "safety": {
            "case_does_not_confirm_vulnerability": True,
            "confirmation_requires_promoted_primary_family_candidate": True,
            "safe_validation_remains_approval_gated": True,
            "change_context_is_advisory_only": True,
            "change_context_does_not_change_evidence_coverage": True,
            "change_context_cannot_trigger_validation": True,
            "change_task_feedback_is_observational_only": True,
            "change_task_feedback_cannot_auto_tune": True,
        },
    }


def cluster_workflow_snapshot(
    db: Database,
    *,
    analysis_id: str,
    item: Mapping[str, Any],
) -> dict[str, Any]:
    target = str(item.get("target") or "")
    cluster_id = str(item.get("cluster_id") or "")
    case = find_cluster_case(db, target=target, cluster_id=cluster_id)
    if not case:
        guidance = _change_guidance(item, {"requirements": []})
        return {
            "status": "not_started",
            "case_id": cluster_case_id(target, cluster_id),
            "candidate_count": 0,
            "primary_candidate_count": 0,
            "analysis_id": analysis_id,
            "change_guidance": guidance,
            "safety": {
                "case_does_not_confirm_vulnerability": True,
                "confirmation_requires_promoted_primary_family_candidate": True,
                "safe_validation_remains_approval_gated": True,
                "change_context_is_advisory_only": True,
                "change_context_does_not_change_evidence_coverage": True,
                "change_context_cannot_trigger_validation": True,
                "change_task_feedback_is_observational_only": True,
                "change_task_feedback_cannot_auto_tune": True,
            },
        }
    return _workflow_snapshot_for_case(db, case, item=item)


def ensure_cluster_case(
    db: Database,
    *,
    analysis_id: str,
    cluster_id: str,
    target: str = "",
    actor: str = "analyst",
    item: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    queue_item = dict(item) if isinstance(item, Mapping) else _queue_item(
        db, analysis_id=analysis_id, cluster_id=cluster_id, target=target
    )
    target_value = str(queue_item.get("target") or target or "").strip()
    cluster_value = str(queue_item.get("cluster_id") or cluster_id or "").strip()
    if not target_value:
        raise ReconError("Investigation cluster target is required")
    if not cluster_value:
        raise ReconError("Investigation cluster id is required")

    hypotheses = _cluster_hypotheses(db, analysis_id, queue_item)
    candidates = _cluster_candidates(db, analysis_id, queue_item, hypotheses)
    family = str(queue_item.get("primary_family") or "").strip()
    label = str(queue_item.get("primary_bug") or family.replace("_", " ") or "Investigation cluster")
    priority = parse_int(queue_item.get("queue_score"), 0, 0, 100)
    source_run_id = next(
        (str(row.get("source_run_id") or "") for row in candidates if str(row.get("source_run_id") or "")),
        next((str(row.get("source_run_id") or "") for row in hypotheses if str(row.get("source_run_id") or "")), ""),
    )
    key = cluster_case_key(cluster_value)
    case_id = cluster_case_id(target_value, cluster_value)
    now = utc_now()
    title = f"Investigate · {label}"
    summary = (
        f"Cluster-level analyst investigation for {label}. Queue score {priority}/100. "
        "This case links stored target evidence and correlated surfaces; it is not vulnerability confirmation."
    )
    existing = db.one("SELECT * FROM security_cases WHERE target=? AND case_key=?", (target_value, key))
    if existing:
        case_id = str(existing["case_id"])
        db.execute(
            "UPDATE security_cases SET analysis_id=?,source_run_id=?,title=?,summary=?,primary_family=?,priority_score=?,updated_at=? WHERE case_id=?",
            (analysis_id, source_run_id, title, summary, family, priority, now, case_id),
        )
        event_type = "investigation_cluster_refreshed"
    else:
        db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,'reviewing','','unknown',0,?,?)",
            (case_id, key, analysis_id, source_run_id, target_value, title, summary, family, priority, now, now),
        )
        event_type = "investigation_cluster_started"

    db.execute(
        "DELETE FROM security_case_members WHERE case_id=? AND relation IN ('cluster_candidate','cluster_hypothesis','cluster_alert')",
        (case_id,),
    )
    alert_ids: set[str] = set()
    for candidate in candidates:
        candidate_id = str(candidate.get("candidate_id") or "")
        if not candidate_id:
            continue
        db.execute(
            "INSERT OR REPLACE INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES(?,?,?,?,?,?)",
            (
                case_id,
                "candidate",
                candidate_id,
                "cluster_candidate",
                json_dumps({
                    "cluster_id": cluster_value,
                    "family": candidate.get("bug_family"),
                    "state": candidate.get("candidate_state"),
                    "investigation_value": candidate.get("investigation_value"),
                }),
                now,
            ),
        )
        if candidate.get("alert_id") is not None:
            alert_ids.add(str(candidate.get("alert_id")))
    for hypothesis in hypotheses:
        hypothesis_id = str(hypothesis.get("hypothesis_id") or "")
        if hypothesis_id:
            db.execute(
                "INSERT OR REPLACE INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES(?,?,?,?,?,?)",
                (
                    case_id,
                    "hypothesis",
                    hypothesis_id,
                    "cluster_hypothesis",
                    json_dumps({
                        "cluster_id": cluster_value,
                        "family": hypothesis.get("bug_family"),
                        "state": hypothesis.get("state"),
                    }),
                    now,
                ),
            )
        if hypothesis.get("alert_id") is not None:
            alert_ids.add(str(hypothesis.get("alert_id")))
    for alert_id in sorted(alert_ids):
        db.execute(
            "INSERT OR REPLACE INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES(?,?,?,?,?,?)",
            (case_id, "alert", alert_id, "cluster_alert", json_dumps({"cluster_id": cluster_value}), now),
        )

    db.execute(
        "INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",
        (
            case_id,
            event_type,
            actor,
            json_dumps({
                "analysis_id": analysis_id,
                "cluster_id": cluster_value,
                "candidate_count": len(candidates),
                "hypothesis_count": len(hypotheses),
                "status": "investigation_only_not_confirmed",
            }),
            now,
        ),
    )
    db.audit(
        event_type,
        actor=actor,
        target=target_value,
        entity_type="case",
        entity_value=case_id,
        details={"cluster_id": cluster_value, "analysis_id": analysis_id, "candidate_count": len(candidates)},
    )

    # Persist the initial evidence/autopilot snapshot, then add review-only
    # change-aware tasks. Neither path executes validation.
    case_autopilot(db, case_id, actor=actor, persist=True)
    gap_preview = evidence_gap_for_case(db, case_id, persist=False)
    guidance = _change_guidance(queue_item, gap_preview)
    _persist_change_advisory_tasks(
        db,
        case_id,
        guidance,
        actor=actor,
    )
    case = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    return _workflow_snapshot_for_case(
        db,
        dict(case) if case else {"case_id": case_id, "primary_family": family},
        item=queue_item,
    )


def refresh_case_workflow(db: Database, case_id: str, *, actor: str = "analyst") -> dict[str, Any]:
    case = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    if not case:
        raise ReconError(f"Security case not found: {case_id}")
    case_dict = dict(case)
    case_autopilot(db, case_id, actor=actor, persist=True)
    queue_item = _queue_item_for_case(db, case_dict)
    gap_preview = evidence_gap_for_case(db, case_id, persist=False)
    guidance = _change_guidance(queue_item, gap_preview) if queue_item else _change_guidance({}, gap_preview)
    _persist_change_advisory_tasks(
        db,
        case_id,
        guidance,
        actor=actor,
    )
    db.execute(
        "INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",
        (
            case_id,
            "investigation_workflow_refreshed",
            actor,
            json_dumps(
                {
                    "change_aware": bool(guidance.get("available")),
                    "change_advisory_score": int(guidance.get("score") or 0),
                }
            ),
            utc_now(),
        ),
    )
    return _workflow_snapshot_for_case(db, case_dict, item=queue_item or None)


def record_cluster_decision(
    db: Database,
    case_id: str,
    decision: str,
    *,
    note: str = "",
    actor: str = "analyst",
) -> dict[str, Any]:
    if decision not in CLUSTER_DECISIONS:
        raise ReconError(f"Unsupported investigation decision: {decision}")
    case = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    if not case:
        raise ReconError(f"Security case not found: {case_id}")
    case_dict = dict(case)
    family = str(case_dict.get("primary_family") or "")
    rows = [
        dict(row)
        for row in db.all(
            "SELECT bc.* FROM security_case_members m JOIN bug_candidates bc ON bc.candidate_id=m.member_id "
            "WHERE m.case_id=? AND m.member_type='candidate' AND bc.bug_family=? ORDER BY bc.investigation_value DESC",
            (case_id, family),
        )
    ]
    if decision == "confirmed_by_analyst" and not rows:
        raise ReconError(
            "This cluster has no promoted Potential Finding for its primary family. "
            "A proximity-only cluster cannot be confirmed as a vulnerability."
        )

    reason_code = "duplicate" if decision == "duplicate" else ""
    for row in rows:
        set_bug_candidate_decision(
            db,
            str(row.get("candidate_id") or ""),
            decision,
            note=note,
            actor=actor,
            reason_code=reason_code,
        )

    state = {
        "confirmed_by_analyst": "confirmed",
        "needs_more_evidence": "needs_evidence",
        "rejected": "rejected",
        "duplicate": "rejected",
    }[decision]
    set_case_state(
        db,
        case_id,
        state,
        assigned_to=str(case_dict.get("assigned_to") or ""),
        note=f"Cluster decision: {decision}. {note}".strip(),
        actor=actor,
    )
    db.execute(
        "INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",
        (
            case_id,
            "investigation_cluster_decision",
            actor,
            json_dumps({
                "decision": decision,
                "primary_family": family,
                "candidate_count": len(rows),
                "historical_feedback_applies_to_future_rankings": bool(rows),
            }),
            utc_now(),
        ),
    )
    db.audit(
        "investigation_cluster_decision",
        actor=actor,
        target=str(case_dict.get("target") or ""),
        entity_type="case",
        entity_value=case_id,
        details={"decision": decision, "primary_family": family, "candidate_count": len(rows)},
    )
    updated = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    return _workflow_snapshot_for_case(db, dict(updated) if updated else case_dict)
