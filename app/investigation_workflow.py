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
from core import Database, ReconError, json_dumps, parse_int, utc_now
from correlation_engine import investigation_queue
from product_platform import case_detail, set_case_state
from safe_validation import validation_eligibility
from workspace_v7 import case_autopilot, evidence_gap_for_case


INVESTIGATION_WORKFLOW_VERSION = "1.0.0"
CLUSTER_CASE_PREFIX = "investigation-cluster:"
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


def _workflow_snapshot_for_case(db: Database, case: Mapping[str, Any]) -> dict[str, Any]:
    case_id = str(case.get("case_id") or "")
    detail = case_detail(db, case_id)
    gap = evidence_gap_for_case(db, case_id, persist=False)
    autopilot = case_autopilot(db, case_id, actor="investigation-preview", persist=False)
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
        "candidate_count": len(detail.get("candidates", [])),
        "primary_candidate_count": len(primary_candidates),
        "primary_candidate_ids": [str(row.get("candidate_id") or "") for row in primary_candidates],
        "safety": {
            "case_does_not_confirm_vulnerability": True,
            "confirmation_requires_promoted_primary_family_candidate": True,
            "safe_validation_remains_approval_gated": True,
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
        return {
            "status": "not_started",
            "case_id": cluster_case_id(target, cluster_id),
            "candidate_count": 0,
            "primary_candidate_count": 0,
            "analysis_id": analysis_id,
            "safety": {
                "case_does_not_confirm_vulnerability": True,
                "confirmation_requires_promoted_primary_family_candidate": True,
                "safe_validation_remains_approval_gated": True,
            },
        }
    return _workflow_snapshot_for_case(db, case)


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

    # Persist the initial evidence/autopilot snapshot, but do not execute validation.
    case_autopilot(db, case_id, actor=actor, persist=True)
    case = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    return _workflow_snapshot_for_case(db, dict(case) if case else {"case_id": case_id, "primary_family": family})


def refresh_case_workflow(db: Database, case_id: str, *, actor: str = "analyst") -> dict[str, Any]:
    case = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    if not case:
        raise ReconError(f"Security case not found: {case_id}")
    case_autopilot(db, case_id, actor=actor, persist=True)
    db.execute(
        "INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)",
        (case_id, "investigation_workflow_refreshed", actor, "{}", utc_now()),
    )
    return _workflow_snapshot_for_case(db, dict(case))


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
