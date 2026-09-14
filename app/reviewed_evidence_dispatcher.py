from __future__ import annotations

"""Unified reviewed-evidence dispatch into Admission and finding notifications.

This module performs no target-side collection or validation. It consumes only
review IDs produced by existing offline reviewers, delegates Admission to the
established family bridges, and then runs the existing Potential Finding
notification pipeline. Notification state is initialized before Admission so a
newly promoted Candidate is not mistaken for pre-existing bootstrap state.
"""

from types import SimpleNamespace
from typing import Any, Callable, Mapping

from core import Database, ReconError, json_dumps, safe_json_loads, sha256_text, utc_now
from finding_notifications import ensure_finding_notification_schema, process_finding_notifications


REVIEWED_EVIDENCE_DISPATCHER_VERSION = "1.0.0"
REVIEWED_EVIDENCE_DISPATCHER_SCHEMA_VERSION = 1

_KIND_PREFIXES = {
    "account_enumeration": "CID-",
    "authentication_session": "ASL-",
    "graphql_data_exposure": "GQLD-",
    "material_classification": "MCR-",
}


def ensure_reviewed_evidence_dispatcher_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS reviewed_evidence_dispatch_runs (
          dispatch_key TEXT PRIMARY KEY,
          review_kind TEXT NOT NULL,
          review_id TEXT NOT NULL,
          analysis_id TEXT NOT NULL DEFAULT '',
          source_run_id TEXT NOT NULL DEFAULT '',
          target TEXT NOT NULL DEFAULT '',
          candidate_id TEXT NOT NULL DEFAULT '',
          bridge_status TEXT NOT NULL DEFAULT '',
          notification_status TEXT NOT NULL DEFAULT '',
          event_ids_json TEXT NOT NULL DEFAULT '[]',
          status TEXT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          first_seen_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          completed_at TEXT NOT NULL DEFAULT '',
          UNIQUE(review_kind,review_id)
        )
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('reviewed_evidence_dispatcher_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(REVIEWED_EVIDENCE_DISPATCHER_SCHEMA_VERSION),),
    )


def _infer_kind(review_id: str) -> str:
    for kind, prefix in _KIND_PREFIXES.items():
        if review_id.startswith(prefix):
            return kind
    return ""


def _normalize_kind(review_id: str, review_kind: str) -> str:
    inferred = _infer_kind(review_id)
    requested = str(review_kind or "").strip()
    if requested and requested not in _KIND_PREFIXES:
        raise ReconError("Unsupported reviewed evidence kind")
    if not requested:
        if not inferred:
            raise ReconError("Unable to infer reviewed evidence kind from review_id")
        return inferred
    if inferred and requested != inferred:
        raise ReconError("review_kind does not match review_id prefix")
    prefix = _KIND_PREFIXES[requested]
    if not review_id.startswith(prefix):
        raise ReconError("review_id does not match the selected reviewed evidence kind")
    return requested


def _bridge(kind: str) -> Callable[[Database, str, str], dict[str, Any]]:
    if kind == "account_enumeration":
        from account_enumeration_admission_bridge import apply_account_enumeration_admission

        return lambda db, review_id, actor: apply_account_enumeration_admission(
            db, comparison_id=review_id, actor=actor
        )
    if kind == "authentication_session":
        from authentication_session_admission_bridge import apply_authentication_session_admission

        return lambda db, review_id, actor: apply_authentication_session_admission(
            db, lifecycle_id=review_id, actor=actor
        )
    if kind == "graphql_data_exposure":
        from graphql_data_exposure_admission_bridge import apply_graphql_data_exposure_admission

        return lambda db, review_id, actor: apply_graphql_data_exposure_admission(
            db, comparison_id=review_id, actor=actor
        )
    if kind == "material_classification":
        from material_classification_admission_bridge import apply_material_classification_admission

        return lambda db, review_id, actor: apply_material_classification_admission(
            db, review_id=review_id, actor=actor
        )
    raise ReconError("Unsupported reviewed evidence kind")


def _source_run_id(db: Database, analysis_id: str, candidate_id: str) -> str:
    if candidate_id:
        row = db.one(
            "SELECT source_run_id FROM bug_candidates WHERE candidate_id=?",
            (candidate_id,),
        )
        if row and str(row["source_run_id"] or ""):
            return str(row["source_run_id"])
    if analysis_id:
        row = db.one("SELECT source_run_id FROM analysis_runs WHERE id=?", (analysis_id,))
        if row:
            return str(row["source_run_id"] or "")
    return ""


def _notification_context(ctx: Any, *, target: str, run_id: str) -> Any:
    return SimpleNamespace(
        paths=getattr(ctx, "paths", None),
        config=getattr(ctx, "config", None),
        db=ctx.db,
        logger=ctx.logger,
        run_id=run_id,
        policy=SimpleNamespace(name=target),
    )


def _matching_events(db: Database, candidate_id: str, transitions: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    event_ids = [
        str(item.get("event_id") or "")
        for item in transitions
        if str(item.get("candidate_id") or "") == candidate_id and str(item.get("event_id") or "")
    ]
    rows: list[dict[str, Any]] = []
    for event_id in dict.fromkeys(event_ids):
        row = db.one(
            "SELECT event_id,status,mode,score,delivered_at FROM notification_events WHERE event_id=?",
            (event_id,),
        )
        if row:
            rows.append(dict(row))
    return rows


def dispatch_reviewed_evidence(
    ctx: Any,
    *,
    review_id: str,
    review_kind: str = "",
    actor: str = "analyst",
) -> dict[str, Any]:
    """Dispatch one immutable reviewed-evidence record through the existing pipeline.

    Event creation remains idempotent in ``finding_notifications``. The dispatcher
    intentionally re-runs notification processing on repeated calls so a queued
    event whose transport previously failed can be retried without creating a
    duplicate transition or Candidate.
    """

    review_id = str(review_id or "").strip()
    if not review_id:
        raise ReconError("A reviewed evidence review_id is required")
    kind = _normalize_kind(review_id, review_kind)
    db: Database = ctx.db

    ensure_reviewed_evidence_dispatcher_schema(db)
    # Critical ordering: bootstrap historical notification state before a bridge
    # can create a new Candidate from this reviewed evidence.
    ensure_finding_notification_schema(db)

    dispatch_key = "RED-" + sha256_text(f"{kind}|{review_id}")[:24].upper()
    previous = db.one(
        "SELECT * FROM reviewed_evidence_dispatch_runs WHERE dispatch_key=?",
        (dispatch_key,),
    )
    previous_map = dict(previous) if previous else {}

    bridge_result = _bridge(kind)(db, review_id, actor)
    analysis_id = str(bridge_result.get("analysis_id") or "")
    target = str(bridge_result.get("target") or "")
    candidate_id = str(bridge_result.get("candidate_id") or "")
    source_run_id = _source_run_id(db, analysis_id, candidate_id)

    notification_result: dict[str, Any] = {
        "status": "not_applicable",
        "analysis_id": analysis_id,
        "queued": 0,
        "deduplicated": 0,
        "transitions": [],
        "delivery": {"queued": 0, "delivered": 0, "error": ""},
    }
    if candidate_id and analysis_id and target:
        notification_result = process_finding_notifications(
            _notification_context(ctx, target=target, run_id=source_run_id),
            {"analysis_id": analysis_id, "status": "success"},
            baseline=False,
        )

    matching_transitions = [
        dict(item)
        for item in list(notification_result.get("transitions") or [])
        if isinstance(item, Mapping) and str(item.get("candidate_id") or "") == candidate_id
    ]
    events = _matching_events(db, candidate_id, matching_transitions) if candidate_id else []
    event_ids = [str(item.get("event_id") or "") for item in events]

    bridge_status = str(bridge_result.get("status") or "")
    notification_status = str(notification_result.get("status") or "not_applicable")
    if not candidate_id:
        status = "not_eligible" if bridge_status == "not_eligible" else "no_candidate"
    elif notification_status == "success":
        status = "completed"
    else:
        status = "notification_incomplete"

    now = utc_now()
    attempts = int(previous_map.get("attempts") or 0) + 1
    first_seen_at = str(previous_map.get("first_seen_at") or now)
    completed_at = now if status == "completed" else str(previous_map.get("completed_at") or "")
    with db.transaction():
        db.execute(
            "INSERT INTO reviewed_evidence_dispatch_runs("
            "dispatch_key,review_kind,review_id,analysis_id,source_run_id,target,candidate_id,"
            "bridge_status,notification_status,event_ids_json,status,attempts,first_seen_at,updated_at,completed_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(dispatch_key) DO UPDATE SET "
            "analysis_id=excluded.analysis_id,source_run_id=excluded.source_run_id,target=excluded.target,"
            "candidate_id=excluded.candidate_id,bridge_status=excluded.bridge_status,"
            "notification_status=excluded.notification_status,event_ids_json=excluded.event_ids_json,"
            "status=excluded.status,attempts=excluded.attempts,updated_at=excluded.updated_at,"
            "completed_at=excluded.completed_at",
            (
                dispatch_key,
                kind,
                review_id,
                analysis_id,
                source_run_id,
                target,
                candidate_id,
                bridge_status,
                notification_status,
                json_dumps(event_ids),
                status,
                attempts,
                first_seen_at,
                now,
                completed_at,
            ),
        )
        db.audit(
            "reviewed_evidence_dispatched",
            actor=actor,
            target=target,
            entity_type="reviewed_evidence",
            entity_value=review_id,
            details={
                "dispatch_key": dispatch_key,
                "review_kind": kind,
                "bridge_status": bridge_status,
                "candidate_id": candidate_id,
                "notification_status": notification_status,
                "event_ids": event_ids,
                "attempts": attempts,
                "target_network_requests_executed": 0,
                "vulnerability_confirmed": False,
            },
        )

    return {
        "version": REVIEWED_EVIDENCE_DISPATCHER_VERSION,
        "dispatch_key": dispatch_key,
        "review_kind": kind,
        "review_id": review_id,
        "status": status,
        "attempts": attempts,
        "replayed": bool(previous_map),
        "analysis_id": analysis_id,
        "source_run_id": source_run_id,
        "target": target,
        "candidate_id": candidate_id,
        "bridge": bridge_result,
        "notification": notification_result,
        "candidate_transitions": matching_transitions,
        "notification_events": events,
        "target_network_requests_executed": 0,
        "notification_delivery_may_use_configured_outbound_transports": bool(candidate_id),
        "vulnerability_confirmed": False,
    }
