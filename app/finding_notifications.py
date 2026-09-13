from __future__ import annotations

"""Idempotent Potential Finding notification pipeline.

Recon Change Alerts and Potential Finding notifications are intentionally
separate streams.  This module runs after automatic Analysis has finished and
queues notifications only for new or materially stronger Potential Findings.

The notification reference state is keyed by the stable candidate fingerprint,
not by analysis_id/candidate_id.  Existing installations are bootstrapped from
their latest historical candidate state so enabling this feature does not create
an alert storm for old findings.
"""

import sys
import uuid
from typing import Any, Mapping

from core import (
    APP_VERSION,
    Database,
    ReconError,
    TelegramNotifier,
    json_dumps,
    parse_int,
    safe_json_loads,
    sha256_text,
    utc_now,
)


FINDING_NOTIFICATION_SCHEMA_VERSION = 1
BOOTSTRAP_META_KEY = "finding_notification_bootstrap_v1"
EVENT_TYPE = "potential_finding"
ELIGIBLE_STATES = {"plausible", "strong_candidate", "confirmed_by_analyst"}
NEGATIVE_DECISIONS = {"rejected", "duplicate", "out_of_scope"}
STATE_RANK = {
    "insufficient_evidence": 0,
    "weak_signal": 1,
    "possible": 2,
    "needs_revalidation": 2,
    "plausible": 3,
    "strong_candidate": 4,
    "confirmed_by_analyst": 5,
}
MATERIAL_SCORE_DELTA = 10


def _support_count(candidate: Mapping[str, Any]) -> int:
    rows = safe_json_loads(candidate.get("supporting_evidence_json"), [], expected_type=list)
    if not isinstance(rows, list):
        return 0
    stable: set[str] = set()
    for row in rows:
        if isinstance(row, Mapping):
            stable.add(
                str(
                    row.get("root_fingerprint")
                    or row.get("source_group")
                    or row.get("type")
                    or json_dumps(dict(row))
                )
            )
        else:
            stable.add(str(row))
    return len(stable)


def _candidate_snapshot(candidate: Mapping[str, Any]) -> dict[str, Any]:
    likelihood = parse_int(
        candidate.get("calibrated_likelihood"),
        parse_int(candidate.get("likelihood_score"), 0, 0, 100),
        0,
        100,
    )
    return {
        "candidate_state": str(candidate.get("candidate_state") or ""),
        "lifecycle_state": str(candidate.get("lifecycle_state") or "observed"),
        "likelihood": likelihood,
        "evidence_strength": parse_int(candidate.get("evidence_strength"), 0, 0, 100),
        "investigation_value": parse_int(
            candidate.get("investigation_value"),
            parse_int(candidate.get("priority_score"), 0, 0, 100),
            0,
            100,
        ),
        "support_count": _support_count(candidate),
        "analyst_decision": str(candidate.get("analyst_decision") or "unreviewed"),
    }


def _eligible(candidate: Mapping[str, Any]) -> bool:
    decision = str(candidate.get("analyst_decision") or "unreviewed")
    state = str(candidate.get("candidate_state") or "")
    if decision in NEGATIVE_DECISIONS:
        return False
    if decision == "confirmed_by_analyst":
        return True
    if decision not in {"unreviewed", ""}:
        return False
    return state in ELIGIBLE_STATES


def _policy(db: Database, target: str) -> tuple[str, int]:
    row = db.one(
        "SELECT * FROM notification_policies WHERE enabled=1 AND ("
        "(target=? AND event_type=?) OR (target=? AND event_type='*') OR "
        "(target='*' AND event_type=?) OR (target='*' AND event_type='*')) "
        "ORDER BY CASE WHEN target=? THEN 0 ELSE 1 END,"
        "CASE WHEN event_type=? THEN 0 ELSE 1 END LIMIT 1",
        (target, EVENT_TYPE, target, EVENT_TYPE, target, EVENT_TYPE),
    )
    if row is None:
        # Potential Findings are already admission-filtered Analysis output, so
        # the default operational behavior is same-run notification.
        return "immediate", 0
    mode = str(row["mode"] or "immediate")
    if mode not in {"immediate", "digest", "system_warning", "silent"}:
        mode = "immediate"
    return mode, parse_int(row["minimum_score"], 0, 0, 100)


def ensure_finding_notification_schema(db: Database) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS finding_notification_state (
          target TEXT NOT NULL,
          candidate_fingerprint TEXT NOT NULL,
          reference_candidate_state TEXT NOT NULL DEFAULT '',
          reference_lifecycle_state TEXT NOT NULL DEFAULT '',
          reference_likelihood INTEGER NOT NULL DEFAULT 0,
          reference_evidence_strength INTEGER NOT NULL DEFAULT 0,
          reference_investigation_value INTEGER NOT NULL DEFAULT 0,
          reference_support_count INTEGER NOT NULL DEFAULT 0,
          reference_analyst_decision TEXT NOT NULL DEFAULT 'unreviewed',
          reference_set_at TEXT NOT NULL,
          reference_reason TEXT NOT NULL DEFAULT 'bootstrap',
          last_seen_analysis_id TEXT NOT NULL DEFAULT '',
          last_seen_run_id TEXT NOT NULL DEFAULT '',
          last_seen_candidate_id TEXT NOT NULL DEFAULT '',
          last_seen_at TEXT NOT NULL,
          last_event_id TEXT NOT NULL DEFAULT '',
          updated_at TEXT NOT NULL,
          PRIMARY KEY(target,candidate_fingerprint)
        );
        CREATE TABLE IF NOT EXISTS finding_notification_transitions (
          transition_key TEXT PRIMARY KEY,
          target TEXT NOT NULL,
          candidate_fingerprint TEXT NOT NULL,
          transition_type TEXT NOT NULL,
          event_id TEXT NOT NULL DEFAULT '',
          analysis_id TEXT NOT NULL DEFAULT '',
          run_id TEXT NOT NULL DEFAULT '',
          snapshot_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_finding_notification_transitions_target
          ON finding_notification_transitions(target,candidate_fingerprint,created_at);
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('finding_notification_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(FINDING_NOTIFICATION_SCHEMA_VERSION),),
    )

    marker = db.one("SELECT value FROM schema_meta WHERE key=?", (BOOTSTRAP_META_KEY,))
    if marker is not None:
        return

    # Conservative rollout: existing candidates establish notification reference
    # state but are not claimed as previously delivered notifications.
    rows = db.all(
        "SELECT rowid,* FROM bug_candidates "
        "ORDER BY target,candidate_fingerprint,COALESCE(updated_at,created_at) DESC,rowid DESC"
    )
    seen: set[tuple[str, str]] = set()
    now = utc_now()
    for row in rows:
        candidate = dict(row)
        target = str(candidate.get("target") or "")
        fingerprint = str(candidate.get("candidate_fingerprint") or "")
        key = (target, fingerprint)
        if not target or not fingerprint or key in seen:
            continue
        seen.add(key)
        snap = _candidate_snapshot(candidate)
        db.execute(
            "INSERT OR IGNORE INTO finding_notification_state("
            "target,candidate_fingerprint,reference_candidate_state,reference_lifecycle_state,"
            "reference_likelihood,reference_evidence_strength,reference_investigation_value,"
            "reference_support_count,reference_analyst_decision,reference_set_at,reference_reason,"
            "last_seen_analysis_id,last_seen_run_id,last_seen_candidate_id,last_seen_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                target,
                fingerprint,
                snap["candidate_state"],
                snap["lifecycle_state"],
                snap["likelihood"],
                snap["evidence_strength"],
                snap["investigation_value"],
                snap["support_count"],
                snap["analyst_decision"],
                now,
                "bootstrap",
                str(candidate.get("analysis_id") or ""),
                str(candidate.get("source_run_id") or ""),
                str(candidate.get("candidate_id") or ""),
                now,
                now,
            ),
        )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (BOOTSTRAP_META_KEY, now),
    )


def _transition(reference: Mapping[str, Any] | None, snap: Mapping[str, Any]) -> str:
    if reference is None:
        return "new"
    ref_state = str(reference.get("reference_candidate_state") or "")
    current_state = str(snap["candidate_state"])
    ref_decision = str(reference.get("reference_analyst_decision") or "unreviewed")
    current_decision = str(snap["analyst_decision"])

    if current_decision == "confirmed_by_analyst" and ref_decision != "confirmed_by_analyst":
        return "promoted"
    if STATE_RANK.get(current_state, 0) > STATE_RANK.get(ref_state, 0):
        return "promoted"
    if (
        str(snap["lifecycle_state"]) == "recurring"
        and str(reference.get("reference_lifecycle_state") or "") != "recurring"
    ):
        return "reopened"
    if (
        int(snap["investigation_value"])
        >= int(reference.get("reference_investigation_value") or 0) + MATERIAL_SCORE_DELTA
        or int(snap["likelihood"])
        >= int(reference.get("reference_likelihood") or 0) + MATERIAL_SCORE_DELTA
    ):
        return "confidence_increased"
    if (
        int(snap["evidence_strength"])
        >= int(reference.get("reference_evidence_strength") or 0) + MATERIAL_SCORE_DELTA
        or int(snap["support_count"])
        > int(reference.get("reference_support_count") or 0)
    ):
        return "material_evidence_added"
    return ""


def _upsert_seen_state(
    db: Database,
    candidate: Mapping[str, Any],
    snap: Mapping[str, Any],
) -> None:
    now = utc_now()
    db.execute(
        "INSERT INTO finding_notification_state("
        "target,candidate_fingerprint,reference_candidate_state,reference_lifecycle_state,"
        "reference_likelihood,reference_evidence_strength,reference_investigation_value,"
        "reference_support_count,reference_analyst_decision,reference_set_at,reference_reason,"
        "last_seen_analysis_id,last_seen_run_id,last_seen_candidate_id,last_seen_at,updated_at"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(target,candidate_fingerprint) DO UPDATE SET "
        "last_seen_analysis_id=excluded.last_seen_analysis_id,last_seen_run_id=excluded.last_seen_run_id,"
        "last_seen_candidate_id=excluded.last_seen_candidate_id,last_seen_at=excluded.last_seen_at,"
        "updated_at=excluded.updated_at",
        (
            str(candidate.get("target") or ""),
            str(candidate.get("candidate_fingerprint") or ""),
            snap["candidate_state"],
            snap["lifecycle_state"],
            snap["likelihood"],
            snap["evidence_strength"],
            snap["investigation_value"],
            snap["support_count"],
            snap["analyst_decision"],
            now,
            "first_seen",
            str(candidate.get("analysis_id") or ""),
            str(candidate.get("source_run_id") or ""),
            str(candidate.get("candidate_id") or ""),
            now,
            now,
        ),
    )


def _queue_transition(
    db: Database,
    candidate: Mapping[str, Any],
    snap: Mapping[str, Any],
    transition: str,
    *,
    mode: str,
) -> tuple[str, bool]:
    target = str(candidate.get("target") or "")
    fingerprint = str(candidate.get("candidate_fingerprint") or "")
    material = {
        "candidate_fingerprint": fingerprint,
        "transition": transition,
        **dict(snap),
    }
    transition_key = sha256_text(json_dumps(material))
    existing_transition = db.one(
        "SELECT event_id FROM finding_notification_transitions WHERE transition_key=?",
        (transition_key,),
    )
    if existing_transition is not None:
        return str(existing_transition["event_id"] or ""), True

    notification_fingerprint = sha256_text(
        f"{target}|{EVENT_TYPE}|{fingerprint}|{transition_key}"
    )
    existing_event = db.one(
        "SELECT event_id FROM notification_events WHERE fingerprint=? LIMIT 1",
        (notification_fingerprint,),
    )
    event_id = str(existing_event["event_id"]) if existing_event else "notify-" + uuid.uuid4().hex[:14]
    now = utc_now()
    score = int(snap["investigation_value"])
    if str(snap["analyst_decision"]) == "confirmed_by_analyst":
        score = max(score, 95)
    payload = {
        "event_type": EVENT_TYPE,
        "transition": transition,
        "title": f"Potential Finding: {candidate.get('title') or candidate.get('bug_family') or 'security candidate'}",
        "summary": str(candidate.get("summary") or ""),
        "score": score,
        "target": target,
        "candidate_id": str(candidate.get("candidate_id") or ""),
        "candidate_fingerprint": fingerprint,
        "bug_family": str(candidate.get("bug_family") or ""),
        "bug_variant": str(candidate.get("bug_variant") or ""),
        "endpoint": str(candidate.get("endpoint") or candidate.get("asset") or ""),
        "candidate_state": str(snap["candidate_state"]),
        "analyst_decision": str(snap["analyst_decision"]),
        "investigation_value": int(snap["investigation_value"]),
        "likelihood": int(snap["likelihood"]),
        "evidence_strength": int(snap["evidence_strength"]),
    }

    if existing_event is None:
        db.execute(
            "INSERT INTO notification_events("
            "event_id,target,event_type,mode,score,fingerprint,payload_json,status,occurrences,created_at,last_seen_at"
            ") VALUES(?,?,?,?,?,?,?,'queued',1,?,?)",
            (
                event_id,
                target,
                EVENT_TYPE,
                mode,
                score,
                notification_fingerprint,
                json_dumps(payload),
                now,
                now,
            ),
        )

    db.execute(
        "INSERT INTO finding_notification_transitions("
        "transition_key,target,candidate_fingerprint,transition_type,event_id,analysis_id,run_id,snapshot_json,created_at"
        ") VALUES(?,?,?,?,?,?,?,?,?)",
        (
            transition_key,
            target,
            fingerprint,
            transition,
            event_id,
            str(candidate.get("analysis_id") or ""),
            str(candidate.get("source_run_id") or ""),
            json_dumps(material),
            now,
        ),
    )
    db.execute(
        "UPDATE finding_notification_state SET "
        "reference_candidate_state=?,reference_lifecycle_state=?,reference_likelihood=?,"
        "reference_evidence_strength=?,reference_investigation_value=?,reference_support_count=?,"
        "reference_analyst_decision=?,reference_set_at=?,reference_reason='notified',last_event_id=?,updated_at=? "
        "WHERE target=? AND candidate_fingerprint=?",
        (
            snap["candidate_state"],
            snap["lifecycle_state"],
            snap["likelihood"],
            snap["evidence_strength"],
            snap["investigation_value"],
            snap["support_count"],
            snap["analyst_decision"],
            now,
            event_id,
            now,
            target,
            fingerprint,
        ),
    )
    return event_id, False


def _deliver_pending(ctx: Any, limit: int = 50) -> dict[str, Any]:
    rows = [
        dict(row)
        for row in ctx.db.all(
            "SELECT * FROM notification_events WHERE target=? AND event_type=? "
            "AND status='queued' AND mode='immediate' ORDER BY score DESC,created_at LIMIT ?",
            (ctx.policy.name, EVENT_TYPE, max(1, min(200, int(limit)))),
        )
    ]
    if not rows:
        return {"queued": 0, "delivered": 0, "error": ""}

    lines = [
        f"🚨 Recon Monitor {APP_VERSION} — Potential Findings",
        f"Target: {ctx.policy.name}",
        f"Run: {ctx.run_id}",
        "",
    ]
    for row in rows:
        payload = safe_json_loads(row["payload_json"], {}, expected_type=dict)
        lines.append(
            f"• [{row['score']}] [{payload.get('transition','new')}] "
            f"{payload.get('bug_family') or 'candidate'} — "
            f"{payload.get('title') or 'Potential Finding'}"
            + (f" @ {payload.get('endpoint')}" if payload.get("endpoint") else "")
        )
    message = "\n".join(lines)[:15000]

    telegram_ok = False
    notify_ok = False
    error = ""
    try:
        notifier = TelegramNotifier(ctx.config, ctx.logger)
        telegram_ok = notifier.send(message) if notifier.ready else False
    except Exception as exc:
        error = str(exc)
        ctx.logger.warn("Potential Finding Telegram notification failed", error=str(exc))
    try:
        # Reuse the established notify-cli transport without coupling this
        # pipeline to Recon Change Alert lifecycle or alert rows.
        import reporting

        notify_ok = bool(reporting._send_notify_cli(ctx.config, ctx.logger, message))
    except Exception as exc:
        error = error or str(exc)
        ctx.logger.warn("Potential Finding notify-cli delivery failed", error=str(exc))

    delivered = len(rows) if (telegram_ok or notify_ok) else 0
    if delivered:
        now = utc_now()
        channel = "telegram+notify" if telegram_ok and notify_ok else "telegram" if telegram_ok else "notify"
        with ctx.db.transaction():
            for row in rows:
                ctx.db.execute(
                    "UPDATE notification_events SET status='delivered',delivered_at=? WHERE event_id=? AND status='queued'",
                    (now, str(row["event_id"])),
                )
                ctx.db.execute(
                    "INSERT INTO notification_deliveries(event_id,channel,status,error,created_at) "
                    "VALUES(?,?, 'delivered','',?)",
                    (str(row["event_id"]), channel, now),
                )
    return {"queued": len(rows), "delivered": delivered, "error": error}


def process_finding_notifications(
    ctx: Any,
    analysis_summary: Mapping[str, Any] | None,
    *,
    baseline: bool = False,
) -> dict[str, Any]:
    """Queue material Potential Finding transitions after Analysis.

    `baseline` is reported for observability only.  It does not suppress this
    stream; baseline suppression applies to Recon Change Alerts, not findings.
    """

    ensure_finding_notification_schema(ctx.db)
    analysis = dict(analysis_summary or {})
    analysis_id = str(analysis.get("analysis_id") or "")
    queued = 0
    deduplicated = 0
    skipped_ineligible = 0
    skipped_unchanged = 0
    skipped_policy = 0
    transitions: list[dict[str, Any]] = []

    candidates: list[dict[str, Any]] = []
    if analysis_id:
        candidates = [
            dict(row)
            for row in ctx.db.all(
                "SELECT * FROM bug_candidates WHERE analysis_id=? AND target=? "
                "ORDER BY investigation_value DESC,priority_score DESC,candidate_id",
                (analysis_id, ctx.policy.name),
            )
        ]

    mode, minimum_score = _policy(ctx.db, ctx.policy.name)
    for candidate in candidates:
        fingerprint = str(candidate.get("candidate_fingerprint") or "")
        if not fingerprint:
            fingerprint = sha256_text(
                "|".join(
                    [
                        str(candidate.get("target") or ctx.policy.name),
                        str(candidate.get("bug_family") or ""),
                        str(candidate.get("bug_variant") or ""),
                        str(candidate.get("endpoint") or candidate.get("asset") or ""),
                    ]
                )
            )
            candidate["candidate_fingerprint"] = fingerprint

        snap = _candidate_snapshot(candidate)
        with ctx.db.transaction():
            reference_row = ctx.db.one(
                "SELECT * FROM finding_notification_state WHERE target=? AND candidate_fingerprint=?",
                (ctx.policy.name, fingerprint),
            )
            reference = dict(reference_row) if reference_row else None
            _upsert_seen_state(ctx.db, candidate, snap)

            if not _eligible(candidate):
                skipped_ineligible += 1
                continue
            score = int(snap["investigation_value"])
            if str(snap["analyst_decision"]) == "confirmed_by_analyst":
                score = max(score, 95)
            if mode == "silent" or score < minimum_score:
                skipped_policy += 1
                continue

            transition = _transition(reference, snap)
            if not transition:
                skipped_unchanged += 1
                continue
            event_id, was_deduplicated = _queue_transition(
                ctx.db,
                candidate,
                snap,
                transition,
                mode=mode,
            )
            if was_deduplicated:
                deduplicated += 1
            else:
                queued += 1
            transitions.append(
                {
                    "candidate_fingerprint": fingerprint,
                    "candidate_id": str(candidate.get("candidate_id") or ""),
                    "transition": transition,
                    "event_id": event_id,
                    "mode": mode,
                    "score": score,
                    "deduplicated": was_deduplicated,
                }
            )

    delivery = _deliver_pending(ctx)
    return {
        "status": "success" if analysis_id else "no_analysis",
        "analysis_id": analysis_id,
        "baseline": bool(baseline),
        "baseline_suppresses_findings": False,
        "candidates": len(candidates),
        "queued": queued,
        "deduplicated": deduplicated,
        "skipped_ineligible": skipped_ineligible,
        "skipped_unchanged": skipped_unchanged,
        "skipped_policy": skipped_policy,
        "delivery": delivery,
        "transitions": transitions,
    }


def install_finding_notification_pipeline() -> None:
    """Wrap the established report stage after Analysis without reordering Recon alerts."""

    import reporting

    if bool(getattr(reporting, "_FINDING_NOTIFICATION_PIPELINE_INSTALLED", False)):
        return
    original = reporting.stage_report

    def stage_report_with_finding_notifications(ctx: Any, baseline: bool) -> dict[str, Any]:
        result = original(ctx, baseline)
        try:
            finding_result = process_finding_notifications(
                ctx,
                result.get("analysis") if isinstance(result, Mapping) else {},
                baseline=baseline,
            )
        except Exception as exc:
            ctx.logger.warn(
                "Potential Finding notification pipeline failed without blocking report",
                target=ctx.policy.name,
                run_id=ctx.run_id,
                error=str(exc),
            )
            finding_result = {
                "status": "failed",
                "error": str(exc),
                "baseline": bool(baseline),
                "baseline_suppresses_findings": False,
                "queued": 0,
                "delivery": {"queued": 0, "delivered": 0, "error": str(exc)},
            }
        result = dict(result)
        result["finding_notifications"] = finding_result
        result["finding_notified"] = bool(
            int(finding_result.get("delivery", {}).get("delivered", 0) or 0)
        )
        return result

    stage_report_with_finding_notifications.__name__ = original.__name__
    stage_report_with_finding_notifications.__doc__ = original.__doc__
    reporting.stage_report = stage_report_with_finding_notifications
    reporting._FINDING_NOTIFICATION_PIPELINE_INSTALLED = True

    runtime = sys.modules.get("recon_monitor_core")
    if runtime is not None and hasattr(runtime, "stage_report"):
        runtime.stage_report = stage_report_with_finding_notifications
