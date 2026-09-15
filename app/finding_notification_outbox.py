from __future__ import annotations

"""Durable, retryable delivery outbox for Potential Finding notifications."""

import datetime as dt
import uuid
from collections import defaultdict
from typing import Any, Callable, Mapping

from core import APP_VERSION, Database, ReconError, safe_json_loads, utc_now
from notification_transports import deliver_notification_message


FINDING_NOTIFICATION_OUTBOX_VERSION = "1.0.0"
FINDING_NOTIFICATION_OUTBOX_SCHEMA_VERSION = 1
EVENT_TYPE = "potential_finding"
DELIVERABLE_MODES = {"immediate", "digest", "system_warning"}
DEFAULT_MAX_ATTEMPTS = 8
LEASE_MINUTES = 5
_BACKOFF_MINUTES = (1, 5, 15, 60, 180, 360, 720, 720)


def _parse_time(value: str) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        return dt.datetime.now(dt.timezone.utc)
    parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _next_attempt(now: str, attempt_count: int) -> str:
    index = max(0, min(len(_BACKOFF_MINUTES) - 1, int(attempt_count) - 1))
    return _iso(_parse_time(now) + dt.timedelta(minutes=_BACKOFF_MINUTES[index]))


def _lease_expiry(now: str) -> str:
    return _iso(_parse_time(now) + dt.timedelta(minutes=LEASE_MINUTES))


def _schema_ready(db: Database) -> bool:
    return db.one(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='finding_notification_outbox'"
    ) is not None


def ensure_finding_notification_outbox_schema(db: Database) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS finding_notification_outbox (
          event_id TEXT PRIMARY KEY,
          target TEXT NOT NULL,
          mode TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'queued',
          attempt_count INTEGER NOT NULL DEFAULT 0,
          max_attempts INTEGER NOT NULL DEFAULT 8,
          next_attempt_at TEXT NOT NULL,
          last_attempt_at TEXT NOT NULL DEFAULT '',
          last_error TEXT NOT NULL DEFAULT '',
          lease_id TEXT NOT NULL DEFAULT '',
          lease_expires_at TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          delivered_at TEXT NOT NULL DEFAULT '',
          FOREIGN KEY(event_id) REFERENCES notification_events(event_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_finding_notification_outbox_due
          ON finding_notification_outbox(status,next_attempt_at,target,mode);
        CREATE INDEX IF NOT EXISTS idx_finding_notification_outbox_lease
          ON finding_notification_outbox(status,lease_expires_at);
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('finding_notification_outbox_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(FINDING_NOTIFICATION_OUTBOX_SCHEMA_VERSION),),
    )

    rows = db.all(
        "SELECT event_id,target,mode,created_at FROM notification_events "
        "WHERE event_type=? AND status='queued' AND mode IN ('immediate','digest','system_warning')",
        (EVENT_TYPE,),
    )
    now = utc_now()
    for row in rows:
        created_at = str(row["created_at"] or now)
        db.execute(
            "INSERT OR IGNORE INTO finding_notification_outbox("
            "event_id,target,mode,status,attempt_count,max_attempts,next_attempt_at,created_at,updated_at"
            ") VALUES(?,?,?,'queued',0,?,?,?,?)",
            (
                str(row["event_id"]),
                str(row["target"]),
                str(row["mode"]),
                DEFAULT_MAX_ATTEMPTS,
                created_at,
                created_at,
                now,
            ),
        )


def enqueue_finding_notification_event(db: Database, event_id: str) -> dict[str, Any]:
    # process_finding_notifications installs the schema before entering Candidate
    # transactions. Avoid executescript inside an existing transaction.
    if not _schema_ready(db):
        ensure_finding_notification_outbox_schema(db)
    row = db.one("SELECT * FROM notification_events WHERE event_id=?", (str(event_id),))
    if row is None:
        raise ReconError("Notification event was not found")
    event = dict(row)
    if str(event.get("event_type") or "") != EVENT_TYPE:
        raise ReconError("Only Potential Finding events may enter the finding outbox")
    mode = str(event.get("mode") or "")
    if mode not in DELIVERABLE_MODES:
        return {"event_id": str(event_id), "queued": False, "status": "not_deliverable", "mode": mode}
    if str(event.get("status") or "") == "delivered":
        return {"event_id": str(event_id), "queued": False, "status": "delivered", "mode": mode}

    now = utc_now()
    db.execute(
        "INSERT OR IGNORE INTO finding_notification_outbox("
        "event_id,target,mode,status,attempt_count,max_attempts,next_attempt_at,created_at,updated_at"
        ") VALUES(?,?,?,'queued',0,?,?,?,?)",
        (
            str(event_id),
            str(event.get("target") or ""),
            mode,
            DEFAULT_MAX_ATTEMPTS,
            now,
            now,
            now,
        ),
    )
    outbox = db.one("SELECT * FROM finding_notification_outbox WHERE event_id=?", (str(event_id),))
    return {
        "event_id": str(event_id),
        "queued": bool(outbox and str(outbox["status"]) in {"queued", "retry_pending"}),
        "status": str(outbox["status"] if outbox else ""),
        "mode": mode,
    }


def outbox_summary(db: Database, *, target: str = "") -> dict[str, Any]:
    ensure_finding_notification_outbox_schema(db)
    params: tuple[Any, ...] = ()
    where = ""
    if target:
        where = " WHERE target=?"
        params = (target,)
    rows = db.all(
        "SELECT status,COUNT(*) AS n FROM finding_notification_outbox" + where + " GROUP BY status",
        params,
    )
    counts = {str(row["status"]): int(row["n"]) for row in rows}
    return {
        "queued": counts.get("queued", 0),
        "retry_pending": counts.get("retry_pending", 0),
        "delivering": counts.get("delivering", 0),
        "delivered": counts.get("delivered", 0),
        "failed": counts.get("failed", 0),
    }


def _message(target: str, mode: str, rows: list[dict[str, Any]]) -> str:
    lines = [
        f"🚨 Recon Monitor {APP_VERSION} — Potential Findings",
        f"Target: {target}",
        f"Mode: {mode}",
        "",
    ]
    for row in rows:
        payload = safe_json_loads(row.get("payload_json"), {}, expected_type=dict)
        lines.append(
            f"• [{row.get('score', 0)}] [{payload.get('transition', 'new')}] "
            f"{payload.get('bug_family') or 'candidate'} — "
            f"{payload.get('title') or 'Potential Finding'}"
            + (f" @ {payload.get('endpoint')}" if payload.get("endpoint") else "")
        )
    return "\n".join(lines)[:15000]


def _claim_due_rows(
    db: Database,
    *,
    now: str,
    target: str,
    mode: str,
    limit: int,
) -> tuple[str, list[dict[str, Any]]]:
    if mode and mode not in DELIVERABLE_MODES:
        raise ReconError("Delivery mode must be immediate, digest, or system_warning")
    lease_id = "FNW-" + uuid.uuid4().hex
    lease_expires = _lease_expiry(now)

    with db.transaction():
        # A worker crash before finalization makes the lease reclaimable.
        db.execute(
            "UPDATE finding_notification_outbox SET status='retry_pending',lease_id='',lease_expires_at='',updated_at=? "
            "WHERE status='delivering' AND lease_expires_at<>'' AND lease_expires_at<=?",
            (now, now),
        )
        clauses = [
            "o.status IN ('queued','retry_pending')",
            "o.next_attempt_at<=?",
            "e.status='queued'",
            "e.event_type=?",
        ]
        params: list[Any] = [now, EVENT_TYPE]
        if target:
            clauses.append("o.target=?")
            params.append(target)
        if mode:
            clauses.append("o.mode=?")
            params.append(mode)
        params.append(max(1, min(500, int(limit))))
        candidates = db.all(
            "SELECT o.event_id FROM finding_notification_outbox o "
            "JOIN notification_events e ON e.event_id=o.event_id WHERE "
            + " AND ".join(clauses)
            + " ORDER BY o.next_attempt_at,e.score DESC,e.created_at LIMIT ?",
            tuple(params),
        )
        for row in candidates:
            db.execute(
                "UPDATE finding_notification_outbox SET status='delivering',lease_id=?,lease_expires_at=?,updated_at=? "
                "WHERE event_id=? AND status IN ('queued','retry_pending') AND next_attempt_at<=?",
                (lease_id, lease_expires, now, str(row["event_id"]), now),
            )

    rows = [
        dict(row)
        for row in db.all(
            "SELECT o.*,e.score,e.payload_json,e.created_at AS event_created_at "
            "FROM finding_notification_outbox o JOIN notification_events e ON e.event_id=o.event_id "
            "WHERE o.status='delivering' AND o.lease_id=? AND e.status='queued' "
            "ORDER BY o.next_attempt_at,e.score DESC,e.created_at",
            (lease_id,),
        )
    ]
    return lease_id, rows


def deliver_finding_notification_outbox(
    *,
    config: Any,
    logger: Any,
    db: Database,
    target: str = "",
    mode: str = "",
    limit: int = 50,
    now: str = "",
    transport: Callable[[Any, Any, str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Deliver due outbox rows; delivery failure never mutates Candidate state."""

    ensure_finding_notification_outbox_schema(db)
    from change_alerts import suppress_finding_delivery
    suppress_finding_delivery(db)
    return {"version": FINDING_NOTIFICATION_OUTBOX_VERSION, "lease_id": "",
            "due": 0, "attempted": 0, "delivered": 0, "retry_pending": 0,
            "failed": 0, "batches": [], "disabled": True,
            "reason": "Only observed Recon changes generate outbound alerts."}


def requeue_failed_finding_notifications(
    db: Database,
    *,
    event_id: str = "",
    target: str = "",
) -> int:
    ensure_finding_notification_outbox_schema(db)
    clauses = ["status='failed'"]
    params: list[Any] = []
    if event_id:
        clauses.append("event_id=?")
        params.append(str(event_id))
    if target:
        clauses.append("target=?")
        params.append(str(target))
    rows = db.all(
        "SELECT event_id FROM finding_notification_outbox WHERE " + " AND ".join(clauses),
        tuple(params),
    )
    now = utc_now()
    with db.transaction():
        for row in rows:
            value = str(row["event_id"])
            db.execute(
                "UPDATE finding_notification_outbox SET status='retry_pending',attempt_count=0,"
                "next_attempt_at=?,last_attempt_at='',last_error='',lease_id='',lease_expires_at='',"
                "updated_at=?,delivered_at='' WHERE event_id=?",
                (now, now, value),
            )
            db.execute(
                "UPDATE notification_events SET status='queued',delivered_at=NULL WHERE event_id=? AND status='failed'",
                (value,),
            )
    return len(rows)
