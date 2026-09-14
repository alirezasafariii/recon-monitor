from __future__ import annotations

"""Durable, retryable delivery outbox for Recon Change Alerts."""

import datetime as dt
import hashlib
import uuid
from collections import defaultdict
from typing import Any, Callable, Mapping

from core import APP_VERSION, Database, ReconError, safe_json_loads, utc_now
from notification_transports import deliver_notification_message


RECON_ALERT_OUTBOX_VERSION = "1.0.0"
RECON_ALERT_OUTBOX_SCHEMA_VERSION = 1
DEFAULT_MAX_ATTEMPTS = 8
LEASE_MINUTES = 5
_BACKOFF_MINUTES = (1, 5, 15, 60, 180, 360, 720, 720)
_ACTIVE_STATUSES = {"queued", "retry_pending", "delivering", "failed"}


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


def _event_id(alert_id: int, run_id: str) -> str:
    raw = f"recon-alert\x00{int(alert_id)}\x00{str(run_id)}".encode("utf-8")
    return "RAO-" + hashlib.sha256(raw).hexdigest()[:32]


def _schema_ready(db: Database) -> bool:
    return db.one(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='recon_alert_notification_outbox'"
    ) is not None


def ensure_recon_alert_outbox_schema(db: Database) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS recon_alert_notification_outbox (
          event_id TEXT PRIMARY KEY,
          alert_id INTEGER NOT NULL,
          target TEXT NOT NULL,
          run_id TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'queued',
          attempt_count INTEGER NOT NULL DEFAULT 0,
          max_attempts INTEGER NOT NULL DEFAULT 8,
          next_attempt_at TEXT NOT NULL,
          last_attempt_at TEXT NOT NULL DEFAULT '',
          last_error TEXT NOT NULL DEFAULT '',
          lease_id TEXT NOT NULL DEFAULT '',
          lease_expires_at TEXT NOT NULL DEFAULT '',
          payload_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          delivered_at TEXT NOT NULL DEFAULT '',
          UNIQUE(alert_id, run_id),
          FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_recon_alert_outbox_due
          ON recon_alert_notification_outbox(status,next_attempt_at,target,run_id);
        CREATE INDEX IF NOT EXISTS idx_recon_alert_outbox_alert
          ON recon_alert_notification_outbox(alert_id,status);
        CREATE INDEX IF NOT EXISTS idx_recon_alert_outbox_lease
          ON recon_alert_notification_outbox(status,lease_expires_at);
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('recon_alert_notification_outbox_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(RECON_ALERT_OUTBOX_SCHEMA_VERSION),),
    )


def unresolved_recon_alert_delivery(db: Database, alert_id: int) -> dict[str, Any] | None:
    if not _schema_ready(db):
        return None
    row = db.one(
        "SELECT event_id,status,run_id,next_attempt_at,last_error FROM recon_alert_notification_outbox "
        "WHERE alert_id=? AND status IN ('queued','retry_pending','delivering','failed') "
        "ORDER BY created_at DESC LIMIT 1",
        (int(alert_id),),
    )
    return dict(row) if row else None


def enqueue_recon_alert_event(
    db: Database,
    *,
    alert_id: int,
    target: str,
    run_id: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not _schema_ready(db):
        ensure_recon_alert_outbox_schema(db)

    event_id = _event_id(int(alert_id), str(run_id))
    existing = db.one("SELECT * FROM recon_alert_notification_outbox WHERE event_id=?", (event_id,))
    if existing is not None:
        row = dict(existing)
        return {
            "event_id": event_id,
            "queued": str(row.get("status") or "") in {"queued", "retry_pending"},
            "status": str(row.get("status") or ""),
            "deduplicated": True,
        }

    unresolved = unresolved_recon_alert_delivery(db, int(alert_id))
    if unresolved is not None:
        return {
            "event_id": str(unresolved.get("event_id") or ""),
            "queued": False,
            "status": str(unresolved.get("status") or ""),
            "deduplicated": True,
            "blocked_by_unresolved": True,
        }

    now = utc_now()
    from core import json_dumps

    db.execute(
        "INSERT INTO recon_alert_notification_outbox("
        "event_id,alert_id,target,run_id,status,attempt_count,max_attempts,next_attempt_at,payload_json,created_at,updated_at"
        ") VALUES(?,?,?,?,'queued',0,?,?,?,?,?)",
        (
            event_id,
            int(alert_id),
            str(target),
            str(run_id),
            DEFAULT_MAX_ATTEMPTS,
            now,
            json_dumps(dict(payload)),
            now,
            now,
        ),
    )
    return {"event_id": event_id, "queued": True, "status": "queued", "deduplicated": False}


def recon_alert_outbox_summary(db: Database, *, target: str = "") -> dict[str, Any]:
    ensure_recon_alert_outbox_schema(db)
    where = ""
    params: tuple[Any, ...] = ()
    if target:
        where = " WHERE target=?"
        params = (str(target),)
    rows = db.all(
        "SELECT status,COUNT(*) AS n FROM recon_alert_notification_outbox" + where + " GROUP BY status",
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


def _message(target: str, run_id: str, rows: list[dict[str, Any]]) -> str:
    ordered = sorted(
        rows,
        key=lambda row: int(safe_json_loads(row.get("payload_json"), {}, expected_type=dict).get("risk_score", 0)),
        reverse=True,
    )
    lines = [
        f"🚨 Recon Monitor {APP_VERSION}",
        f"Target: {target}",
        f"Run: {run_id}",
        f"High-priority changes: {len(ordered)}",
        "",
    ]
    for row in ordered[:100]:
        payload = safe_json_loads(row.get("payload_json"), {}, expected_type=dict)
        lines.append(
            f"• [{payload.get('severity', 'INFO')}] "
            f"[{payload.get('change_class', payload.get('category', 'change'))}/"
            f"{payload.get('confirmation_state', 'confirmed')}] "
            f"{payload.get('title', 'Recon change')}: {payload.get('item', '')}"
        )
    if len(ordered) > 100:
        lines.append(f"• … and {len(ordered) - 100} more")
    return "\n".join(lines)[:15000]


def _claim_due_rows(
    db: Database,
    *,
    now: str,
    target: str,
    run_id: str,
    limit: int,
) -> tuple[str, list[dict[str, Any]]]:
    lease_id = "RAW-" + uuid.uuid4().hex
    lease_expires = _lease_expiry(now)
    with db.transaction():
        db.execute(
            "UPDATE recon_alert_notification_outbox SET status='retry_pending',lease_id='',lease_expires_at='',updated_at=? "
            "WHERE status='delivering' AND lease_expires_at<>'' AND lease_expires_at<=?",
            (now, now),
        )
        clauses = ["status IN ('queued','retry_pending')", "next_attempt_at<=?"]
        params: list[Any] = [now]
        if target:
            clauses.append("target=?")
            params.append(str(target))
        if run_id:
            clauses.append("run_id=?")
            params.append(str(run_id))
        params.append(max(1, min(500, int(limit))))
        candidates = db.all(
            "SELECT event_id FROM recon_alert_notification_outbox WHERE "
            + " AND ".join(clauses)
            + " ORDER BY next_attempt_at,created_at LIMIT ?",
            tuple(params),
        )
        for row in candidates:
            db.execute(
                "UPDATE recon_alert_notification_outbox SET status='delivering',lease_id=?,lease_expires_at=?,updated_at=? "
                "WHERE event_id=? AND status IN ('queued','retry_pending') AND next_attempt_at<=?",
                (lease_id, lease_expires, now, str(row["event_id"]), now),
            )
    rows = [
        dict(row)
        for row in db.all(
            "SELECT * FROM recon_alert_notification_outbox WHERE status='delivering' AND lease_id=? "
            "ORDER BY target,run_id,created_at",
            (lease_id,),
        )
    ]
    return lease_id, rows


def deliver_recon_alert_outbox(
    *,
    config: Any,
    logger: Any,
    db: Database,
    target: str = "",
    run_id: str = "",
    limit: int = 50,
    now: str = "",
    transport: Callable[[Any, Any, str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_recon_alert_outbox_schema(db)
    current = str(now or utc_now())
    lease_id, rows = _claim_due_rows(
        db,
        now=current,
        target=str(target or ""),
        run_id=str(run_id or ""),
        limit=limit,
    )
    if not rows:
        return {
            "version": RECON_ALERT_OUTBOX_VERSION,
            "lease_id": lease_id,
            "due": 0,
            "attempted": 0,
            "delivered": 0,
            "retry_pending": 0,
            "failed": 0,
            "batches": [],
        }

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(str(row.get("target") or ""), str(row.get("run_id") or ""))].append(row)

    send = transport or deliver_notification_message
    delivered_count = 0
    retry_count = 0
    failed_count = 0
    batches: list[dict[str, Any]] = []

    for (batch_target, batch_run_id), batch_rows in groups.items():
        try:
            result = dict(send(config, logger, _message(batch_target, batch_run_id, batch_rows)))
        except Exception as exc:
            result = {"delivered": False, "channel": "", "channels": [], "error": str(exc)}
        delivered = bool(result.get("delivered"))
        channel = str(result.get("channel") or "+".join(result.get("channels") or []) or "unknown")
        error = str(result.get("error") or "")

        with db.transaction():
            for row in batch_rows:
                event_id = str(row["event_id"])
                attempts = int(row.get("attempt_count") or 0) + 1
                max_attempts = max(1, int(row.get("max_attempts") or DEFAULT_MAX_ATTEMPTS))
                if delivered:
                    db.execute(
                        "UPDATE recon_alert_notification_outbox SET status='delivered',attempt_count=?,last_attempt_at=?,"
                        "last_error='',lease_id='',lease_expires_at='',updated_at=?,delivered_at=? "
                        "WHERE event_id=? AND status='delivering' AND lease_id=?",
                        (attempts, current, current, current, event_id, lease_id),
                    )
                    db.execute(
                        "UPDATE alerts SET last_notified=? WHERE id=?",
                        (current, int(row["alert_id"])),
                    )
                    delivered_count += 1
                    continue

                terminal = attempts >= max_attempts
                next_status = "failed" if terminal else "retry_pending"
                next_attempt = current if terminal else _next_attempt(current, attempts)
                db.execute(
                    "UPDATE recon_alert_notification_outbox SET status=?,attempt_count=?,next_attempt_at=?,last_attempt_at=?,"
                    "last_error=?,lease_id='',lease_expires_at='',updated_at=? "
                    "WHERE event_id=? AND status='delivering' AND lease_id=?",
                    (next_status, attempts, next_attempt, current, error, current, event_id, lease_id),
                )
                if terminal:
                    failed_count += 1
                else:
                    retry_count += 1

        batches.append(
            {
                "target": batch_target,
                "run_id": batch_run_id,
                "events": len(batch_rows),
                "delivered": delivered,
                "channel": channel,
                "error": error,
            }
        )

    return {
        "version": RECON_ALERT_OUTBOX_VERSION,
        "lease_id": lease_id,
        "due": len(rows),
        "attempted": len(rows),
        "delivered": delivered_count,
        "retry_pending": retry_count,
        "failed": failed_count,
        "batches": batches,
    }


def requeue_failed_recon_alerts(
    db: Database,
    *,
    event_id: str = "",
    target: str = "",
) -> int:
    ensure_recon_alert_outbox_schema(db)
    clauses = ["status='failed'"]
    params: list[Any] = []
    if event_id:
        clauses.append("event_id=?")
        params.append(str(event_id))
    if target:
        clauses.append("target=?")
        params.append(str(target))
    rows = db.all(
        "SELECT event_id FROM recon_alert_notification_outbox WHERE " + " AND ".join(clauses),
        tuple(params),
    )
    now = utc_now()
    with db.transaction():
        for row in rows:
            db.execute(
                "UPDATE recon_alert_notification_outbox SET status='retry_pending',attempt_count=0,next_attempt_at=?,"
                "last_attempt_at='',last_error='',lease_id='',lease_expires_at='',updated_at=?,delivered_at='' "
                "WHERE event_id=? AND status='failed'",
                (now, now, str(row["event_id"])),
            )
    return len(rows)
