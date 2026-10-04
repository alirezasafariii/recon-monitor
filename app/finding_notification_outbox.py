from __future__ import annotations

"""Durable, retryable delivery outbox for Potential Finding notifications."""

import datetime as dt
import uuid
from collections import defaultdict
from typing import Any, Callable, Iterator, Mapping

from core import APP_VERSION, Database, ReconError, safe_json_loads, utc_now
from notification_transports import deliver_notification_message


FINDING_NOTIFICATION_OUTBOX_VERSION = "1.0.1"
FINDING_NOTIFICATION_OUTBOX_SCHEMA_VERSION = 1
EVENT_TYPE = "potential_finding"
DELIVERABLE_MODES = {"immediate", "digest", "system_warning"}
DEFAULT_MAX_ATTEMPTS = 8
LEASE_MINUTES = 5
MESSAGE_CHAR_LIMIT = 15000
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


def _event_line(row: Mapping[str, Any]) -> str:
    payload = safe_json_loads(row.get("payload_json"), {}, expected_type=dict)
    return (
        f"• [{row.get('score', 0)}] [{payload.get('transition', 'new')}] "
        f"{payload.get('bug_family') or 'candidate'} — "
        f"{payload.get('title') or 'Potential Finding'}"
        + (f" @ {payload.get('endpoint')}" if payload.get("endpoint") else "")
    )


def _message(target: str, mode: str, rows: list[dict[str, Any]]) -> str:
    return "\n".join([
        f"🚨 Recon Monitor {APP_VERSION} — Potential Findings",
        f"Target: {target}",
        f"Mode: {mode}",
        "",
        *(_event_line(row) for row in rows),
    ])


def _message_batches(
    target: str, mode: str, rows: list[dict[str, Any]],
) -> Iterator[tuple[list[dict[str, Any]], list[str]]]:
    """Keep whole events together; an oversized event owns all of its parts."""
    header_size = len(_message(target, mode, []))
    batch: list[dict[str, Any]] = []
    size = header_size
    for row in rows:
        line_size = 1 + len(_event_line(row))
        if batch and size + line_size > MESSAGE_CHAR_LIMIT:
            yield batch, [_message(target, mode, batch)]
            batch, size = [], header_size
        if header_size + line_size > MESSAGE_CHAR_LIMIT:
            message = _message(target, mode, [row])
            yield [row], [message[offset:offset + MESSAGE_CHAR_LIMIT]
                          for offset in range(0, len(message), MESSAGE_CHAR_LIMIT)]
            continue
        batch.append(row)
        size += line_size
    if batch:
        yield batch, [_message(target, mode, batch)]


def _send_message_parts(
    config: Any, logger: Any, db: Database, lease_id: str, rows: list[dict[str, Any]],
    messages: list[str], send: Callable[[Any, Any, str], Mapping[str, Any]], now: str,
) -> dict[str, Any]:
    common_channels: set[str] | None = None
    errors: list[str] = []
    sent_parts = 0
    for message in messages:
        current = str(now or utc_now())
        with db.transaction():
            # Bounded messages may require several transport calls. Keep the
            # remaining claimed events leased while earlier parts are sent.
            db.execute("UPDATE finding_notification_outbox SET lease_expires_at=?,updated_at=? "
                       "WHERE status='delivering' AND lease_id=?", (_lease_expiry(current), current, lease_id))
            owned = all(db.one("SELECT 1 FROM finding_notification_outbox o JOIN notification_events e "
                               "ON e.event_id=o.event_id WHERE o.event_id=? AND o.status='delivering' "
                               "AND o.lease_id=? AND e.status='queued'", (row["event_id"], lease_id)) for row in rows)
        if not owned:
            return {"delivered": False, "channel": "", "error": "notification_batch_lease_lost", "sent_parts": sent_parts}
        try:
            result = dict(send(config, logger, message))
        except Exception as exc:
            result = {"delivered": False, "error": str(exc)}
        sent_parts += 1
        error = str(result.get("error") or "")
        if error:
            errors.append(error)
        if not result.get("delivered"):
            return {**result, "delivered": False, "error": error or "notification_delivery_failed", "sent_parts": sent_parts}
        raw_channels = result.get("channels")
        channels = {str(value) for value in raw_channels if value} if isinstance(raw_channels, (list, tuple, set)) else set()
        channels = channels or set(str(result.get("channel") or "unknown").split("+"))
        common_channels = channels if common_channels is None else common_channels & channels
        if not common_channels:
            return {"delivered": False, "channel": "", "error": "notification_parts_have_no_complete_channel", "sent_parts": sent_parts}
    if len(messages) == 1:
        return {**result, "delivered": True, "sent_parts": sent_parts}
    channel = "+".join(sorted(common_channels or {"unknown"}))
    return {"delivered": True, "channel": channel, "error": "; ".join(errors), "sent_parts": sent_parts}


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
    current = str(now or utc_now())
    lease_id, rows = _claim_due_rows(
        db,
        now=current,
        target=str(target or ""),
        mode=str(mode or ""),
        limit=limit,
    )
    if not rows:
        return {
            "version": FINDING_NOTIFICATION_OUTBOX_VERSION,
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
        groups[(str(row.get("target") or ""), str(row.get("mode") or ""))].append(row)

    send = transport or deliver_notification_message
    delivered_count = 0
    retry_count = 0
    failed_count = 0
    batches: list[dict[str, Any]] = []

    for (batch_target, batch_mode), group_rows in groups.items():
        for batch_rows, messages in _message_batches(batch_target, batch_mode, group_rows):
            result = _send_message_parts(config, logger, db, lease_id, batch_rows, messages, send, str(now or ""))
            current = str(now or utc_now())
            delivered = bool(result.get("delivered"))
            channel = str(result.get("channel") or "+".join(result.get("channels") or []) or "unknown")
            error = str(result.get("error") or "")

            with db.transaction():
                for row in batch_rows:
                    event_id = str(row["event_id"])
                    attempts = int(row.get("attempt_count") or 0) + 1
                    max_attempts = max(1, int(row.get("max_attempts") or DEFAULT_MAX_ATTEMPTS))
                    if delivered:
                        cursor = db.execute(
                            "UPDATE finding_notification_outbox SET status='delivered',attempt_count=?,"
                            "last_attempt_at=?,last_error='',lease_id='',lease_expires_at='',updated_at=?,delivered_at=? "
                            "WHERE event_id=? AND status='delivering' AND lease_id=?",
                            (attempts, current, current, current, event_id, lease_id),
                        )
                        if cursor.rowcount != 1:
                            # Another worker reclaimed or finalized this event after
                            # transport returned. The stale worker must not mutate
                            # domain delivery state without owning the lease.
                            continue
                        db.execute(
                            "UPDATE notification_events SET status='delivered',delivered_at=? "
                            "WHERE event_id=? AND status='queued'",
                            (current, event_id),
                        )
                        db.execute(
                            "INSERT INTO notification_deliveries(event_id,channel,status,error,created_at) "
                            "VALUES(?,?,'delivered','',?)",
                            (event_id, channel, current),
                        )
                        delivered_count += 1
                        continue

                    terminal = attempts >= max_attempts
                    next_attempt = current if terminal else _next_attempt(current, attempts)
                    next_status = "failed" if terminal else "retry_pending"
                    cursor = db.execute(
                        "UPDATE finding_notification_outbox SET status=?,attempt_count=?,next_attempt_at=?,"
                        "last_attempt_at=?,last_error=?,lease_id='',lease_expires_at='',updated_at=? "
                        "WHERE event_id=? AND status='delivering' AND lease_id=?",
                        (next_status, attempts, next_attempt, current, error, current, event_id, lease_id),
                    )
                    if cursor.rowcount != 1:
                        # Lease ownership is the authority to finalize an attempt.
                        # A stale worker may have contacted the transport, but it
                        # cannot record delivery state after its lease was replaced.
                        continue
                    if terminal:
                        db.execute(
                            "UPDATE notification_events SET status='failed' WHERE event_id=? AND status='queued'",
                            (event_id,),
                        )
                        failed_count += 1
                    else:
                        retry_count += 1
                    db.execute(
                        "INSERT INTO notification_deliveries(event_id,channel,status,error,created_at) "
                        "VALUES(?,?,'failed',?,?)",
                        (event_id, channel, error, current),
                    )

            batches.append(
                {
                    "target": batch_target,
                    "mode": batch_mode,
                    "events": len(batch_rows),
                    "event_ids": [str(row["event_id"]) for row in batch_rows],
                    "message_parts": len(messages),
                    "sent_parts": int(result.get("sent_parts") or 0),
                    "message_lengths": [len(message) for message in messages],
                    "delivered": delivered,
                    "channel": channel,
                    "error": error,
                }
            )

    return {
        "version": FINDING_NOTIFICATION_OUTBOX_VERSION,
        "lease_id": lease_id,
        "due": len(rows),
        "attempted": len(rows),
        "delivered": delivered_count,
        "retry_pending": retry_count,
        "failed": failed_count,
        "batches": batches,
    }


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
