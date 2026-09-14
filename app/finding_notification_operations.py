from __future__ import annotations

"""Operational scheduler, diagnostics, and dead-letter controls for finding notifications."""

import datetime as dt
import time
import uuid
from typing import Any, Callable, Mapping

from core import Database, ReconError, parse_int, utc_now
from finding_notification_outbox import (
    DELIVERABLE_MODES,
    deliver_finding_notification_outbox,
    ensure_finding_notification_outbox_schema,
    requeue_failed_finding_notifications,
)


FINDING_NOTIFICATION_OPERATIONS_VERSION = "1.0.0"
FINDING_NOTIFICATION_OPERATIONS_SCHEMA_VERSION = 1
DEFAULT_INTERVAL_SECONDS = 60
DEFAULT_BATCH_LIMIT = 100
MIN_INTERVAL_SECONDS = 60
MAX_INTERVAL_SECONDS = 3600


def _parse_time(value: str) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _age_seconds(value: str, *, now: str = "") -> int:
    then = _parse_time(value)
    current = _parse_time(now or utc_now())
    if then is None or current is None:
        return 0
    return max(0, int((current - then).total_seconds()))


def ensure_finding_notification_operations_schema(db: Database) -> None:
    ensure_finding_notification_outbox_schema(db)
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS finding_notification_worker_policy (
          singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          enabled INTEGER NOT NULL DEFAULT 1,
          interval_seconds INTEGER NOT NULL DEFAULT 60,
          batch_limit INTEGER NOT NULL DEFAULT 100,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS finding_notification_worker_runs (
          worker_run_id TEXT PRIMARY KEY,
          trigger TEXT NOT NULL,
          status TEXT NOT NULL,
          due_before INTEGER NOT NULL DEFAULT 0,
          attempted INTEGER NOT NULL DEFAULT 0,
          delivered INTEGER NOT NULL DEFAULT 0,
          retry_pending INTEGER NOT NULL DEFAULT 0,
          failed INTEGER NOT NULL DEFAULT 0,
          error TEXT NOT NULL DEFAULT '',
          started_at TEXT NOT NULL,
          finished_at TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_finding_notification_worker_runs_finished
          ON finding_notification_worker_runs(finished_at);
        CREATE TABLE IF NOT EXISTS finding_notification_dead_letters (
          event_id TEXT PRIMARY KEY,
          target TEXT NOT NULL,
          mode TEXT NOT NULL,
          attempt_count INTEGER NOT NULL,
          last_error TEXT NOT NULL DEFAULT '',
          dead_lettered_at TEXT NOT NULL,
          resolved_at TEXT NOT NULL DEFAULT '',
          resolution TEXT NOT NULL DEFAULT '',
          FOREIGN KEY(event_id) REFERENCES notification_events(event_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_finding_notification_dead_letters_open
          ON finding_notification_dead_letters(resolved_at,dead_lettered_at);
        """
    )
    now = utc_now()
    db.execute(
        "INSERT OR IGNORE INTO finding_notification_worker_policy("
        "singleton,enabled,interval_seconds,batch_limit,updated_at) VALUES(1,1,?,?,?)",
        (DEFAULT_INTERVAL_SECONDS, DEFAULT_BATCH_LIMIT, now),
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('finding_notification_operations_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(FINDING_NOTIFICATION_OPERATIONS_SCHEMA_VERSION),),
    )
    _sync_dead_letters(db)


def configure_finding_notification_worker(
    db: Database,
    *,
    enabled: bool | None = None,
    interval_seconds: int | None = None,
    batch_limit: int | None = None,
) -> dict[str, Any]:
    ensure_finding_notification_operations_schema(db)
    current = dict(db.one("SELECT * FROM finding_notification_worker_policy WHERE singleton=1"))
    new_enabled = int(bool(enabled)) if enabled is not None else int(current["enabled"])
    new_interval = (
        max(MIN_INTERVAL_SECONDS, min(MAX_INTERVAL_SECONDS, int(interval_seconds)))
        if interval_seconds is not None
        else int(current["interval_seconds"])
    )
    new_limit = (
        max(1, min(500, int(batch_limit)))
        if batch_limit is not None
        else int(current["batch_limit"])
    )
    now = utc_now()
    db.execute(
        "UPDATE finding_notification_worker_policy SET enabled=?,interval_seconds=?,batch_limit=?,updated_at=? "
        "WHERE singleton=1",
        (new_enabled, new_interval, new_limit, now),
    )
    return worker_policy(db)


def worker_policy(db: Database) -> dict[str, Any]:
    ensure_finding_notification_operations_schema(db)
    row = db.one("SELECT * FROM finding_notification_worker_policy WHERE singleton=1")
    return {
        "enabled": bool(int(row["enabled"])),
        "interval_seconds": int(row["interval_seconds"]),
        "batch_limit": int(row["batch_limit"]),
        "updated_at": str(row["updated_at"]),
    }


def _sync_dead_letters(db: Database) -> int:
    if db.one(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='finding_notification_dead_letters'"
    ) is None:
        return 0
    rows = db.all(
        "SELECT event_id,target,mode,attempt_count,last_error,updated_at FROM finding_notification_outbox "
        "WHERE status='failed'"
    )
    inserted = 0
    for row in rows:
        existing = db.one(
            "SELECT resolved_at FROM finding_notification_dead_letters WHERE event_id=?",
            (str(row["event_id"]),),
        )
        if existing is None:
            inserted += 1
        db.execute(
            "INSERT INTO finding_notification_dead_letters("
            "event_id,target,mode,attempt_count,last_error,dead_lettered_at,resolved_at,resolution"
            ") VALUES(?,?,?,?,?,?,'','') "
            "ON CONFLICT(event_id) DO UPDATE SET "
            "attempt_count=excluded.attempt_count,last_error=excluded.last_error,"
            "dead_lettered_at=CASE WHEN finding_notification_dead_letters.resolved_at<>'' "
            "THEN excluded.dead_lettered_at ELSE finding_notification_dead_letters.dead_lettered_at END,"
            "resolved_at='',resolution=''",
            (
                str(row["event_id"]),
                str(row["target"]),
                str(row["mode"]),
                int(row["attempt_count"]),
                str(row["last_error"] or ""),
                str(row["updated_at"] or utc_now()),
            ),
        )
    return inserted


def finding_notification_diagnostics(db: Database, *, now: str = "") -> dict[str, Any]:
    ensure_finding_notification_operations_schema(db)
    current = str(now or utc_now())
    counts = {
        str(row["status"]): int(row["n"])
        for row in db.all(
            "SELECT status,COUNT(*) AS n FROM finding_notification_outbox GROUP BY status"
        )
    }
    due = db.one(
        "SELECT COUNT(*) AS n FROM finding_notification_outbox o "
        "JOIN notification_events e ON e.event_id=o.event_id "
        "WHERE o.status IN ('queued','retry_pending') AND o.next_attempt_at<=? AND e.status='queued'",
        (current,),
    )
    oldest = db.one(
        "SELECT MIN(created_at) AS oldest FROM finding_notification_outbox "
        "WHERE status IN ('queued','retry_pending','delivering')"
    )
    open_dead = db.one(
        "SELECT COUNT(*) AS n FROM finding_notification_dead_letters WHERE resolved_at=''"
    )
    last_run = db.one(
        "SELECT * FROM finding_notification_worker_runs ORDER BY started_at DESC LIMIT 1"
    )
    policy = worker_policy(db)
    return {
        "version": FINDING_NOTIFICATION_OPERATIONS_VERSION,
        "generated_at": current,
        "policy": policy,
        "queue_depth": counts.get("queued", 0)
        + counts.get("retry_pending", 0)
        + counts.get("delivering", 0),
        "due_now": int(due["n"] if due else 0),
        "queued": counts.get("queued", 0),
        "retry_pending": counts.get("retry_pending", 0),
        "delivering": counts.get("delivering", 0),
        "delivered": counts.get("delivered", 0),
        "failed": counts.get("failed", 0),
        "dead_letter_open": int(open_dead["n"] if open_dead else 0),
        "oldest_pending_at": str((oldest or {}).get("oldest") or ""),
        "oldest_pending_age_seconds": _age_seconds(
            str((oldest or {}).get("oldest") or ""), now=current
        ),
        "last_worker_run": dict(last_run) if last_run else {},
    }


def list_dead_letters(db: Database, *, target: str = "", limit: int = 100) -> list[dict[str, Any]]:
    ensure_finding_notification_operations_schema(db)
    clauses = ["resolved_at='' "]
    params: list[Any] = []
    if target:
        clauses.append("target=?")
        params.append(str(target))
    params.append(max(1, min(500, int(limit))))
    return [
        dict(row)
        for row in db.all(
            "SELECT * FROM finding_notification_dead_letters WHERE "
            + " AND ".join(clauses)
            + " ORDER BY dead_lettered_at DESC LIMIT ?",
            tuple(params),
        )
    ]


def retry_dead_letters(
    db: Database,
    *,
    event_id: str = "",
    target: str = "",
    resolution: str = "operator_retry",
) -> int:
    ensure_finding_notification_operations_schema(db)
    selected = list_dead_letters(db, target=target, limit=500)
    if event_id:
        selected = [row for row in selected if str(row["event_id"]) == str(event_id)]
    if not selected:
        return 0
    count = 0
    now = utc_now()
    with db.transaction():
        for row in selected:
            value = str(row["event_id"])
            requeued = requeue_failed_finding_notifications(db, event_id=value)
            if not requeued:
                continue
            db.execute(
                "UPDATE finding_notification_dead_letters SET resolved_at=?,resolution=? WHERE event_id=?",
                (now, str(resolution or "operator_retry"), value),
            )
            count += 1
    return count


def _last_completed_run(db: Database) -> dict[str, Any]:
    row = db.one(
        "SELECT * FROM finding_notification_worker_runs WHERE finished_at<>'' "
        "ORDER BY finished_at DESC LIMIT 1"
    )
    return dict(row) if row else {}


def worker_due(db: Database, *, now: str = "") -> dict[str, Any]:
    ensure_finding_notification_operations_schema(db)
    current_text = str(now or utc_now())
    current = _parse_time(current_text)
    policy = worker_policy(db)
    last = _last_completed_run(db)
    if not policy["enabled"]:
        return {"due": False, "reason": "disabled", "next_due_at": "", "policy": policy}
    if not last:
        return {"due": True, "reason": "first_run", "next_due_at": current_text, "policy": policy}
    finished = _parse_time(str(last.get("finished_at") or ""))
    if current is None or finished is None:
        return {"due": True, "reason": "invalid_last_run_time", "next_due_at": current_text, "policy": policy}
    next_due = finished + dt.timedelta(seconds=int(policy["interval_seconds"]))
    return {
        "due": current >= next_due,
        "reason": "interval_elapsed" if current >= next_due else "interval_pending",
        "next_due_at": next_due.isoformat().replace("+00:00", "Z"),
        "policy": policy,
    }


def run_finding_notification_worker(
    *,
    config: Any,
    logger: Any,
    db: Database,
    trigger: str = "scheduler",
    force: bool = False,
    target: str = "",
    mode: str = "",
    limit: int | None = None,
    now: str = "",
    transport: Callable[[Any, Any, str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_finding_notification_operations_schema(db)
    current = str(now or utc_now())
    due_state = worker_due(db, now=current)
    if not force and not bool(due_state["due"]):
        return {
            "version": FINDING_NOTIFICATION_OPERATIONS_VERSION,
            "status": "skipped",
            "reason": str(due_state["reason"]),
            "next_due_at": str(due_state["next_due_at"]),
            "diagnostics": finding_notification_diagnostics(db, now=current),
        }

    policy = due_state["policy"]
    batch_limit = max(1, min(500, int(limit or policy["batch_limit"])))
    before = finding_notification_diagnostics(db, now=current)
    run_id = "FNWR-" + uuid.uuid4().hex[:16]
    db.execute(
        "INSERT INTO finding_notification_worker_runs("
        "worker_run_id,trigger,status,due_before,started_at) VALUES(?,?,'running',?,?)",
        (run_id, str(trigger or "scheduler"), int(before["due_now"]), current),
    )
    try:
        result = deliver_finding_notification_outbox(
            config=config,
            logger=logger,
            db=db,
            target=str(target or ""),
            mode=str(mode or ""),
            limit=batch_limit,
            now=current,
            transport=transport,
        )
        _sync_dead_letters(db)
        finished = utc_now() if not now else current
        db.execute(
            "UPDATE finding_notification_worker_runs SET status='success',attempted=?,delivered=?,"
            "retry_pending=?,failed=?,finished_at=? WHERE worker_run_id=?",
            (
                int(result.get("attempted", 0) or 0),
                int(result.get("delivered", 0) or 0),
                int(result.get("retry_pending", 0) or 0),
                int(result.get("failed", 0) or 0),
                finished,
                run_id,
            ),
        )
        return {
            "version": FINDING_NOTIFICATION_OPERATIONS_VERSION,
            "status": "success",
            "worker_run_id": run_id,
            "delivery": result,
            "diagnostics": finding_notification_diagnostics(db, now=finished),
        }
    except Exception as exc:
        finished = utc_now() if not now else current
        db.execute(
            "UPDATE finding_notification_worker_runs SET status='failed',error=?,finished_at=? "
            "WHERE worker_run_id=?",
            (str(exc), finished, run_id),
        )
        _sync_dead_letters(db)
        raise


def drain_finding_notification_outbox(
    *,
    config: Any,
    logger: Any,
    db: Database,
    max_batches: int = 20,
    batch_limit: int = 100,
    transport: Callable[[Any, Any, str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_finding_notification_operations_schema(db)
    batches = 0
    attempted = 0
    delivered = 0
    failed = 0
    while batches < max(1, min(100, int(max_batches))):
        result = run_finding_notification_worker(
            config=config,
            logger=logger,
            db=db,
            trigger="drain",
            force=True,
            limit=batch_limit,
            transport=transport,
        )
        delivery = dict(result.get("delivery") or {})
        current_attempted = int(delivery.get("attempted", 0) or 0)
        attempted += current_attempted
        delivered += int(delivery.get("delivered", 0) or 0)
        failed += int(delivery.get("failed", 0) or 0)
        batches += 1
        if current_attempted == 0:
            break
    return {
        "version": FINDING_NOTIFICATION_OPERATIONS_VERSION,
        "status": "success",
        "batches": batches,
        "attempted": attempted,
        "delivered": delivered,
        "failed": failed,
        "diagnostics": finding_notification_diagnostics(db),
    }


def watch_finding_notification_worker(
    *,
    config: Any,
    logger: Any,
    db: Database,
    stop: Callable[[], bool] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    max_cycles: int = 0,
) -> dict[str, Any]:
    """Run the queue-centric scheduler loop. ``max_cycles`` is mainly for deterministic tests."""

    ensure_finding_notification_operations_schema(db)
    cycles = 0
    executed = 0
    while True:
        if stop and stop():
            break
        policy = worker_policy(db)
        result = run_finding_notification_worker(
            config=config,
            logger=logger,
            db=db,
            trigger="watch",
            force=False,
        )
        cycles += 1
        if str(result.get("status")) == "success":
            executed += 1
        if max_cycles and cycles >= max_cycles:
            break
        sleep(max(MIN_INTERVAL_SECONDS, int(policy["interval_seconds"])))
    return {"status": "stopped", "cycles": cycles, "executed": executed}
