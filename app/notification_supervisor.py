from __future__ import annotations

"""Single-instance runtime supervisor for independent notification workers."""

import datetime as dt
import time
import uuid
from typing import Any, Callable

from core import Database, utc_now
from finding_notification_operations import finding_notification_diagnostics, run_finding_notification_worker, worker_due
from notification_delivery_slo import evaluate_notification_delivery_slo
from recon_alert_operations import recon_alert_diagnostics, recon_alert_worker_due, run_recon_alert_worker

NOTIFICATION_SUPERVISOR_VERSION = "1.0.0"
NOTIFICATION_SUPERVISOR_SCHEMA_VERSION = 1
DEFAULT_POLL_SECONDS = 15
DEFAULT_LEASE_SECONDS = 900
MIN_POLL_SECONDS = 5
MAX_POLL_SECONDS = 300
MIN_LEASE_SECONDS = 60
MAX_LEASE_SECONDS = 3600


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


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _future(now: str, seconds: int) -> str:
    current = _parse_time(now) or dt.datetime.now(dt.timezone.utc)
    return _iso(current + dt.timedelta(seconds=max(1, int(seconds))))


def _age_seconds(value: str, *, now: str) -> int:
    then = _parse_time(value)
    current = _parse_time(now)
    if then is None or current is None:
        return 0
    return max(0, int((current - then).total_seconds()))


def ensure_notification_supervisor_schema(db: Database) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS notification_supervisor_state (
          singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          enabled INTEGER NOT NULL DEFAULT 1,
          poll_seconds INTEGER NOT NULL DEFAULT 15,
          lease_seconds INTEGER NOT NULL DEFAULT 900,
          lease_owner TEXT NOT NULL DEFAULT '',
          lease_expires_at TEXT NOT NULL DEFAULT '',
          heartbeat_at TEXT NOT NULL DEFAULT '',
          last_started_at TEXT NOT NULL DEFAULT '',
          last_finished_at TEXT NOT NULL DEFAULT '',
          last_success_at TEXT NOT NULL DEFAULT '',
          last_error_at TEXT NOT NULL DEFAULT '',
          last_status TEXT NOT NULL DEFAULT 'never_run',
          last_error TEXT NOT NULL DEFAULT '',
          cycle_count INTEGER NOT NULL DEFAULT 0,
          worker_success_count INTEGER NOT NULL DEFAULT 0,
          worker_failure_count INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notification_supervisor_runs (
          supervisor_run_id TEXT PRIMARY KEY,
          owner_id TEXT NOT NULL,
          trigger TEXT NOT NULL,
          status TEXT NOT NULL,
          finding_status TEXT NOT NULL DEFAULT '',
          recon_alert_status TEXT NOT NULL DEFAULT '',
          error TEXT NOT NULL DEFAULT '',
          started_at TEXT NOT NULL,
          finished_at TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_notification_supervisor_runs_started
          ON notification_supervisor_runs(started_at);
        """
    )
    now = utc_now()
    db.execute(
        "INSERT OR IGNORE INTO notification_supervisor_state("
        "singleton,enabled,poll_seconds,lease_seconds,updated_at) VALUES(1,1,?,?,?)",
        (DEFAULT_POLL_SECONDS, DEFAULT_LEASE_SECONDS, now),
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('notification_supervisor_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(NOTIFICATION_SUPERVISOR_SCHEMA_VERSION),),
    )


def configure_notification_supervisor(
    db: Database,
    *,
    enabled: bool | None = None,
    poll_seconds: int | None = None,
    lease_seconds: int | None = None,
) -> dict[str, Any]:
    ensure_notification_supervisor_schema(db)
    row = dict(db.one("SELECT * FROM notification_supervisor_state WHERE singleton=1"))
    value_enabled = int(bool(enabled)) if enabled is not None else int(row["enabled"])
    value_poll = (
        max(MIN_POLL_SECONDS, min(MAX_POLL_SECONDS, int(poll_seconds)))
        if poll_seconds is not None else int(row["poll_seconds"])
    )
    value_lease = (
        max(MIN_LEASE_SECONDS, min(MAX_LEASE_SECONDS, int(lease_seconds)))
        if lease_seconds is not None else int(row["lease_seconds"])
    )
    db.execute(
        "UPDATE notification_supervisor_state SET enabled=?,poll_seconds=?,lease_seconds=?,updated_at=? "
        "WHERE singleton=1",
        (value_enabled, value_poll, value_lease, utc_now()),
    )
    return notification_supervisor_status(db)


def acquire_notification_supervisor_lease(
    db: Database,
    *,
    owner_id: str,
    now: str = "",
    lease_seconds: int | None = None,
) -> bool:
    ensure_notification_supervisor_schema(db)
    current = str(now or utc_now())
    row = db.one("SELECT lease_seconds FROM notification_supervisor_state WHERE singleton=1")
    seconds = max(MIN_LEASE_SECONDS, min(MAX_LEASE_SECONDS, int(lease_seconds or row["lease_seconds"])))
    expires = _future(current, seconds)
    cursor = db.execute(
        "UPDATE notification_supervisor_state SET lease_owner=?,lease_expires_at=?,heartbeat_at=?,updated_at=? "
        "WHERE singleton=1 AND (lease_owner='' OR lease_expires_at='' OR lease_expires_at<=? OR lease_owner=?)",
        (str(owner_id), expires, current, current, current, str(owner_id)),
    )
    return int(cursor.rowcount or 0) == 1


def heartbeat_notification_supervisor(
    db: Database,
    *,
    owner_id: str,
    now: str = "",
    lease_seconds: int | None = None,
) -> bool:
    ensure_notification_supervisor_schema(db)
    current = str(now or utc_now())
    row = db.one("SELECT lease_seconds FROM notification_supervisor_state WHERE singleton=1")
    seconds = max(MIN_LEASE_SECONDS, min(MAX_LEASE_SECONDS, int(lease_seconds or row["lease_seconds"])))
    cursor = db.execute(
        "UPDATE notification_supervisor_state SET heartbeat_at=?,lease_expires_at=?,updated_at=? "
        "WHERE singleton=1 AND lease_owner=?",
        (current, _future(current, seconds), current, str(owner_id)),
    )
    return int(cursor.rowcount or 0) == 1


def release_notification_supervisor_lease(db: Database, *, owner_id: str, now: str = "") -> bool:
    ensure_notification_supervisor_schema(db)
    current = str(now or utc_now())
    cursor = db.execute(
        "UPDATE notification_supervisor_state SET lease_owner='',lease_expires_at='',updated_at=? "
        "WHERE singleton=1 AND lease_owner=?",
        (current, str(owner_id)),
    )
    return int(cursor.rowcount or 0) == 1


def _due_snapshot(db: Database, *, now: str) -> dict[str, Any]:
    return {
        "finding": worker_due(db, now=now),
        "recon_alert": recon_alert_worker_due(db, now=now),
    }


def notification_supervisor_status(db: Database, *, now: str = "") -> dict[str, Any]:
    ensure_notification_supervisor_schema(db)
    current = str(now or utc_now())
    row = dict(db.one("SELECT * FROM notification_supervisor_state WHERE singleton=1"))
    lease_expiry = _parse_time(str(row.get("lease_expires_at") or ""))
    current_dt = _parse_time(current)
    lease_active = bool(str(row.get("lease_owner") or "")) and lease_expiry is not None and current_dt is not None and lease_expiry > current_dt
    due = _due_snapshot(db, now=current)
    next_values = [str(item.get("next_due_at") or "") for item in due.values() if str(item.get("next_due_at") or "")]
    state = "disabled" if not bool(int(row["enabled"])) else "running" if lease_active else "degraded" if str(row.get("last_status")) in {"failed", "partial_failure"} else "idle"
    last_run = db.one("SELECT * FROM notification_supervisor_runs ORDER BY started_at DESC LIMIT 1")
    return {
        "version": NOTIFICATION_SUPERVISOR_VERSION,
        "generated_at": current,
        "state": state,
        "enabled": bool(int(row["enabled"])),
        "poll_seconds": int(row["poll_seconds"]),
        "lease_seconds": int(row["lease_seconds"]),
        "lease_owner": str(row.get("lease_owner") or "") if lease_active else "",
        "lease_active": lease_active,
        "lease_expires_at": str(row.get("lease_expires_at") or "") if lease_active else "",
        "heartbeat_at": str(row.get("heartbeat_at") or ""),
        "heartbeat_age_seconds": _age_seconds(str(row.get("heartbeat_at") or ""), now=current),
        "last_started_at": str(row.get("last_started_at") or ""),
        "last_finished_at": str(row.get("last_finished_at") or ""),
        "last_success_at": str(row.get("last_success_at") or ""),
        "last_error_at": str(row.get("last_error_at") or ""),
        "last_status": str(row.get("last_status") or "never_run"),
        "last_error": str(row.get("last_error") or ""),
        "cycle_count": int(row.get("cycle_count") or 0),
        "worker_success_count": int(row.get("worker_success_count") or 0),
        "worker_failure_count": int(row.get("worker_failure_count") or 0),
        "next_due_at": min(next_values) if next_values else "",
        "workers_due": due,
        "last_run": dict(last_run) if last_run else {},
    }


def _execute_owned_cycle(
    *,
    config: Any,
    logger: Any,
    db: Database,
    owner_id: str,
    trigger: str,
    now: str,
    fixed_clock: bool = False,
) -> dict[str, Any]:
    state = db.one("SELECT enabled FROM notification_supervisor_state WHERE singleton=1")
    if not bool(int(state["enabled"])):
        return {"status": "skipped", "reason": "disabled", "workers": {}}
    run_id = "NSUP-" + uuid.uuid4().hex[:16]
    db.execute(
        "INSERT INTO notification_supervisor_runs(supervisor_run_id,owner_id,trigger,status,started_at) "
        "VALUES(?,?,?,'running',?)",
        (run_id, str(owner_id), str(trigger or "supervisor"), now),
    )
    db.execute(
        "UPDATE notification_supervisor_state SET last_started_at=?,last_status='running',last_error='',updated_at=? WHERE singleton=1",
        (now, now),
    )
    results: dict[str, Any] = {}
    failures: list[str] = []
    success_count = 0
    for name, runner in (
        ("finding", run_finding_notification_worker),
        ("recon_alert", run_recon_alert_worker),
    ):
        if not heartbeat_notification_supervisor(db, owner_id=owner_id, now=now if fixed_clock else utc_now()):
            raise RuntimeError("Notification supervisor lease lost")
        try:
            result = runner(config=config, logger=logger, db=db, trigger="supervisor", force=False, now=now)
            results[name] = result
            if str(result.get("status") or "") == "success":
                success_count += 1
        except Exception as exc:
            message = f"{name}: {type(exc).__name__}: {exc}"
            results[name] = {"status": "failed", "error": str(exc)}
            failures.append(message)
    finished = now if fixed_clock else utc_now()
    status = "partial_failure" if failures else "success"
    error = " | ".join(failures)
    finding_status = str(dict(results.get("finding") or {}).get("status") or "")
    recon_status = str(dict(results.get("recon_alert") or {}).get("status") or "")
    db.execute(
        "UPDATE notification_supervisor_runs SET status=?,finding_status=?,recon_alert_status=?,error=?,finished_at=? "
        "WHERE supervisor_run_id=?",
        (status, finding_status, recon_status, error, finished, run_id),
    )
    if failures:
        db.execute(
            "UPDATE notification_supervisor_state SET last_finished_at=?,last_error_at=?,last_status=?,last_error=?,"
            "cycle_count=cycle_count+1,worker_success_count=worker_success_count+?,"
            "worker_failure_count=worker_failure_count+?,updated_at=? WHERE singleton=1",
            (finished, finished, status, error, success_count, len(failures), finished),
        )
    else:
        db.execute(
            "UPDATE notification_supervisor_state SET last_finished_at=?,last_success_at=?,last_status='success',last_error='',"
            "cycle_count=cycle_count+1,worker_success_count=worker_success_count+?,updated_at=? WHERE singleton=1",
            (finished, finished, success_count, finished),
        )
    heartbeat_notification_supervisor(db, owner_id=owner_id, now=finished)
    supervisor_status = notification_supervisor_status(db, now=finished)
    slo = evaluate_notification_delivery_slo(
        db,
        workers={
            "finding": finding_notification_diagnostics(db, now=finished),
            "recon_alert": recon_alert_diagnostics(db, now=finished),
        },
        supervisor=supervisor_status,
        now=finished,
    )
    return {
        "version": NOTIFICATION_SUPERVISOR_VERSION,
        "status": status,
        "supervisor_run_id": run_id,
        "owner_id": owner_id,
        "workers": results,
        "error": error,
        "supervisor": supervisor_status,
        "slo": slo,
    }


def run_notification_supervisor_cycle(
    *,
    config: Any,
    logger: Any,
    db: Database,
    owner_id: str = "",
    trigger: str = "cli",
    now: str = "",
) -> dict[str, Any]:
    ensure_notification_supervisor_schema(db)
    current = str(now or utc_now())
    owner = str(owner_id or ("supervisor-" + uuid.uuid4().hex[:12]))
    if not acquire_notification_supervisor_lease(db, owner_id=owner, now=current):
        return {
            "version": NOTIFICATION_SUPERVISOR_VERSION,
            "status": "skipped",
            "reason": "lease_held",
            "supervisor": notification_supervisor_status(db, now=current),
        }
    try:
        return _execute_owned_cycle(
            config=config,
            logger=logger,
            db=db,
            owner_id=owner,
            trigger=trigger,
            now=current,
            fixed_clock=bool(now),
        )
    finally:
        release_notification_supervisor_lease(db, owner_id=owner, now=current if now else utc_now())


def watch_notification_supervisor(
    *,
    config: Any,
    logger: Any,
    db: Database,
    owner_id: str = "",
    stop: Callable[[], bool] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    max_cycles: int = 0,
) -> dict[str, Any]:
    ensure_notification_supervisor_schema(db)
    owner = str(owner_id or ("supervisor-" + uuid.uuid4().hex[:12]))
    current = utc_now()
    if not acquire_notification_supervisor_lease(db, owner_id=owner, now=current):
        return {"status": "skipped", "reason": "lease_held", "supervisor": notification_supervisor_status(db)}
    cycles = failures = 0
    try:
        while True:
            if stop and stop():
                break
            now = utc_now()
            result = _execute_owned_cycle(
                config=config,
                logger=logger,
                db=db,
                owner_id=owner,
                trigger="watch",
                now=now,
            )
            cycles += 1
            if str(result.get("status") or "") == "partial_failure":
                failures += 1
            if max_cycles and cycles >= max_cycles:
                break
            policy = dict(db.one("SELECT poll_seconds,lease_seconds FROM notification_supervisor_state WHERE singleton=1"))
            if not heartbeat_notification_supervisor(db, owner_id=owner, lease_seconds=int(policy["lease_seconds"])):
                raise RuntimeError("Notification supervisor lease lost")
            sleep(max(MIN_POLL_SECONDS, min(MAX_POLL_SECONDS, int(policy["poll_seconds"]))))
        return {
            "status": "stopped",
            "cycles": cycles,
            "partial_failures": failures,
            "supervisor": notification_supervisor_status(db),
        }
    finally:
        release_notification_supervisor_lease(db, owner_id=owner)
