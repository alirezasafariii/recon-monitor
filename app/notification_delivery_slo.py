from __future__ import annotations

"""Delivery SLO evaluation and durable breach lifecycle for notification workers."""

import datetime as dt
import uuid
from typing import Any, Mapping

from core import Database, utc_now

NOTIFICATION_DELIVERY_SLO_VERSION = "1.0.0"
NOTIFICATION_DELIVERY_SLO_SCHEMA_VERSION = 1

DEFAULT_PENDING_WARNING_SECONDS = 7200
DEFAULT_PENDING_CRITICAL_SECONDS = 21600
DEFAULT_BACKLOG_WARNING = 50
DEFAULT_BACKLOG_CRITICAL = 200
DEFAULT_DEAD_LETTER_WARNING = 1
DEFAULT_DEAD_LETTER_CRITICAL = 5
DEFAULT_HEARTBEAT_WARNING_SECONDS = 90
DEFAULT_HEARTBEAT_CRITICAL_SECONDS = 300
DEFAULT_FAILURE_WARNING_COUNT = 2
DEFAULT_FAILURE_CRITICAL_COUNT = 3
DEFAULT_COOLDOWN_SECONDS = 900

_WORKER_LABELS = {"finding": "Finding", "recon_alert": "Recon Alert"}
_SEVERITY_ORDER = {"healthy": 0, "warning": 1, "critical": 2}


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


def _age_seconds(value: str, *, now: str) -> int:
    then = _parse_time(value)
    current = _parse_time(now)
    if then is None or current is None:
        return 0
    return max(0, int((current - then).total_seconds()))


def _future(now: str, seconds: int) -> str:
    current = _parse_time(now) or dt.datetime.now(dt.timezone.utc)
    return _iso(current + dt.timedelta(seconds=max(0, int(seconds))))


def ensure_notification_delivery_slo_schema(db: Database) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS notification_delivery_slo_policy (
          singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          enabled INTEGER NOT NULL DEFAULT 1,
          pending_warning_seconds INTEGER NOT NULL DEFAULT 7200,
          pending_critical_seconds INTEGER NOT NULL DEFAULT 21600,
          backlog_warning INTEGER NOT NULL DEFAULT 50,
          backlog_critical INTEGER NOT NULL DEFAULT 200,
          dead_letter_warning INTEGER NOT NULL DEFAULT 1,
          dead_letter_critical INTEGER NOT NULL DEFAULT 5,
          heartbeat_warning_seconds INTEGER NOT NULL DEFAULT 90,
          heartbeat_critical_seconds INTEGER NOT NULL DEFAULT 300,
          failure_warning_count INTEGER NOT NULL DEFAULT 2,
          failure_critical_count INTEGER NOT NULL DEFAULT 3,
          cooldown_seconds INTEGER NOT NULL DEFAULT 900,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notification_delivery_slo_breaches (
          breach_key TEXT PRIMARY KEY,
          scope TEXT NOT NULL,
          metric TEXT NOT NULL,
          status TEXT NOT NULL,
          severity TEXT NOT NULL,
          value INTEGER NOT NULL DEFAULT 0,
          warning_threshold INTEGER NOT NULL DEFAULT 0,
          critical_threshold INTEGER NOT NULL DEFAULT 0,
          summary TEXT NOT NULL DEFAULT '',
          opened_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL,
          resolved_at TEXT NOT NULL DEFAULT '',
          duration_seconds INTEGER NOT NULL DEFAULT 0,
          occurrences INTEGER NOT NULL DEFAULT 1,
          last_transition_at TEXT NOT NULL,
          last_event_at TEXT NOT NULL DEFAULT '',
          cooldown_until TEXT NOT NULL DEFAULT '',
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_notification_delivery_slo_breaches_status
          ON notification_delivery_slo_breaches(status,severity,last_seen_at);
        CREATE TABLE IF NOT EXISTS notification_delivery_slo_events (
          event_id TEXT PRIMARY KEY,
          breach_key TEXT NOT NULL,
          scope TEXT NOT NULL,
          metric TEXT NOT NULL,
          transition TEXT NOT NULL,
          severity TEXT NOT NULL,
          value INTEGER NOT NULL DEFAULT 0,
          summary TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          FOREIGN KEY(breach_key) REFERENCES notification_delivery_slo_breaches(breach_key) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_notification_delivery_slo_events_created
          ON notification_delivery_slo_events(created_at);
        """
    )
    now = utc_now()
    db.execute(
        "INSERT OR IGNORE INTO notification_delivery_slo_policy("
        "singleton,enabled,pending_warning_seconds,pending_critical_seconds,backlog_warning,backlog_critical,"
        "dead_letter_warning,dead_letter_critical,heartbeat_warning_seconds,heartbeat_critical_seconds,"
        "failure_warning_count,failure_critical_count,cooldown_seconds,updated_at"
        ") VALUES(1,1,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            DEFAULT_PENDING_WARNING_SECONDS,
            DEFAULT_PENDING_CRITICAL_SECONDS,
            DEFAULT_BACKLOG_WARNING,
            DEFAULT_BACKLOG_CRITICAL,
            DEFAULT_DEAD_LETTER_WARNING,
            DEFAULT_DEAD_LETTER_CRITICAL,
            DEFAULT_HEARTBEAT_WARNING_SECONDS,
            DEFAULT_HEARTBEAT_CRITICAL_SECONDS,
            DEFAULT_FAILURE_WARNING_COUNT,
            DEFAULT_FAILURE_CRITICAL_COUNT,
            DEFAULT_COOLDOWN_SECONDS,
            now,
        ),
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('notification_delivery_slo_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(NOTIFICATION_DELIVERY_SLO_SCHEMA_VERSION),),
    )


def notification_delivery_slo_policy(db: Database) -> dict[str, Any]:
    ensure_notification_delivery_slo_schema(db)
    row = dict(db.one("SELECT * FROM notification_delivery_slo_policy WHERE singleton=1"))
    row["enabled"] = bool(int(row["enabled"]))
    return row


def configure_notification_delivery_slo(
    db: Database,
    *,
    enabled: bool | None = None,
    pending_warning_seconds: int | None = None,
    pending_critical_seconds: int | None = None,
    backlog_warning: int | None = None,
    backlog_critical: int | None = None,
    dead_letter_warning: int | None = None,
    dead_letter_critical: int | None = None,
    heartbeat_warning_seconds: int | None = None,
    heartbeat_critical_seconds: int | None = None,
    failure_warning_count: int | None = None,
    failure_critical_count: int | None = None,
    cooldown_seconds: int | None = None,
) -> dict[str, Any]:
    ensure_notification_delivery_slo_schema(db)
    current = notification_delivery_slo_policy(db)

    def choose(name: str, value: int | None, minimum: int, maximum: int) -> int:
        if value is None:
            return int(current[name])
        return max(minimum, min(maximum, int(value)))

    values = {
        "enabled": int(bool(enabled)) if enabled is not None else int(bool(current["enabled"])),
        "pending_warning_seconds": choose("pending_warning_seconds", pending_warning_seconds, 60, 604800),
        "pending_critical_seconds": choose("pending_critical_seconds", pending_critical_seconds, 60, 1209600),
        "backlog_warning": choose("backlog_warning", backlog_warning, 1, 1000000),
        "backlog_critical": choose("backlog_critical", backlog_critical, 1, 1000000),
        "dead_letter_warning": choose("dead_letter_warning", dead_letter_warning, 1, 1000000),
        "dead_letter_critical": choose("dead_letter_critical", dead_letter_critical, 1, 1000000),
        "heartbeat_warning_seconds": choose("heartbeat_warning_seconds", heartbeat_warning_seconds, 15, 86400),
        "heartbeat_critical_seconds": choose("heartbeat_critical_seconds", heartbeat_critical_seconds, 15, 604800),
        "failure_warning_count": choose("failure_warning_count", failure_warning_count, 1, 1000),
        "failure_critical_count": choose("failure_critical_count", failure_critical_count, 1, 1000),
        "cooldown_seconds": choose("cooldown_seconds", cooldown_seconds, 0, 86400),
    }
    pairs = (
        ("pending_warning_seconds", "pending_critical_seconds"),
        ("backlog_warning", "backlog_critical"),
        ("dead_letter_warning", "dead_letter_critical"),
        ("heartbeat_warning_seconds", "heartbeat_critical_seconds"),
        ("failure_warning_count", "failure_critical_count"),
    )
    for warning_name, critical_name in pairs:
        if int(values[critical_name]) < int(values[warning_name]):
            values[critical_name] = int(values[warning_name])
    now = utc_now()
    db.execute(
        "UPDATE notification_delivery_slo_policy SET enabled=?,pending_warning_seconds=?,pending_critical_seconds=?,"
        "backlog_warning=?,backlog_critical=?,dead_letter_warning=?,dead_letter_critical=?,"
        "heartbeat_warning_seconds=?,heartbeat_critical_seconds=?,failure_warning_count=?,failure_critical_count=?,"
        "cooldown_seconds=?,updated_at=? WHERE singleton=1",
        (
            values["enabled"], values["pending_warning_seconds"], values["pending_critical_seconds"],
            values["backlog_warning"], values["backlog_critical"], values["dead_letter_warning"],
            values["dead_letter_critical"], values["heartbeat_warning_seconds"],
            values["heartbeat_critical_seconds"], values["failure_warning_count"],
            values["failure_critical_count"], values["cooldown_seconds"], now,
        ),
    )
    return notification_delivery_slo_policy(db)


def _severity(value: int, warning: int, critical: int) -> str:
    numeric = int(value or 0)
    if numeric >= int(critical):
        return "critical"
    if numeric >= int(warning):
        return "warning"
    return "healthy"


def _consecutive_failures(db: Database, table: str, *, limit: int = 100) -> int:
    allowed = {
        "finding_notification_worker_runs": {"failed"},
        "recon_alert_worker_runs": {"failed"},
        "notification_supervisor_runs": {"failed", "partial_failure"},
    }
    if table not in allowed:
        return 0
    if db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)) is None:
        return 0
    failures = 0
    for row in db.all(f"SELECT status FROM {table} ORDER BY started_at DESC LIMIT ?", (max(1, min(1000, int(limit))),)):
        status = str(row["status"] or "")
        if status in allowed[table]:
            failures += 1
            continue
        break
    return failures


def _record_event(
    db: Database,
    *,
    breach_key: str,
    scope: str,
    metric: str,
    transition: str,
    severity: str,
    value: int,
    summary: str,
    now: str,
) -> dict[str, Any]:
    event_id = "NSLO-" + uuid.uuid4().hex[:20]
    db.execute(
        "INSERT INTO notification_delivery_slo_events("
        "event_id,breach_key,scope,metric,transition,severity,value,summary,created_at"
        ") VALUES(?,?,?,?,?,?,?,?,?)",
        (event_id, breach_key, scope, metric, transition, severity, int(value), summary, now),
    )
    return {
        "event_id": event_id,
        "breach_key": breach_key,
        "scope": scope,
        "metric": metric,
        "transition": transition,
        "severity": severity,
        "value": int(value),
        "summary": summary,
        "created_at": now,
    }


def _apply_metric(
    db: Database,
    *,
    scope: str,
    metric: str,
    value: int,
    warning_threshold: int,
    critical_threshold: int,
    summary: str,
    now: str,
    cooldown_seconds: int,
) -> list[dict[str, Any]]:
    breach_key = f"{scope}:{metric}"
    severity = _severity(value, warning_threshold, critical_threshold)
    existing_row = db.one("SELECT * FROM notification_delivery_slo_breaches WHERE breach_key=?", (breach_key,))
    existing = dict(existing_row) if existing_row else None
    emitted: list[dict[str, Any]] = []

    if severity == "healthy":
        if existing and str(existing.get("status")) == "open":
            duration = _age_seconds(str(existing.get("opened_at") or ""), now=now)
            db.execute(
                "UPDATE notification_delivery_slo_breaches SET status='resolved',severity='healthy',value=?,summary=?,"
                "last_seen_at=?,resolved_at=?,duration_seconds=?,last_transition_at=?,updated_at=? WHERE breach_key=?",
                (int(value), summary, now, now, duration, now, now, breach_key),
            )
            emitted.append(_record_event(
                db, breach_key=breach_key, scope=scope, metric=metric, transition="resolved",
                severity="healthy", value=value, summary=summary, now=now,
            ))
        return emitted

    cooldown_until = _future(now, cooldown_seconds)
    if existing is None:
        db.execute(
            "INSERT INTO notification_delivery_slo_breaches("
            "breach_key,scope,metric,status,severity,value,warning_threshold,critical_threshold,summary,"
            "opened_at,last_seen_at,resolved_at,duration_seconds,occurrences,last_transition_at,last_event_at,"
            "cooldown_until,updated_at"
            ") VALUES(?,?,?,'open',?,?,?,?,?,?,?,'',0,1,?,?,?,?,?)",
            (
                breach_key, scope, metric, severity, int(value), int(warning_threshold), int(critical_threshold),
                summary, now, now, now, now, cooldown_until, now,
            ),
        )
        emitted.append(_record_event(
            db, breach_key=breach_key, scope=scope, metric=metric, transition="opened",
            severity=severity, value=value, summary=summary, now=now,
        ))
        return emitted

    was_open = str(existing.get("status") or "") == "open"
    old_severity = str(existing.get("severity") or "warning")
    last_event_at = str(existing.get("last_event_at") or "")
    event_allowed = not last_event_at or _age_seconds(last_event_at, now=now) >= max(0, int(cooldown_seconds))
    transition = ""
    occurrences = int(existing.get("occurrences") or 0)
    opened_at = str(existing.get("opened_at") or now)
    last_transition_at = str(existing.get("last_transition_at") or now)
    new_last_event_at = last_event_at
    new_cooldown_until = str(existing.get("cooldown_until") or "")

    if not was_open:
        occurrences += 1
        opened_at = now
        last_transition_at = now
        transition = "reopened"
    elif _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(old_severity, 0):
        last_transition_at = now
        transition = "escalated"
    elif _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(old_severity, 0):
        last_transition_at = now
        transition = "deescalated"

    if transition and event_allowed:
        event = _record_event(
            db, breach_key=breach_key, scope=scope, metric=metric, transition=transition,
            severity=severity, value=value, summary=summary, now=now,
        )
        emitted.append(event)
        new_last_event_at = now
        new_cooldown_until = cooldown_until

    db.execute(
        "UPDATE notification_delivery_slo_breaches SET status='open',severity=?,value=?,warning_threshold=?,"
        "critical_threshold=?,summary=?,opened_at=?,last_seen_at=?,resolved_at='',duration_seconds=0,"
        "occurrences=?,last_transition_at=?,last_event_at=?,cooldown_until=?,updated_at=? WHERE breach_key=?",
        (
            severity, int(value), int(warning_threshold), int(critical_threshold), summary, opened_at, now,
            occurrences, last_transition_at, new_last_event_at, new_cooldown_until, now, breach_key,
        ),
    )
    return emitted


def _worker_metrics(name: str, diagnostics: Mapping[str, Any], db: Database) -> dict[str, int]:
    table = "finding_notification_worker_runs" if name == "finding" else "recon_alert_worker_runs"
    return {
        "pending_age_seconds": int(diagnostics.get("oldest_pending_age_seconds", 0) or 0),
        "backlog": int(diagnostics.get("queue_depth", 0) or 0),
        "dead_letters": int(diagnostics.get("dead_letter_open", 0) or 0),
        "consecutive_failures": _consecutive_failures(db, table),
    }


def evaluate_notification_delivery_slo(
    db: Database,
    *,
    workers: Mapping[str, Mapping[str, Any]],
    supervisor: Mapping[str, Any],
    now: str = "",
) -> dict[str, Any]:
    """Evaluate current delivery health, update breach lifecycle, and return one SLO snapshot."""
    ensure_notification_delivery_slo_schema(db)
    current = str(now or utc_now())
    policy = notification_delivery_slo_policy(db)
    if not bool(policy["enabled"]):
        return notification_delivery_slo_status(db, now=current, policy=policy)

    emitted: list[dict[str, Any]] = []
    for name in ("finding", "recon_alert"):
        diagnostics = dict(workers.get(name) or {})
        metrics = _worker_metrics(name, diagnostics, db)
        label = _WORKER_LABELS[name]
        queue_depth = metrics["backlog"]
        pending_age = metrics["pending_age_seconds"] if queue_depth else 0
        specifications = (
            (
                "pending_age_seconds", pending_age,
                int(policy["pending_warning_seconds"]), int(policy["pending_critical_seconds"]),
                f"{label} delivery oldest pending event is {pending_age}s old.",
            ),
            (
                "backlog", queue_depth,
                int(policy["backlog_warning"]), int(policy["backlog_critical"]),
                f"{label} delivery backlog contains {queue_depth} event(s).",
            ),
            (
                "dead_letters", metrics["dead_letters"],
                int(policy["dead_letter_warning"]), int(policy["dead_letter_critical"]),
                f"{label} delivery has {metrics['dead_letters']} open dead-letter event(s).",
            ),
            (
                "consecutive_failures", metrics["consecutive_failures"],
                int(policy["failure_warning_count"]), int(policy["failure_critical_count"]),
                f"{label} worker has {metrics['consecutive_failures']} consecutive failed run(s).",
            ),
        )
        for metric, value, warning, critical, summary in specifications:
            emitted.extend(_apply_metric(
                db, scope=name, metric=metric, value=int(value), warning_threshold=warning,
                critical_threshold=critical, summary=summary, now=current,
                cooldown_seconds=int(policy["cooldown_seconds"]),
            ))

    aggregate_due = sum(int(dict(workers.get(name) or {}).get("due_now", 0) or 0) for name in ("finding", "recon_alert"))
    aggregate_queue = sum(int(dict(workers.get(name) or {}).get("queue_depth", 0) or 0) for name in ("finding", "recon_alert"))
    heartbeat_at = str(supervisor.get("heartbeat_at") or "")
    heartbeat_age = int(supervisor.get("heartbeat_age_seconds", 0) or 0)
    supervisor_enabled = bool(supervisor.get("enabled", True))
    heartbeat_relevant = supervisor_enabled and (bool(supervisor.get("lease_active")) or aggregate_due > 0 or aggregate_queue > 0)
    if heartbeat_relevant and not heartbeat_at:
        heartbeat_age = int(policy["heartbeat_critical_seconds"])
    elif not heartbeat_relevant:
        heartbeat_age = 0
    emitted.extend(_apply_metric(
        db,
        scope="supervisor",
        metric="heartbeat_age_seconds",
        value=heartbeat_age,
        warning_threshold=int(policy["heartbeat_warning_seconds"]),
        critical_threshold=int(policy["heartbeat_critical_seconds"]),
        summary=(
            "Notification supervisor has no heartbeat while delivery work requires supervision."
            if heartbeat_relevant and not heartbeat_at
            else f"Notification supervisor heartbeat age is {heartbeat_age}s."
        ),
        now=current,
        cooldown_seconds=int(policy["cooldown_seconds"]),
    ))
    supervisor_failures = _consecutive_failures(db, "notification_supervisor_runs")
    emitted.extend(_apply_metric(
        db,
        scope="supervisor",
        metric="consecutive_failures",
        value=supervisor_failures,
        warning_threshold=int(policy["failure_warning_count"]),
        critical_threshold=int(policy["failure_critical_count"]),
        summary=f"Notification supervisor has {supervisor_failures} consecutive failed/partial cycle(s).",
        now=current,
        cooldown_seconds=int(policy["cooldown_seconds"]),
    ))
    snapshot = notification_delivery_slo_status(db, now=current, policy=policy)
    snapshot["emitted_events"] = emitted
    return snapshot


def notification_delivery_slo_status(
    db: Database,
    *,
    now: str = "",
    policy: Mapping[str, Any] | None = None,
    recent_event_limit: int = 20,
) -> dict[str, Any]:
    ensure_notification_delivery_slo_schema(db)
    current = str(now or utc_now())
    active_policy = dict(policy or notification_delivery_slo_policy(db))
    open_rows = [dict(row) for row in db.all(
        "SELECT * FROM notification_delivery_slo_breaches WHERE status='open' "
        "ORDER BY CASE severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END DESC,last_seen_at DESC"
    )]
    recent_events = [dict(row) for row in db.all(
        "SELECT * FROM notification_delivery_slo_events ORDER BY created_at DESC LIMIT ?",
        (max(1, min(200, int(recent_event_limit))),),
    )]
    critical = sum(1 for row in open_rows if str(row.get("severity")) == "critical")
    warning = sum(1 for row in open_rows if str(row.get("severity")) == "warning")
    state = "disabled" if not bool(active_policy.get("enabled", True)) else "critical" if critical else "warning" if warning else "healthy"
    return {
        "version": NOTIFICATION_DELIVERY_SLO_VERSION,
        "generated_at": current,
        "state": state,
        "policy": active_policy,
        "open_breach_count": len(open_rows),
        "critical_breach_count": critical,
        "warning_breach_count": warning,
        "open_breaches": open_rows,
        "recent_events": recent_events,
    }


def list_notification_delivery_slo_breaches(
    db: Database,
    *,
    status: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    ensure_notification_delivery_slo_schema(db)
    bounded = max(1, min(500, int(limit)))
    normalized = str(status or "").strip().lower()
    if normalized in {"open", "resolved"}:
        rows = db.all(
            "SELECT * FROM notification_delivery_slo_breaches WHERE status=? ORDER BY last_seen_at DESC LIMIT ?",
            (normalized, bounded),
        )
    else:
        rows = db.all("SELECT * FROM notification_delivery_slo_breaches ORDER BY last_seen_at DESC LIMIT ?", (bounded,))
    return [dict(row) for row in rows]


def list_notification_delivery_slo_events(db: Database, *, limit: int = 100) -> list[dict[str, Any]]:
    ensure_notification_delivery_slo_schema(db)
    return [dict(row) for row in db.all(
        "SELECT * FROM notification_delivery_slo_events ORDER BY created_at DESC LIMIT ?",
        (max(1, min(500, int(limit))),),
    )]
