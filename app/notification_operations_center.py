from __future__ import annotations

"""Unified control-plane view for independent notification delivery workers."""

from typing import Any

from core import Database, ReconError, utc_now
from finding_notification_operations import (
    configure_finding_notification_worker,
    drain_finding_notification_outbox,
    finding_notification_diagnostics,
    list_dead_letters,
    retry_dead_letters,
    run_finding_notification_worker,
)
from notification_supervisor import notification_supervisor_status
from recon_alert_operations import (
    configure_recon_alert_worker,
    drain_recon_alert_outbox,
    list_recon_alert_dead_letters,
    recon_alert_diagnostics,
    retry_recon_alert_dead_letters,
    run_recon_alert_worker,
)

NOTIFICATION_OPERATIONS_CENTER_VERSION = "1.1.0"
_WORKERS = {"finding", "recon_alert"}
_ACTIONS = {"configure", "retry", "run", "drain"}


def _last_run_health(diagnostics: dict[str, Any]) -> str:
    last = dict(diagnostics.get("last_worker_run") or {})
    if not last:
        return "not_run"
    return str(last.get("status") or "unknown")


def _worker_snapshot(name: str, diagnostics: dict[str, Any]) -> dict[str, Any]:
    policy = dict(diagnostics.get("policy") or {})
    dead = int(diagnostics.get("dead_letter_open", 0) or 0)
    due = int(diagnostics.get("due_now", 0) or 0)
    queue = int(diagnostics.get("queue_depth", 0) or 0)
    last_status = _last_run_health(diagnostics)
    state = "healthy"
    if dead or last_status == "failed":
        state = "degraded"
    elif queue and not bool(policy.get("enabled", True)):
        state = "paused_with_backlog"
    elif due:
        state = "work_due"
    return {"worker": name, "state": state, **diagnostics}


def notification_delivery_operations(db: Database, *, now: str = "") -> dict[str, Any]:
    """Return one operational view without merging worker persistence or lifecycle state."""
    current = str(now or utc_now())
    finding = _worker_snapshot("finding", finding_notification_diagnostics(db, now=current))
    recon = _worker_snapshot("recon_alert", recon_alert_diagnostics(db, now=current))
    supervisor = notification_supervisor_status(db, now=current)
    workers = [finding, recon]
    warnings: list[str] = []
    for item in workers:
        label = "Finding" if item["worker"] == "finding" else "Recon Alert"
        if int(item.get("dead_letter_open", 0) or 0):
            warnings.append(f"{label} delivery has {int(item['dead_letter_open'])} open dead-letter event(s).")
        if int(item.get("queue_depth", 0) or 0) and not bool(dict(item.get("policy") or {}).get("enabled", True)):
            warnings.append(f"{label} worker is disabled while delivery backlog remains queued.")
        if _last_run_health(item) == "failed":
            warnings.append(f"{label} worker's latest recorded run failed.")
    if str(supervisor.get("state") or "") == "degraded":
        warnings.append("Notification supervisor is degraded; inspect its latest error and worker results.")
    if not bool(supervisor.get("enabled", True)) and any(int(item.get("due_now", 0) or 0) for item in workers):
        warnings.append("Notification supervisor is disabled while delivery work is due.")
    return {
        "version": NOTIFICATION_OPERATIONS_CENTER_VERSION,
        "generated_at": current,
        "supervisor": supervisor,
        "workers": {"finding": finding, "recon_alert": recon},
        "queue_depth": sum(int(item.get("queue_depth", 0) or 0) for item in workers),
        "due_now": sum(int(item.get("due_now", 0) or 0) for item in workers),
        "dead_letter_open": sum(int(item.get("dead_letter_open", 0) or 0) for item in workers),
        "warnings": warnings,
    }


def combined_dead_letters(db: Database, *, limit: int = 100) -> list[dict[str, Any]]:
    bounded = max(1, min(500, int(limit)))
    rows: list[dict[str, Any]] = []
    for row in list_dead_letters(db, limit=bounded):
        rows.append({"worker": "finding", **dict(row)})
    for row in list_recon_alert_dead_letters(db, limit=bounded):
        rows.append({"worker": "recon_alert", **dict(row)})
    rows.sort(key=lambda row: str(row.get("dead_lettered_at") or ""), reverse=True)
    return rows[:bounded]


def notification_delivery_action(
    *,
    worker: str,
    action: str,
    config: Any,
    logger: Any,
    db: Database,
    enabled: bool | None = None,
    interval_seconds: int | None = None,
    batch_limit: int | None = None,
    event_id: str = "",
    target: str = "",
    max_batches: int = 20,
) -> dict[str, Any]:
    """Dispatch an operator action to one worker while preserving independent state."""
    worker = str(worker or "").strip().lower()
    action = str(action or "").strip().lower()
    if worker not in _WORKERS:
        raise ReconError(f"Unknown notification worker: {worker}")
    if action not in _ACTIONS:
        raise ReconError(f"Unknown notification worker action: {action}")

    result: Any
    if worker == "finding":
        if action == "configure":
            result = configure_finding_notification_worker(
                db, enabled=enabled, interval_seconds=interval_seconds, batch_limit=batch_limit
            )
        elif action == "retry":
            result = {"requeued": retry_dead_letters(db, event_id=event_id, target=target)}
        elif action == "run":
            result = run_finding_notification_worker(
                config=config,
                logger=logger,
                db=db,
                trigger="dashboard",
                force=True,
                target=target,
                limit=batch_limit,
            )
        else:
            result = drain_finding_notification_outbox(
                config=config,
                logger=logger,
                db=db,
                max_batches=max(1, min(100, int(max_batches))),
                batch_limit=max(1, min(500, int(batch_limit or 100))),
            )
    else:
        if action == "configure":
            result = configure_recon_alert_worker(
                db, enabled=enabled, interval_seconds=interval_seconds, batch_limit=batch_limit
            )
        elif action == "retry":
            result = {"requeued": retry_recon_alert_dead_letters(db, event_id=event_id, target=target)}
        elif action == "run":
            result = run_recon_alert_worker(
                config=config,
                logger=logger,
                db=db,
                trigger="dashboard",
                force=True,
                target=target,
                limit=batch_limit,
            )
        else:
            result = drain_recon_alert_outbox(
                config=config,
                logger=logger,
                db=db,
                target=target,
                max_batches=max(1, min(100, int(max_batches))),
                batch_limit=max(1, min(500, int(batch_limit or 100))),
            )
    return {
        "worker": worker,
        "action": action,
        "result": result,
        "operations": notification_delivery_operations(db),
    }
