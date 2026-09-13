from __future__ import annotations

"""Explicit per-target lifecycle and baseline state for Recon Monitor.

This module separates four operational truths that previously collapsed into a
single target status:

* collection_status: whether the Recon snapshot is complete enough to compare;
* analysis_status: whether automatic Analysis completed;
* report_status: whether report generation completed;
* notification_status: whether the Potential Finding notification pipeline ran.

Baseline eligibility is intentionally derived from collection completeness only.
A report, Analysis, or notification failure can make the overall run partial,
but it must not invalidate a complete Recon snapshot. Conversely, incomplete
collection can never establish or refresh the canonical comparison baseline.
"""

from typing import Any, Iterable, Mapping

from core import utc_now


LIFECYCLE_STATE_VERSION = "1.0.0"
LIFECYCLE_META_KEY = "explicit_target_lifecycle_v1"

COLLECTION_TERMINAL = {"success", "failed", "interrupted", "not_run"}
ANALYSIS_TERMINAL = {"success", "failed", "not_run"}
REPORT_TERMINAL = {"success", "failed", "interrupted", "not_run"}
NOTIFICATION_TERMINAL = {"success", "queued", "failed", "not_run"}
OVERALL_TERMINAL = {"success", "partial", "failed", "interrupted"}
BASELINE_STATES = {"pending", "established", "refreshed", "retained", "blocked"}


def ensure_lifecycle_schema(db: Any) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS target_run_lifecycle (
          run_id TEXT NOT NULL,
          target TEXT NOT NULL,
          collection_status TEXT NOT NULL DEFAULT 'not_run',
          analysis_status TEXT NOT NULL DEFAULT 'not_run',
          report_status TEXT NOT NULL DEFAULT 'not_run',
          notification_status TEXT NOT NULL DEFAULT 'not_run',
          overall_status TEXT NOT NULL DEFAULT 'partial',
          baseline_eligible INTEGER NOT NULL DEFAULT 0,
          baseline_state TEXT NOT NULL DEFAULT 'pending',
          baseline_reason TEXT NOT NULL DEFAULT '',
          baseline_source_run_id TEXT NOT NULL DEFAULT '',
          baseline_established_at TEXT,
          details_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY(run_id,target)
        );
        CREATE INDEX IF NOT EXISTS idx_target_run_lifecycle_target
          ON target_run_lifecycle(target,updated_at);

        CREATE TABLE IF NOT EXISTS target_baselines (
          target TEXT PRIMARY KEY,
          state TEXT NOT NULL DEFAULT 'established',
          established_run_id TEXT NOT NULL,
          established_at TEXT NOT NULL,
          last_refreshed_run_id TEXT NOT NULL,
          last_refreshed_at TEXT NOT NULL,
          reason TEXT NOT NULL DEFAULT 'collection_complete',
          migrated INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        );
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (LIFECYCLE_META_KEY, LIFECYCLE_STATE_VERSION),
    )

    # Compatibility bootstrap: successful_recon_commits is already the trusted
    # canonical Recon snapshot boundary from the previous reliability phase.
    # Use it to initialize explicit baseline identity without reinterpreting
    # mutable working tables or legacy failed runs.
    rows = db.all(
        "SELECT target,run_id,committed_at FROM successful_recon_commits "
        "ORDER BY target"
    )
    now = utc_now()
    for row in rows:
        target = str(row["target"])
        run_id = str(row["run_id"])
        committed_at = str(row["committed_at"] or now)
        db.execute(
            "INSERT OR IGNORE INTO target_baselines("
            "target,state,established_run_id,established_at,last_refreshed_run_id,"
            "last_refreshed_at,reason,migrated,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?)",
            (
                target,
                "established",
                run_id,
                committed_at,
                run_id,
                committed_at,
                "migrated_successful_snapshot",
                1,
                now,
            ),
        )


def has_established_baseline(db: Any, target: str) -> bool:
    row = db.one(
        "SELECT 1 FROM target_baselines WHERE target=? AND state='established' LIMIT 1",
        (target,),
    )
    return row is not None


def baseline_record(db: Any, target: str) -> dict[str, Any] | None:
    row = db.one(
        "SELECT * FROM target_baselines WHERE target=?",
        (target,),
    )
    return dict(row) if row else None


def begin_target_lifecycle(db: Any, run_id: str, target: str) -> None:
    ensure_lifecycle_schema(db)
    existing = baseline_record(db, target)
    now = utc_now()
    db.execute(
        "INSERT OR IGNORE INTO target_run_lifecycle("
        "run_id,target,collection_status,analysis_status,report_status,notification_status,"
        "overall_status,baseline_eligible,baseline_state,baseline_reason,"
        "baseline_source_run_id,baseline_established_at,details_json,created_at,updated_at"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            run_id,
            target,
            "not_run",
            "not_run",
            "not_run",
            "not_run",
            "partial",
            0,
            "pending",
            "",
            str(existing.get("last_refreshed_run_id") or "") if existing else "",
            str(existing.get("established_at") or "") if existing else None,
            "{}",
            now,
            now,
        ),
    )


def _stage_statuses(db: Any, run_id: str, target: str) -> dict[str, str]:
    return {
        str(row["stage"]): str(row["status"])
        for row in db.all(
            "SELECT stage,status FROM stage_runs WHERE run_id=? AND target=?",
            (run_id, target),
        )
    }


def derive_collection_status(
    db: Any,
    run_id: str,
    target: str,
    collection_stages: Iterable[str],
) -> tuple[str, str]:
    statuses = _stage_statuses(db, run_id, target)
    stages = [str(stage) for stage in collection_stages]
    for stage in stages:
        status = statuses.get(stage)
        if status == "interrupted":
            return "interrupted", f"collection_interrupted:{stage}"
        if status == "failed":
            return "failed", f"collection_failed:{stage}"

    missing = [stage for stage in stages if statuses.get(stage) != "success"]
    if missing:
        return "not_run", "collection_incomplete:" + ",".join(missing)
    return "success", "collection_complete"


def derive_analysis_status(
    db: Any,
    run_id: str,
    target: str,
    report_metrics: Mapping[str, Any] | None,
) -> str:
    metrics = dict(report_metrics or {})
    analysis = metrics.get("analysis")
    if isinstance(analysis, Mapping):
        status = str(analysis.get("status") or "").strip().lower()
        if status == "failed":
            return "failed"
        if analysis.get("analysis_id"):
            return "success"

    row = db.one(
        "SELECT status FROM analysis_runs WHERE source_run_id=? AND target=? "
        "ORDER BY COALESCE(finished_at,started_at) DESC,rowid DESC LIMIT 1",
        (run_id, target),
    )
    if row is None:
        return "not_run"
    status = str(row["status"] or "").strip().lower()
    if status == "success":
        return "success"
    if status in {"failed", "error", "interrupted"}:
        return "failed"
    return "not_run"


def derive_notification_status(
    report_metrics: Mapping[str, Any] | None,
    analysis_status: str,
) -> str:
    if analysis_status != "success":
        return "not_run"
    metrics = dict(report_metrics or {})
    finding = metrics.get("finding_notifications")
    if not isinstance(finding, Mapping):
        return "not_run"

    if str(finding.get("status") or "").strip().lower() == "failed":
        return "failed"

    delivery = finding.get("delivery")
    delivery_map = dict(delivery) if isinstance(delivery, Mapping) else {}
    queued_for_delivery = int(delivery_map.get("queued", 0) or 0)
    delivered = int(delivery_map.get("delivered", 0) or 0)
    error = str(delivery_map.get("error") or "").strip()
    newly_queued = int(finding.get("queued", 0) or 0)

    if error and queued_for_delivery > delivered:
        return "failed"
    if queued_for_delivery > delivered:
        return "queued"
    if newly_queued > delivered and queued_for_delivery == 0:
        # Digest/silent policies can intentionally leave an event queued for a
        # later delivery path. This is healthy deferred work, not a scan error.
        return "queued"
    return "success"


def derive_overall_status(
    collection_status: str,
    analysis_status: str,
    report_status: str,
    notification_status: str,
) -> str:
    if collection_status == "interrupted" or report_status == "interrupted":
        return "interrupted"
    if collection_status != "success":
        return "failed"
    if report_status != "success":
        return "partial"
    if analysis_status != "success":
        return "partial"
    if notification_status not in {"success", "queued"}:
        return "partial"
    return "success"


def record_target_lifecycle(
    db: Any,
    run_id: str,
    target: str,
    *,
    collection_status: str,
    analysis_status: str,
    report_status: str,
    notification_status: str,
    overall_status: str,
    baseline_reason: str,
    details_json: str = "{}",
) -> None:
    begin_target_lifecycle(db, run_id, target)
    if collection_status not in COLLECTION_TERMINAL:
        raise ValueError(f"invalid collection status: {collection_status}")
    if analysis_status not in ANALYSIS_TERMINAL:
        raise ValueError(f"invalid analysis status: {analysis_status}")
    if report_status not in REPORT_TERMINAL:
        raise ValueError(f"invalid report status: {report_status}")
    if notification_status not in NOTIFICATION_TERMINAL:
        raise ValueError(f"invalid notification status: {notification_status}")
    if overall_status not in OVERALL_TERMINAL:
        raise ValueError(f"invalid overall status: {overall_status}")

    eligible = int(collection_status == "success")
    db.execute(
        "UPDATE target_run_lifecycle SET "
        "collection_status=?,analysis_status=?,report_status=?,notification_status=?,"
        "overall_status=?,baseline_eligible=?,baseline_reason=?,details_json=?,updated_at=? "
        "WHERE run_id=? AND target=?",
        (
            collection_status,
            analysis_status,
            report_status,
            notification_status,
            overall_status,
            eligible,
            baseline_reason,
            details_json,
            utc_now(),
            run_id,
            target,
        ),
    )


def lifecycle_record(db: Any, run_id: str, target: str) -> dict[str, Any] | None:
    row = db.one(
        "SELECT * FROM target_run_lifecycle WHERE run_id=? AND target=?",
        (run_id, target),
    )
    return dict(row) if row else None


def baseline_commit_eligible(db: Any, run_id: str, target: str) -> bool | None:
    row = db.one(
        "SELECT baseline_eligible,collection_status,baseline_state "
        "FROM target_run_lifecycle WHERE run_id=? AND target=?",
        (run_id, target),
    )
    if row is None:
        return None
    # A row is created when collection starts. Synthetic/maintenance callers
    # that never finalize explicit component states retain the previous
    # compatibility behavior instead of being interpreted as ineligible.
    if str(row["collection_status"]) == "not_run" and str(row["baseline_state"]) == "pending":
        return None
    return bool(row["baseline_eligible"])


def mark_baseline_committed(db: Any, run_id: str, target: str, reason: str) -> str:
    """Persist first establishment or refresh after the snapshot commit succeeds."""

    now = utc_now()
    previous = baseline_record(db, target)
    if previous is None:
        state = "established"
        established_at = now
        db.execute(
            "INSERT INTO target_baselines("
            "target,state,established_run_id,established_at,last_refreshed_run_id,"
            "last_refreshed_at,reason,migrated,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?)",
            (
                target,
                "established",
                run_id,
                established_at,
                run_id,
                now,
                reason or "collection_complete",
                0,
                now,
            ),
        )
    else:
        state = "refreshed"
        established_at = str(previous["established_at"])
        db.execute(
            "UPDATE target_baselines SET state='established',last_refreshed_run_id=?,"
            "last_refreshed_at=?,reason=?,updated_at=? WHERE target=?",
            (run_id, now, reason or "collection_complete", now, target),
        )

    db.execute(
        "UPDATE target_run_lifecycle SET baseline_state=?,baseline_reason=?,"
        "baseline_source_run_id=?,baseline_established_at=?,updated_at=? "
        "WHERE run_id=? AND target=?",
        (
            state,
            reason or "collection_complete",
            run_id,
            established_at,
            now,
            run_id,
            target,
        ),
    )
    return state


def mark_baseline_not_committed(db: Any, run_id: str, target: str, reason: str) -> str:
    existing = baseline_record(db, target)
    state = "retained" if existing is not None else "blocked"
    db.execute(
        "UPDATE target_run_lifecycle SET baseline_state=?,baseline_reason=?,"
        "baseline_source_run_id=?,baseline_established_at=?,updated_at=? "
        "WHERE run_id=? AND target=?",
        (
            state,
            reason,
            str(existing.get("last_refreshed_run_id") or "") if existing else "",
            str(existing.get("established_at") or "") if existing else None,
            utc_now(),
            run_id,
            target,
        ),
    )
    return state
