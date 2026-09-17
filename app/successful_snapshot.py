from __future__ import annotations

"""Successful-run comparison snapshots for Recon Monitor.

Collection keeps using the established mutable tables during an in-progress run
so resume and Analysis behavior remain compatible. This module adds a separate
commit boundary for the comparison state that drives "new" and "changed"
decisions:

* a new run restores the last committed successful snapshot before collection;
* failed/interrupted collection may mutate working tables, but is never promoted;
* a collection-complete target run atomically replaces the committed snapshot;
* Analysis/report/notification health is tracked separately from Recon baseline validity;
* resuming the same run keeps its working state and does not restore;
* an unsafe legacy database is re-baselined instead of guessing through state
  that may already have been overwritten by a failed run.

The mutable comparison view still checkpoints the four core tables that
directly participate in baseline comparisons: assets, DNS records, URLs, and
HTTP fingerprints. Derived Recon sets that should not be restored into mutable
core tables (for example source-map sources and JavaScript chunk references)
use a separate prepare/promote boundary in the same successful-run contract.
"""

import sys
from pathlib import Path
from typing import Any, Mapping

from core import Database as BaseDatabase
from core import TargetPolicy, json_dumps, safe_json_loads, sha256_text, utc_now
from finding_notifications import (
    ensure_finding_notification_schema,
    install_finding_notification_pipeline,
)
from run_lifecycle_state import (
    baseline_commit_eligible,
    begin_target_lifecycle,
    ensure_lifecycle_schema,
    has_established_baseline,
    lifecycle_record,
    mark_baseline_committed,
    mark_baseline_not_committed,
)
from stable_confirmation import (
    discard_stale_stable_change_runs,
    ensure_stable_confirmation_schema,
    finalize_stable_change_run,
    install_stable_confirmation,
)


SNAPSHOT_SCHEMA_VERSION = 2
BOOTSTRAP_META_KEY = "successful_snapshot_bootstrap_v1"
TRACKED_TABLES = ("assets", "dns_records", "urls", "fingerprints")


class SuccessfulSnapshotDatabase(BaseDatabase):
    """Database with explicit successful comparison and confirmation boundaries."""

    def __init__(self, path: Path):
        super().__init__(path)
        self._migrate_successful_snapshot_schema()
        ensure_lifecycle_schema(self)
        ensure_stable_confirmation_schema(self)
        ensure_finding_notification_schema(self)

    def _migrate_successful_snapshot_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS successful_recon_commits (
              target TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              committed_at TEXT NOT NULL,
              bootstrap INTEGER NOT NULL DEFAULT 0,
              table_count INTEGER NOT NULL DEFAULT 0,
              row_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS successful_recon_state (
              target TEXT NOT NULL,
              table_name TEXT NOT NULL,
              row_hash TEXT NOT NULL,
              row_json TEXT NOT NULL,
              committed_run_id TEXT NOT NULL,
              committed_at TEXT NOT NULL,
              PRIMARY KEY(target,table_name,row_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_successful_recon_state_target_table
              ON successful_recon_state(target,table_name);

            CREATE TABLE IF NOT EXISTS successful_recon_derived_sets (
              target TEXT NOT NULL,
              state_type TEXT NOT NULL,
              committed_run_id TEXT NOT NULL,
              committed_at TEXT NOT NULL,
              row_count INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(target,state_type)
            );
            CREATE TABLE IF NOT EXISTS successful_recon_derived_state (
              target TEXT NOT NULL,
              state_type TEXT NOT NULL,
              item_key TEXT NOT NULL,
              item_hash TEXT NOT NULL,
              item_json TEXT NOT NULL,
              committed_run_id TEXT NOT NULL,
              committed_at TEXT NOT NULL,
              PRIMARY KEY(target,state_type,item_key)
            );
            CREATE INDEX IF NOT EXISTS idx_successful_recon_derived_state_target_type
              ON successful_recon_derived_state(target,state_type);

            CREATE TABLE IF NOT EXISTS working_recon_derived_sets (
              run_id TEXT NOT NULL,
              target TEXT NOT NULL,
              state_type TEXT NOT NULL,
              row_count INTEGER NOT NULL DEFAULT 0,
              prepared_at TEXT NOT NULL,
              PRIMARY KEY(run_id,target,state_type)
            );
            CREATE TABLE IF NOT EXISTS working_recon_derived_state (
              run_id TEXT NOT NULL,
              target TEXT NOT NULL,
              state_type TEXT NOT NULL,
              item_key TEXT NOT NULL,
              item_hash TEXT NOT NULL,
              item_json TEXT NOT NULL,
              PRIMARY KEY(run_id,target,state_type,item_key)
            );
            CREATE INDEX IF NOT EXISTS idx_working_recon_derived_state_run_target
              ON working_recon_derived_state(run_id,target,state_type);
            """
        )
        self.execute(
            "INSERT INTO schema_meta(key,value) "
            "VALUES('successful_snapshot_schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SNAPSHOT_SCHEMA_VERSION),),
        )

        marker = self.one(
            "SELECT value FROM schema_meta WHERE key=?",
            (BOOTSTRAP_META_KEY,),
        )
        if marker is not None:
            return

        # Compatibility bootstrap is intentionally conservative. The current
        # mutable rows are trustworthy only when the target's latest execution
        # itself completed successfully and has no explicit failed/interrupted
        # stage. If the latest execution is partial/failed/running (or report
        # explicitly failed), we do not fabricate a canonical snapshot. The
        # next run will be an alert-silent re-baseline and establish one safely.
        targets = self.all(
            "SELECT DISTINCT target FROM run_targets ORDER BY target"
        )
        for target_row in targets:
            target = str(target_row["target"])
            latest = self.one(
                "SELECT run_id,status FROM run_targets WHERE target=? "
                "ORDER BY COALESCE(finished_at,started_at) DESC,rowid DESC "
                "LIMIT 1",
                (target,),
            )
            if latest is None or str(latest["status"]) != "success":
                continue
            run_id = str(latest["run_id"])
            if not self._run_is_snapshot_safe(run_id, target, allow_missing_report=True):
                continue
            with self.transaction():
                self._replace_successful_snapshot_no_tx(
                    target,
                    run_id,
                    bootstrap=True,
                )

        self.execute(
            "INSERT INTO schema_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (BOOTSTRAP_META_KEY, utc_now()),
        )

    def _run_is_snapshot_safe(
        self,
        run_id: str,
        target: str,
        *,
        allow_missing_report: bool,
    ) -> bool:
        failed_stage = self.one(
            "SELECT 1 FROM stage_runs WHERE run_id=? AND target=? "
            "AND status IN ('failed','interrupted') LIMIT 1",
            (run_id, target),
        )
        if failed_stage is not None:
            return False
        report_status = self.stage_status(run_id, target, "report")
        if report_status is None:
            return allow_missing_report
        return report_status == "success"

    def target_has_history(self, target: str) -> bool:
        # Baseline/history eligibility is now explicit and independent from the
        # aggregate run_targets status. The baseline registry is initialized
        # from previously trusted successful_recon_commits during migration.
        return has_established_baseline(self, target)

    def _table_columns(self, table_name: str) -> list[str]:
        if table_name not in TRACKED_TABLES:
            raise ValueError(f"Unsupported snapshot table: {table_name}")
        return [
            str(row[1])
            for row in self.all(f'PRAGMA table_info("{table_name}")')
        ]

    @staticmethod
    def _row_payload(row: Any) -> dict[str, Any]:
        return {str(key): row[key] for key in row.keys()}

    def _replace_successful_snapshot_no_tx(
        self,
        target: str,
        run_id: str,
        *,
        bootstrap: bool = False,
    ) -> dict[str, int]:
        now = utc_now()
        total_rows = 0
        self.execute(
            "DELETE FROM successful_recon_state WHERE target=?",
            (target,),
        )
        for table_name in TRACKED_TABLES:
            rows = self.all(
                f'SELECT * FROM "{table_name}" WHERE target=?',
                (target,),
            )
            for row in rows:
                row_json = json_dumps(self._row_payload(row))
                self.execute(
                    "INSERT INTO successful_recon_state("
                    "target,table_name,row_hash,row_json,committed_run_id,committed_at"
                    ") VALUES(?,?,?,?,?,?)",
                    (
                        target,
                        table_name,
                        sha256_text(row_json),
                        row_json,
                        run_id,
                        now,
                    ),
                )
                total_rows += 1
        self.execute(
            "INSERT INTO successful_recon_commits("
            "target,run_id,committed_at,bootstrap,table_count,row_count"
            ") VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(target) DO UPDATE SET "
            "run_id=excluded.run_id,committed_at=excluded.committed_at,"
            "bootstrap=excluded.bootstrap,table_count=excluded.table_count,"
            "row_count=excluded.row_count",
            (
                target,
                run_id,
                now,
                int(bootstrap),
                len(TRACKED_TABLES),
                total_rows,
            ),
        )
        return {"tables": len(TRACKED_TABLES), "rows": total_rows}

    def _restore_successful_snapshot_no_tx(self, target: str) -> dict[str, int]:
        commit = self.one(
            "SELECT run_id FROM successful_recon_commits WHERE target=?",
            (target,),
        )
        restored_rows = 0

        # Clear the target's mutable comparison view first. If no committed
        # snapshot exists, the clean view is intentional: prior failed-only
        # observations must not become the reference for this run.
        for table_name in TRACKED_TABLES:
            self.execute(f'DELETE FROM "{table_name}" WHERE target=?', (target,))
            if commit is None:
                continue
            columns_allowed = self._table_columns(table_name)
            snapshot_rows = self.all(
                "SELECT row_json FROM successful_recon_state "
                "WHERE target=? AND table_name=? ORDER BY row_hash",
                (target, table_name),
            )
            for snapshot_row in snapshot_rows:
                payload = safe_json_loads(
                    snapshot_row["row_json"], {}, expected_type=dict
                )
                if str(payload.get("target") or "") != target:
                    raise RuntimeError(
                        f"Snapshot target mismatch for {target}/{table_name}"
                    )
                columns = [c for c in columns_allowed if c in payload]
                if "target" not in columns:
                    raise RuntimeError(
                        f"Snapshot row lacks target for {target}/{table_name}"
                    )
                placeholders = ",".join("?" for _ in columns)
                quoted = ",".join(f'"{column}"' for column in columns)
                self.execute(
                    f'INSERT INTO "{table_name}"({quoted}) VALUES({placeholders})',
                    [payload[column] for column in columns],
                )
                restored_rows += 1
        return {
            "tables": len(TRACKED_TABLES),
            "rows": restored_rows,
            "has_snapshot": int(commit is not None),
        }

    def replace_recon_derived_working_state(
        self,
        run_id: str,
        target: str,
        state_type: str,
        items: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Prepare one complete derived Recon set and diff it against the last successful set."""
        normalized_type = str(state_type or "").strip()
        if not normalized_type or len(normalized_type) > 100:
            raise ValueError("Invalid derived Recon state type")
        if len(items) > 50000:
            raise ValueError("Derived Recon state exceeds the 50000-item safety limit")

        current: dict[str, dict[str, Any]] = {}
        for raw_key, raw_payload in items.items():
            item_key = str(raw_key or "").strip()
            if not item_key or len(item_key) > 2000:
                raise ValueError("Invalid derived Recon item key")
            payload = dict(raw_payload)
            current[item_key] = payload

        baseline_set = self.one(
            "SELECT committed_run_id FROM successful_recon_derived_sets "
            "WHERE target=? AND state_type=?",
            (target, normalized_type),
        )
        previous_rows = self.all(
            "SELECT item_key,item_hash,item_json FROM successful_recon_derived_state "
            "WHERE target=? AND state_type=? ORDER BY item_key",
            (target, normalized_type),
        )
        previous: dict[str, tuple[str, dict[str, Any]]] = {}
        for row in previous_rows:
            payload = safe_json_loads(row["item_json"], {}, expected_type=dict)
            previous[str(row["item_key"])] = (str(row["item_hash"]), payload)

        now = utc_now()
        with self.transaction():
            self.execute(
                "DELETE FROM working_recon_derived_state "
                "WHERE run_id=? AND target=? AND state_type=?",
                (run_id, target, normalized_type),
            )
            self.execute(
                "INSERT INTO working_recon_derived_sets("
                "run_id,target,state_type,row_count,prepared_at"
                ") VALUES(?,?,?,?,?) "
                "ON CONFLICT(run_id,target,state_type) DO UPDATE SET "
                "row_count=excluded.row_count,prepared_at=excluded.prepared_at",
                (run_id, target, normalized_type, len(current), now),
            )
            for item_key in sorted(current):
                item_json = json_dumps(current[item_key])
                self.execute(
                    "INSERT INTO working_recon_derived_state("
                    "run_id,target,state_type,item_key,item_hash,item_json"
                    ") VALUES(?,?,?,?,?,?)",
                    (
                        run_id,
                        target,
                        normalized_type,
                        item_key,
                        sha256_text(item_json),
                        item_json,
                    ),
                )

        baseline_exists = baseline_set is not None
        if not baseline_exists:
            return {
                "state_type": normalized_type,
                "baseline_exists": False,
                "baseline_run_id": "",
                "current_count": len(current),
                "added": [],
                "removed": [],
                "changed": [],
            }

        added: list[dict[str, Any]] = []
        removed: list[dict[str, Any]] = []
        changed: list[dict[str, Any]] = []
        for item_key in sorted(set(current) - set(previous)):
            added.append({"item_key": item_key, "after": current[item_key]})
        for item_key in sorted(set(previous) - set(current)):
            removed.append({"item_key": item_key, "before": previous[item_key][1]})
        for item_key in sorted(set(current) & set(previous)):
            item_json = json_dumps(current[item_key])
            item_hash = sha256_text(item_json)
            if item_hash != previous[item_key][0]:
                changed.append(
                    {
                        "item_key": item_key,
                        "before": previous[item_key][1],
                        "after": current[item_key],
                    }
                )

        return {
            "state_type": normalized_type,
            "baseline_exists": True,
            "baseline_run_id": str(baseline_set["committed_run_id"]),
            "current_count": len(current),
            "added": added,
            "removed": removed,
            "changed": changed,
        }

    def _discard_derived_working_state_no_tx(self, run_id: str, target: str) -> None:
        self.execute(
            "DELETE FROM working_recon_derived_state WHERE run_id=? AND target=?",
            (run_id, target),
        )
        self.execute(
            "DELETE FROM working_recon_derived_sets WHERE run_id=? AND target=?",
            (run_id, target),
        )

    def _promote_derived_working_state_no_tx(self, run_id: str, target: str) -> dict[str, int]:
        sets = self.all(
            "SELECT state_type,row_count FROM working_recon_derived_sets "
            "WHERE run_id=? AND target=? ORDER BY state_type",
            (run_id, target),
        )
        now = utc_now()
        promoted_rows = 0
        for set_row in sets:
            state_type = str(set_row["state_type"])
            self.execute(
                "DELETE FROM successful_recon_derived_state "
                "WHERE target=? AND state_type=?",
                (target, state_type),
            )
            rows = self.all(
                "SELECT item_key,item_hash,item_json FROM working_recon_derived_state "
                "WHERE run_id=? AND target=? AND state_type=? ORDER BY item_key",
                (run_id, target, state_type),
            )
            for row in rows:
                self.execute(
                    "INSERT INTO successful_recon_derived_state("
                    "target,state_type,item_key,item_hash,item_json,committed_run_id,committed_at"
                    ") VALUES(?,?,?,?,?,?,?)",
                    (
                        target,
                        state_type,
                        str(row["item_key"]),
                        str(row["item_hash"]),
                        str(row["item_json"]),
                        run_id,
                        now,
                    ),
                )
                promoted_rows += 1
            self.execute(
                "INSERT INTO successful_recon_derived_sets("
                "target,state_type,committed_run_id,committed_at,row_count"
                ") VALUES(?,?,?,?,?) "
                "ON CONFLICT(target,state_type) DO UPDATE SET "
                "committed_run_id=excluded.committed_run_id,"
                "committed_at=excluded.committed_at,row_count=excluded.row_count",
                (target, state_type, run_id, now, len(rows)),
            )
        self._discard_derived_working_state_no_tx(run_id, target)
        return {"sets": len(sets), "rows": promoted_rows}

    def successful_snapshot_status(self, target: str) -> dict[str, Any]:
        row = self.one(
            "SELECT target,run_id,committed_at,bootstrap,table_count,row_count "
            "FROM successful_recon_commits WHERE target=?",
            (target,),
        )
        derived = self.one(
            "SELECT COUNT(*) AS set_count,COALESCE(SUM(row_count),0) AS row_count "
            "FROM successful_recon_derived_sets WHERE target=?",
            (target,),
        )
        derived_set_count = int(derived["set_count"] or 0) if derived else 0
        derived_row_count = int(derived["row_count"] or 0) if derived else 0
        if row is None:
            return {
                "target": target,
                "exists": False,
                "run_id": "",
                "bootstrap": False,
                "table_count": 0,
                "row_count": 0,
                "derived_set_count": derived_set_count,
                "derived_row_count": derived_row_count,
            }
        return {
            "target": target,
            "exists": True,
            "run_id": str(row["run_id"]),
            "committed_at": str(row["committed_at"]),
            "bootstrap": bool(row["bootstrap"]),
            "table_count": int(row["table_count"]),
            "row_count": int(row["row_count"]),
            "derived_set_count": derived_set_count,
            "derived_row_count": derived_row_count,
        }

    def create_run_target(
        self,
        run_id: str,
        policy: TargetPolicy,
        run_dir: Path,
        baseline: bool,
    ) -> None:
        existing = self.one(
            "SELECT 1 FROM run_targets WHERE run_id=? AND target=?",
            (run_id, policy.name),
        )
        if existing is not None:
            # Resume/re-entry of the same run keeps completed-stage working
            # state. A restore here would erase progress from that same run.
            begin_target_lifecycle(self, run_id, policy.name)
            return super().create_run_target(run_id, policy, run_dir, baseline)
        with self.transaction():
            discard_stale_stable_change_runs(self, policy.name, run_id)
            self.execute(
                "DELETE FROM working_recon_derived_state WHERE target=?",
                (policy.name,),
            )
            self.execute(
                "DELETE FROM working_recon_derived_sets WHERE target=?",
                (policy.name,),
            )
            self._restore_successful_snapshot_no_tx(policy.name)
            super().create_run_target(run_id, policy, run_dir, baseline)
        begin_target_lifecycle(self, run_id, policy.name)

    def _snapshot_commit_ready(
        self,
        run_id: str,
        target: str,
        status: str,
    ) -> bool:
        if status != "success":
            return False
        return self._run_is_snapshot_safe(
            run_id,
            target,
            allow_missing_report=True,
        )

    def finish_run_target(self, run_id: str, target: str, status: str) -> None:
        explicit_eligibility = baseline_commit_eligible(self, run_id, target)
        if explicit_eligibility is None:
            # Compatibility for synthetic/maintenance callers that finalize a
            # target without going through the explicit lifecycle recorder.
            commit_ready = self._snapshot_commit_ready(run_id, target, status)
        else:
            commit_ready = explicit_eligibility

        lifecycle = lifecycle_record(self, run_id, target)
        reason = str((lifecycle or {}).get("baseline_reason") or "collection_complete")
        confirmation_status = "success" if commit_ready else "failed"

        with self.transaction():
            # Stable change confirmation tracks trusted Recon observations, so
            # it follows collection/baseline eligibility rather than report or
            # notification side effects.
            finalize_stable_change_run(
                self,
                run_id,
                target,
                confirmation_status,
            )
            if commit_ready:
                self._replace_successful_snapshot_no_tx(
                    target, run_id, bootstrap=False
                )
                self._promote_derived_working_state_no_tx(run_id, target)
                if lifecycle is not None:
                    mark_baseline_committed(self, run_id, target, reason)
            else:
                self._discard_derived_working_state_no_tx(run_id, target)
                if lifecycle is not None:
                    mark_baseline_not_committed(self, run_id, target, reason)
            super().finish_run_target(run_id, target, status)


def _install_runtime_reliability_guards() -> None:
    """Attach lifecycle, confirmation, and finding notification semantics."""

    runtime = sys.modules.get("recon_monitor_core")
    if runtime is None or not hasattr(runtime, "Orchestrator"):
        return
    from lifecycle_status import install_lifecycle_status_guard

    install_lifecycle_status_guard(vars(runtime))
    install_stable_confirmation()
    install_finding_notification_pipeline()


_install_runtime_reliability_guards()
