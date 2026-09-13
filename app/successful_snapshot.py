from __future__ import annotations

"""Successful-run comparison snapshots for Recon Monitor.

Collection stages intentionally keep using the established mutable tables during
an in-progress run so resume and Analysis behavior remain compatible. This
module adds a commit boundary around the comparison state that drives "new" and
"changed" decisions:

* a new run restores the last committed successful snapshot before collection;
* failed/interrupted runs may mutate the working tables, but those mutations are
  never promoted to the committed snapshot;
* a successful target run replaces the committed snapshot atomically;
* resuming the same run does not restore, so already-completed stage state stays
  available to the resume path.

Only the four comparison-critical tables covered by this first reliability
phase are checkpointed: assets, DNS records, URLs, and HTTP fingerprints.
"""

from pathlib import Path
from typing import Any

from core import Database as BaseDatabase
from core import TargetPolicy, json_dumps, safe_json_loads, sha256_text, utc_now


SNAPSHOT_SCHEMA_VERSION = 1
BOOTSTRAP_META_KEY = "successful_snapshot_bootstrap_v1"

# Deliberately narrow for the first reliability phase. These are the shared
# tables directly responsible for the failed-run contamination bug that can
# suppress new/change detection on the next scan.
TRACKED_TABLES = (
    "assets",
    "dns_records",
    "urls",
    "fingerprints",
)


class SuccessfulSnapshotDatabase(BaseDatabase):
    """Database with an explicit last-successful comparison-state boundary."""

    def __init__(self, path: Path):
        super().__init__(path)
        self._migrate_successful_snapshot_schema()

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
            """
        )
        self.execute(
            "INSERT INTO schema_meta(key,value) VALUES('successful_snapshot_schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SNAPSHOT_SCHEMA_VERSION),),
        )

        # One-time compatibility bootstrap for databases that already had
        # successful runs before this boundary existed. Preserve their current
        # comparison view rather than generating a surprise re-alert storm.
        # Failed-only targets are intentionally not bootstrapped.
        marker = self.one(
            "SELECT value FROM schema_meta WHERE key=?",
            (BOOTSTRAP_META_KEY,),
        )
        if marker is not None:
            return

        latest_by_target: dict[str, str] = {}
        for row in self.all(
            "SELECT target,run_id FROM run_targets WHERE status='success' "
            "ORDER BY target,COALESCE(finished_at,started_at) DESC,run_id DESC"
        ):
            target = str(row["target"])
            if target not in latest_by_target:
                latest_by_target[target] = str(row["run_id"])

        for target, run_id in latest_by_target.items():
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
                payload = self._row_payload(row)
                row_json = json_dumps(payload)
                row_hash = sha256_text(row_json)
                self.execute(
                    "INSERT INTO successful_recon_state("
                    "target,table_name,row_hash,row_json,committed_run_id,committed_at"
                    ") VALUES(?,?,?,?,?,?)",
                    (
                        target,
                        table_name,
                        row_hash,
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

        # Clearing happens even when no committed snapshot exists. This is the
        # key first-baseline behavior: rows left by a failed attempt must not be
        # treated as the baseline of a later run.
        for table_name in TRACKED_TABLES:
            self.execute(
                f'DELETE FROM "{table_name}" WHERE target=?',
                (target,),
            )

            if commit is None:
                continue

            allowed_columns = self._table_columns(table_name)
            snapshot_rows = self.all(
                "SELECT row_json FROM successful_recon_state "
                "WHERE target=? AND table_name=? ORDER BY row_hash",
                (target, table_name),
            )
            for snapshot_row in snapshot_rows:
                payload = safe_json_loads(
                    snapshot_row["row_json"],
                    {},
                    expected_type=dict,
                )
                if str(payload.get("target") or "") != target:
                    raise RuntimeError(
                        f"Snapshot target mismatch for {target}/{table_name}"
                    )

                columns = [
                    column
                    for column in allowed_columns
                    if column in payload
                ]
                if "target" not in columns:
                    raise RuntimeError(
                        f"Snapshot row lacks target for {target}/{table_name}"
                    )
                placeholders = ",".join("?" for _ in columns)
                quoted = ",".join(f'"{column}"' for column in columns)
                values = [payload[column] for column in columns]
                self.execute(
                    f'INSERT INTO "{table_name}"({quoted}) '
                    f"VALUES({placeholders})",
                    values,
                )
                restored_rows += 1

        return {
            "tables": len(TRACKED_TABLES),
            "rows": restored_rows,
            "has_snapshot": int(commit is not None),
        }

    def successful_snapshot_status(self, target: str) -> dict[str, Any]:
        row = self.one(
            "SELECT target,run_id,committed_at,bootstrap,table_count,row_count "
            "FROM successful_recon_commits WHERE target=?",
            (target,),
        )
        if row is None:
            return {
                "target": target,
                "exists": False,
                "run_id": "",
                "bootstrap": False,
                "table_count": 0,
                "row_count": 0,
            }
        return {
            "target": target,
            "exists": True,
            "run_id": str(row["run_id"]),
            "committed_at": str(row["committed_at"]),
            "bootstrap": bool(row["bootstrap"]),
            "table_count": int(row["table_count"]),
            "row_count": int(row["row_count"]),
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
            # Resume/re-entry of the same run must keep its working state.
            return super().create_run_target(
                run_id,
                policy,
                run_dir,
                baseline,
            )

        with self.transaction():
            self._restore_successful_snapshot_no_tx(policy.name)
            super().create_run_target(
                run_id,
                policy,
                run_dir,
                baseline,
            )

    def _snapshot_commit_ready(
        self,
        run_id: str,
        target: str,
        status: str,
    ) -> bool:
        if status != "success":
            return False

        failed_stage = self.one(
            "SELECT 1 FROM stage_runs "
            "WHERE run_id=? AND target=? "
            "AND status IN ('failed','interrupted') LIMIT 1",
            (run_id, target),
        )
        if failed_stage is not None:
            return False

        # Production runs always execute report. Keeping None compatible lets
        # existing maintenance/tests that directly finalize a synthetic target
        # continue to work, while an explicit report failure can never commit.
        report_status = self.stage_status(run_id, target, "report")
        return report_status in {None, "success"}

    def finish_run_target(
        self,
        run_id: str,
        target: str,
        status: str,
    ) -> None:
        commit_ready = self._snapshot_commit_ready(
            run_id,
            target,
            status,
        )
        with self.transaction():
            if commit_ready:
                self._replace_successful_snapshot_no_tx(
                    target,
                    run_id,
                    bootstrap=False,
                )
            super().finish_run_target(run_id, target, status)
