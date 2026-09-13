from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import recon_monitor_core
from core import APP_VERSION, AppPaths, Database as BaseDatabase, TargetPolicy, utc_now
from successful_snapshot import SuccessfulSnapshotDatabase


class SuccessfulSnapshotBoundaryTests(unittest.TestCase):
    TARGET = "example.test"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.db = SuccessfulSnapshotDatabase(self.paths.db)
        self.policy = TargetPolicy.from_dict(
            {"name": self.TARGET, "roots": [self.TARGET]}
        )

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _insert_run(self, run_id: str, status: str = "running") -> None:
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,target_selector,target_count) "
            "VALUES(?,?,?,?,?,1)",
            (run_id, APP_VERSION, status, now, self.TARGET),
        )

    def _start(self, run_id: str, *, baseline: bool = False) -> None:
        self._insert_run(run_id)
        run_dir = self.paths.output / self.TARGET / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        self.db.create_run_target(run_id, self.policy, run_dir, baseline)

    def test_runtime_cli_uses_snapshot_aware_database(self) -> None:
        self.assertIs(recon_monitor_core.Database, SuccessfulSnapshotDatabase)

    def test_failed_first_run_does_not_hide_new_asset_or_url(self) -> None:
        self._start("RUN-FAILED", baseline=True)
        self.assertTrue(
            self.db.upsert_asset(
                self.TARGET, "api.example.test", ["subfinder"], "RUN-FAILED"
            )
        )
        self.assertTrue(
            self.db.upsert_url(
                self.TARGET,
                "https://api.example.test/admin",
                "url",
                "katana",
                "RUN-FAILED",
            )
        )
        self.db.finish_run_target("RUN-FAILED", self.TARGET, "failed")
        self.assertFalse(self.db.target_has_history(self.TARGET))

        self._start("RUN-NEXT", baseline=True)
        self.assertTrue(
            self.db.upsert_asset(
                self.TARGET, "api.example.test", ["subfinder"], "RUN-NEXT"
            )
        )
        self.assertTrue(
            self.db.upsert_url(
                self.TARGET,
                "https://api.example.test/admin",
                "url",
                "katana",
                "RUN-NEXT",
            )
        )

    def test_successful_snapshot_is_reused_after_failed_run(self) -> None:
        self._start("RUN-GOOD-1", baseline=True)
        self.db.upsert_asset(
            self.TARGET, "stable.example.test", ["subfinder"], "RUN-GOOD-1"
        )
        self.db.finish_run_target("RUN-GOOD-1", self.TARGET, "success")
        self.assertTrue(self.db.target_has_history(self.TARGET))

        self._start("RUN-BAD-2")
        self.db.upsert_asset(
            self.TARGET, "failed-only.example.test", ["subfinder"], "RUN-BAD-2"
        )
        self.db.finish_run_target("RUN-BAD-2", self.TARGET, "failed")

        self._start("RUN-GOOD-3")
        self.assertIsNotNone(
            self.db.one(
                "SELECT 1 FROM assets WHERE target=? AND host=?",
                (self.TARGET, "stable.example.test"),
            )
        )
        self.assertIsNone(
            self.db.one(
                "SELECT 1 FROM assets WHERE target=? AND host=?",
                (self.TARGET, "failed-only.example.test"),
            )
        )
        self.assertTrue(
            self.db.upsert_asset(
                self.TARGET,
                "failed-only.example.test",
                ["subfinder"],
                "RUN-GOOD-3",
            )
        )

    def test_failed_fingerprint_change_is_not_next_baseline(self) -> None:
        url = "https://example.test/"
        self._start("RUN-FP-1", baseline=True)
        self.db.upsert_fingerprint(
            self.TARGET, url, {"status_code": 200, "title": "A"}, "hash-a", "RUN-FP-1"
        )
        self.db.finish_run_target("RUN-FP-1", self.TARGET, "success")

        self._start("RUN-FP-BAD")
        _new, changed, old = self.db.upsert_fingerprint(
            self.TARGET, url, {"status_code": 200, "title": "B"}, "hash-b", "RUN-FP-BAD"
        )
        self.assertTrue(changed)
        self.assertEqual(str(old["fingerprint_hash"]), "hash-a")
        self.db.finish_run_target("RUN-FP-BAD", self.TARGET, "failed")

        self._start("RUN-FP-3")
        _new, changed, old = self.db.upsert_fingerprint(
            self.TARGET, url, {"status_code": 200, "title": "B"}, "hash-b", "RUN-FP-3"
        )
        self.assertTrue(changed)
        self.assertEqual(str(old["fingerprint_hash"]), "hash-a")

    def test_failed_dns_rotation_is_not_next_baseline(self) -> None:
        host = "api.example.test"
        self._start("RUN-DNS-1", baseline=True)
        self.db.upsert_dns(self.TARGET, host, "A", "192.0.2.10", "RUN-DNS-1")
        self.db.finalize_dns_current(self.TARGET, "RUN-DNS-1", ["A"])
        self.db.finish_run_target("RUN-DNS-1", self.TARGET, "success")

        self._start("RUN-DNS-BAD")
        self.db.upsert_dns(self.TARGET, host, "A", "192.0.2.20", "RUN-DNS-BAD")
        self.db.finalize_dns_current(self.TARGET, "RUN-DNS-BAD", ["A"])
        self.db.finish_run_target("RUN-DNS-BAD", self.TARGET, "failed")

        self._start("RUN-DNS-3")
        rows = self.db.all(
            "SELECT value,is_current FROM dns_records "
            "WHERE target=? AND host=? AND rrtype='A' ORDER BY value",
            (self.TARGET, host),
        )
        self.assertEqual(
            [(str(row["value"]), int(row["is_current"])) for row in rows],
            [("192.0.2.10", 1)],
        )

    def test_explicit_report_failure_cannot_promote_snapshot(self) -> None:
        self._start("RUN-REPORT-1", baseline=True)
        self.db.upsert_asset(
            self.TARGET, "stable.example.test", ["subfinder"], "RUN-REPORT-1"
        )
        self.db.finish_run_target("RUN-REPORT-1", self.TARGET, "success")

        self._start("RUN-REPORT-BAD")
        self.db.upsert_asset(
            self.TARGET,
            "failed-only.example.test",
            ["subfinder"],
            "RUN-REPORT-BAD",
        )
        self.db.stage_begin("RUN-REPORT-BAD", self.TARGET, "report", 1)
        self.db.stage_finish(
            "RUN-REPORT-BAD",
            self.TARGET,
            "report",
            "failed",
            exit_code=1,
            error="synthetic report failure",
        )
        # Reproduce the current orchestrator bug: even if the caller asks to
        # finalize success, an explicit report failure must not move baseline.
        self.db.finish_run_target("RUN-REPORT-BAD", self.TARGET, "success")
        self.assertEqual(
            self.db.successful_snapshot_status(self.TARGET)["run_id"],
            "RUN-REPORT-1",
        )

        self._start("RUN-REPORT-NEXT")
        self.assertIsNone(
            self.db.one(
                "SELECT 1 FROM assets WHERE target=? AND host=?",
                (self.TARGET, "failed-only.example.test"),
            )
        )

    def test_unsafe_legacy_latest_run_forces_safe_rebaseline(self) -> None:
        # Build a pre-feature database: old success establishes history, then a
        # failed run contaminates the shared assets table.
        self.db.close()
        raw = BaseDatabase(self.paths.db)
        try:
            now = utc_now()
            raw.execute(
                "INSERT INTO runs(id,version,status,started_at,target_selector,target_count) "
                "VALUES('LEGACY-GOOD',?,'success',?,?,1)",
                (APP_VERSION, now, self.TARGET),
            )
            good_dir = self.paths.output / self.TARGET / "runs" / "LEGACY-GOOD"
            good_dir.mkdir(parents=True, exist_ok=True)
            raw.create_run_target("LEGACY-GOOD", self.policy, good_dir, True)
            raw.upsert_asset(
                self.TARGET, "stable.example.test", ["subfinder"], "LEGACY-GOOD"
            )
            raw.finish_run_target("LEGACY-GOOD", self.TARGET, "success")

            raw.execute(
                "INSERT INTO runs(id,version,status,started_at,target_selector,target_count) "
                "VALUES('LEGACY-BAD',?,'failed',?,?,1)",
                (APP_VERSION, now, self.TARGET),
            )
            bad_dir = self.paths.output / self.TARGET / "runs" / "LEGACY-BAD"
            bad_dir.mkdir(parents=True, exist_ok=True)
            raw.create_run_target("LEGACY-BAD", self.policy, bad_dir, False)
            raw.upsert_asset(
                self.TARGET, "polluted.example.test", ["subfinder"], "LEGACY-BAD"
            )
            raw.finish_run_target("LEGACY-BAD", self.TARGET, "failed")

            raw.execute("DROP TABLE IF EXISTS successful_recon_state")
            raw.execute("DROP TABLE IF EXISTS successful_recon_commits")
            raw.execute(
                "DELETE FROM schema_meta WHERE key IN (?,?)",
                ("successful_snapshot_schema_version", "successful_snapshot_bootstrap_v1"),
            )
        finally:
            raw.close()

        self.db = SuccessfulSnapshotDatabase(self.paths.db)
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertFalse(self.db.successful_snapshot_status(self.TARGET)["exists"])

        self._start("RUN-REBASELINE", baseline=True)
        self.assertIsNone(
            self.db.one(
                "SELECT 1 FROM assets WHERE target=? AND host=?",
                (self.TARGET, "polluted.example.test"),
            )
        )


if __name__ == "__main__":
    unittest.main()
