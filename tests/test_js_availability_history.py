from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import (
    Database,
    SCHEMA_VERSION,
    utc_now,
)


class JsAvailabilityHistoryTests(
    unittest.TestCase
):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

        self.db = Database(
            Path(self.temp.name)
            / "history.db"
        )


    def tearDown(self):
        self.db.close()
        self.temp.cleanup()


    def add_run(
        self,
        run_id,
        *,
        target_status="running",
    ):
        now = utc_now()

        self.db.execute(
            """
            INSERT INTO runs(
              id,
              version,
              status,
              started_at,
              target_count
            )
            VALUES(?,?,?,?,1)
            """,
            (
                run_id,
                "test",
                target_status,
                now,
            ),
        )

        self.db.execute(
            """
            INSERT INTO run_targets(
              run_id,
              target,
              policy_hash,
              status,
              started_at,
              run_dir,
              baseline
            )
            VALUES(?,?,?,?,?,?,0)
            """,
            (
                run_id,
                "example.test",
                "policy",
                target_status,
                now,
                self.temp.name,
            ),
        )


    def test_schema_version_and_table_exist(self):
        self.assertEqual(
            SCHEMA_VERSION,
            18,
        )

        row = self.db.one(
            """
            SELECT name
            FROM sqlite_master
            WHERE type='table'
              AND name='js_availability_history'
            """
        )

        self.assertIsNotNone(row)


    def test_live_to_not_found_uses_successful_prior_run(self):
        self.add_run(
            "run-1",
            target_status="success",
        )

        first = self.db.record_js_availability(
            "run-1",
            "example.test",
            "https://example.test/app.js",
            "live",
            status_code=200,
        )

        self.assertIsNone(
            first["previous"]
        )

        self.add_run(
            "run-2",
            target_status="running",
        )

        second = self.db.record_js_availability(
            "run-2",
            "example.test",
            "https://example.test/app.js",
            "not_found",
            status_code=404,
        )

        self.assertTrue(
            second["changed"]
        )

        self.assertEqual(
            second["previous"]["state"],
            "live",
        )

        self.assertEqual(
            second["previous"]["run_id"],
            "run-1",
        )


    def test_incomplete_prior_run_is_not_baseline(self):
        self.add_run(
            "run-bad",
            target_status="partial",
        )

        self.db.record_js_availability(
            "run-bad",
            "example.test",
            "https://example.test/app.js",
            "live",
            status_code=200,
        )

        self.add_run(
            "run-current",
            target_status="running",
        )

        result = self.db.record_js_availability(
            "run-current",
            "example.test",
            "https://example.test/app.js",
            "not_found",
            status_code=404,
        )

        self.assertIsNone(
            result["previous"]
        )

        self.assertFalse(
            result["changed"]
        )


    def test_same_run_is_upserted_not_duplicated(self):
        self.add_run(
            "run-current",
            target_status="running",
        )

        url = "https://example.test/app.js"

        self.db.record_js_availability(
            "run-current",
            "example.test",
            url,
            "live",
            status_code=200,
        )

        self.db.record_js_availability(
            "run-current",
            "example.test",
            url,
            "not_found",
            status_code=404,
        )

        row = self.db.one(
            """
            SELECT COUNT(*) AS count
            FROM js_availability_history
            WHERE run_id=?
              AND target=?
              AND url=?
            """,
            (
                "run-current",
                "example.test",
                url,
            ),
        )

        self.assertEqual(
            int(row["count"]),
            1,
        )

        current = self.db.one(
            """
            SELECT state,status_code
            FROM js_availability_history
            WHERE run_id=?
              AND target=?
              AND url=?
            """,
            (
                "run-current",
                "example.test",
                url,
            ),
        )

        self.assertEqual(
            current["state"],
            "not_found",
        )

        self.assertEqual(
            int(current["status_code"]),
            404,
        )


if __name__ == "__main__":
    unittest.main()
