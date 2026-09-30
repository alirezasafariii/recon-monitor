from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Database, utc_now
from dashboard import DashboardHandler, _layout


class RunReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.tmp.name))
        self.paths.ensure()
        db = Database(self.paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count,error) "
            "VALUES(?,?,?,?,?,?,?,?)",
            ("R1", "test", "success", now, now, "example.test", 1, None),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES(?,?,?,?,?,?,?,?,0)",
            ("R1", "example.test", "test", "success", "report", now, now, str(self.paths.output / "R1")),
        )
        db.execute(
            "INSERT INTO stage_runs(run_id,target,stage,status,attempt,started_at,metrics_json,duration_seconds,exit_code) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("R1", "example.test", "urls", "partial", 1, now,
             json.dumps({"urls": 119, "collection_status": "partial",
                         "katana_status": "timeout", "katana_exit_code": 124,
                         "katana_timed_out": True}), 120.0, 0),
        )
        db.execute(
            "INSERT INTO stage_runs(run_id,target,stage,status,attempt,started_at,metrics_json,duration_seconds,exit_code) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("R1", "example.test", "javascript", "success", 1, now,
             json.dumps({"files": 0, "downloaded": 0,
                         "collection_status": "no_input"}), 0.01, 0),
        )
        db.close()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def handler(self, run_id: str) -> tuple[DashboardHandler, dict]:
        handler = object.__new__(DashboardHandler)
        handler.paths = self.paths
        handler.db_path = self.paths.db
        handler.path = "/run-review"
        handler.query = lambda: {"id": [run_id]}
        result = {}
        handler.send_html = lambda title, body, status=200: result.update(
            title=title, body=body, status=status,
        )
        return handler, result

    def test_successful_run_can_show_partial_katana_and_no_js_input(self) -> None:
        handler, captured = self.handler("R1")
        handler.run_review()
        body = str(captured["body"])
        self.assertEqual(captured["status"], 200)
        self.assertIn("Run finished; 1 collection stage(s) incomplete", body)
        self.assertIn("Katana: timeout", body)
        self.assertIn("No input", body)
        self.assertIn("zero findings is not proof", body)
        self.assertIn("<details", body)

    def test_unknown_run_returns_404(self) -> None:
        handler, captured = self.handler("missing")
        handler.run_review()
        self.assertEqual(captured["status"], 404)

    def test_same_page_navigation_preserves_scroll(self) -> None:
        page = _layout("Run review", "<p>Example</p>", current_path="/run-review")
        self.assertIn("recon-same-page-scroll", page)
        self.assertIn("window.scrollTo(0,saved.y)", page)
        self.assertIn("next.pathname===window.location.pathname", page)
        self.assertIn("event.target.closest('.content a[href]')", page)


if __name__ == "__main__":
    unittest.main()
