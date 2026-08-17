from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import AppPaths, Database
from product_platform import (
    engine_quality_snapshot,
    invalidate_platform_cache,
    list_cases,
    operations_center,
    run_completeness_snapshot,
    storage_health_snapshot,
)


class DashboardPerformanceV501Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = AppPaths.from_root(self.root)
        self.paths.ensure()
        self.paths.config.write_text("", encoding="utf-8")
        self.paths.policy.write_text('{"schema":1,"defaults":{},"targets":[]}', encoding="utf-8")
        self.db = Database(self.paths.db)
        invalidate_platform_cache()

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def test_quality_snapshot_avoids_full_recalculation(self) -> None:
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json,error) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("A1", "R1", "example.com", "5.0.0", "v", "balanced", "success", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "{}", None),
        )
        payload = {"health_score": 91, "warnings": [], "families": {}, "rules": [], "parsers": []}
        self.db.execute(
            "INSERT INTO engine_quality_snapshots(analysis_id,target,health_score,metrics_json,created_at) VALUES(?,?,?,?,?)",
            ("A1", "example.com", 91, json.dumps(payload), "2026-01-01T00:02:00Z"),
        )
        with mock.patch("product_platform.engine_quality", side_effect=AssertionError("full scan should not run")):
            result = engine_quality_snapshot(self.db, "A1", "example.com")
        self.assertEqual(result["health_score"], 91)
        self.assertEqual(result["snapshot_source"], "persisted")

    def test_operations_normal_view_skips_deep_integrity_checks(self) -> None:
        with mock.patch.object(self.db, "integrity", side_effect=AssertionError("integrity scan should be explicit")), mock.patch.object(
            self.db, "foreign_key_violations", side_effect=AssertionError("FK scan should be explicit")
        ):
            result = operations_center(self.paths, self.db, refresh=False, deep_check=False)
        self.assertEqual(result["database"]["integrity_check"], "not_run")

    def test_case_pagination_is_bounded(self) -> None:
        for index in range(120):
            self.db.execute(
                "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"C{index}", f"K{index}", "A", "R", "example.com", f"Case {index}", "summary", "family", index % 100, "new", "", "unknown", 0, "2026-01-01", "2026-01-01"),
            )
        first = list_cases(self.db, limit=50, offset=0)
        third = list_cases(self.db, limit=50, offset=100)
        self.assertEqual(len(first), 50)
        self.assertEqual(len(third), 20)
        self.assertNotEqual(first[0]["case_id"], third[0]["case_id"])

    def test_run_and_storage_snapshots_are_reused(self) -> None:
        self.db.execute("INSERT INTO runs(id,version,status,started_at,target_count) VALUES('R1','5.1.0','success','2026-01-01',1)")
        run_payload = {"run_id": "R1", "score": 88, "dimensions": {}, "warnings": []}
        self.db.execute("INSERT INTO run_completeness(run_id,score,metrics_json,created_at) VALUES(?,?,?,?)", ("R1", 88, json.dumps(run_payload), "2026-01-01"))
        storage_payload = {"estimated_total_bytes": 1234, "retention_preview": {}}
        self.db.execute("INSERT INTO storage_snapshots(metrics_json,created_at) VALUES(?,?)", (json.dumps(storage_payload), "2026-01-01"))
        with mock.patch("product_platform.run_completeness", side_effect=AssertionError("recompute should not run")):
            self.assertEqual(run_completeness_snapshot(self.db, "R1")["score"], 88)
        with mock.patch("product_platform.storage_health", side_effect=AssertionError("tree scan should not run")):
            self.assertEqual(storage_health_snapshot(self.paths, self.db)["estimated_total_bytes"], 1234)

    def test_dashboard_listener_binds_before_startup_diagnostics(self) -> None:
        app = Path(__file__).parents[1].joinpath("app")
        source = app.joinpath("dashboard_core.py").read_text(encoding="utf-8")
        serve = source[source.index("def serve_dashboard"): ]
        self.assertLess(serve.index("server = ThreadingHTTPServer"), serve.index("operator_diagnostics("))
        self.assertIn("threading.Thread(", serve)
        self.assertIn('name="dashboard-startup-self-check"', serve)

    def test_live_analysis_progress_defers_deep_intelligence(self) -> None:
        app = Path(__file__).parents[1].joinpath("app")
        source = app.joinpath("progress_tracking.py").read_text(encoding="utf-8")
        self.assertIn('getattr(dash, "_ORIGINAL_ANALYSIS_ENGINE", None)', source)
        self.assertIn("Deep vulnerability-intelligence correlation is deferred", source)
        self.assertIn("10000", source)

    def test_analysis_summary_never_builds_investigation_queue(self) -> None:
        app = Path(__file__).parents[1].joinpath("app")
        wrapper = app.joinpath("dashboard.py").read_text(encoding="utf-8")
        start = wrapper.index("def _analysis_engine_with_intelligence")
        end = wrapper.index("def _bug_candidates_with_queue")
        renderer = wrapper[start:end]
        self.assertNotIn("_latest_analysis_queue(", renderer)
        self.assertNotIn("investigation_queue(", renderer)
        self.assertIn("Fast Analysis summary", renderer)
        self.assertIn("/potential-findings#investigation-queue", renderer)

    def test_dashboard_pid_file_is_identity_and_port_checked(self) -> None:
        app = Path(__file__).parents[1].joinpath("app")
        source = app.joinpath("dashboard_service.py").read_text(encoding="utf-8")
        self.assertIn("def _dashboard_process_info", source)
        self.assertIn('tail[0:2] != ["dashboard", "foreground"]', source)
        self.assertIn("Dashboard is already running (PID", source)
        self.assertIn("requested http://{host}:{port}", source)
        self.assertIn("but is not accepting connections", source)
        stop = source[source.index("def stop_dashboard"):source.index("def restart_dashboard")]
        self.assertIn("_dashboard_process_info(paths, pid)", stop)

    def test_dashboard_get_routes_do_not_implicitly_sync_cases(self) -> None:
        app = Path(__file__).parents[1].joinpath("app")
        wrapper_source = app.joinpath("dashboard.py").read_text(encoding="utf-8")
        source = app.joinpath("dashboard_core.py").read_text(encoding="utf-8")
        overview = source[source.index("    def overview"):source.index("    def workbench")]
        cases = source[source.index("    def cases_page"):source.index("    def case_page")]
        stories = source[source.index("    def security_stories_page"):source.index("    def scope_center_page")]
        self.assertNotIn("sync_security_cases(db)", wrapper_source)
        self.assertNotIn("sync_security_stories(db)", wrapper_source)
        self.assertNotIn("sync_security_cases(db)", overview)
        self.assertNotIn("sync_security_cases(db)", cases)
        self.assertNotIn("sync_security_stories(db)", stories)


if __name__ == "__main__":
    unittest.main()
