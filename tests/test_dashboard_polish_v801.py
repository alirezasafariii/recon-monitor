from __future__ import annotations

import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Config, Database, Logger, ReconError
from dashboard import ADVANCED_NAV_SECTIONS, NAV_SECTIONS, _candidate_confidence_story, _command_decision_item, _layout, _recon_interest_score, _recon_security_categories, _recon_surface_items
from dashboard_service import _port_listener_details, start_dashboard


class DashboardPolishV801Tests(unittest.TestCase):
    def test_primary_sidebar_is_four_direct_workspaces(self) -> None:
        page = _layout("Recon", "<p>body</p>", current_path="/recon")
        self.assertIn("class='nav-item active' href='/recon'", page)
        self.assertIn("data-primary-workspace='1'", page)
        self.assertIn("03 · Potential Findings", page)
        self.assertIn("04 · Alerts", page)
        self.assertIn("<strong>System</strong>", page)
        self.assertNotIn("<div class='advanced-label'>Recon detail</div>", page)
        self.assertNotIn("<div class='advanced-label'>Analysis detail</div>", page)

    def test_candidate_confidence_is_explainable(self) -> None:
        html = _candidate_confidence_story({
            "calibrated_likelihood": 87,
            "evidence_strength": 78,
            "evidence_coverage": 72,
            "observation_quality": 84,
            "exploitability_confidence": 63,
            "supporting_evidence_json": json.dumps([{"text": "a"}, {"text": "b"}]),
            "contradicting_evidence_json": json.dumps([{"text": "c"}]),
            "missing_evidence_json": json.dumps(["identity comparison"]),
        })
        self.assertIn("Why this confidence?", html)
        self.assertIn("87%", html)
        self.assertIn("2 supporting · 1 contradicting · 1 missing", html)
        self.assertIn("not an additive formula", html)

    def test_port_conflict_is_explained_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = AppPaths.from_root(Path(tmp)); paths.ensure()
            paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
            paths.policy.write_text(json.dumps({"schema": 1, "defaults": {}, "targets": []}), encoding="utf-8")
            config = Config(paths); logger = Logger(paths, verbose=False)
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0)); listener.listen(1)
            port = listener.getsockname()[1]
            try:
                details = _port_listener_details("127.0.0.1", port)
                self.assertIsNotNone(details)
                with self.assertRaises(ReconError) as ctx:
                    start_dashboard(paths, config, logger, "127.0.0.1", port, False, False)
                message = str(ctx.exception)
                self.assertIn(str(port), message)
                self.assertIn("already in use", message)
                self.assertIn("--port", message)
            finally:
                listener.close()

    def test_command_center_remains_reachable_from_sidebar(self) -> None:
        page = _layout("Command Center", "<p>body</p>", current_path="/")
        self.assertIn("class='nav-item active' href='/' data-command-center='1'", page)
        self.assertIn("<strong>Command Center</strong>", page)
        self.assertIn("<small>Overview and decision inbox</small>", page)

    def test_command_center_v2_decision_item_is_actionable(self) -> None:
        html = _command_decision_item({
            "kind": "candidate", "eyebrow": "Potential finding", "title": "Review authorization boundary",
            "detail": "Compare two authorized test identities.", "href": "/bug-candidate?id=BC-1",
            "score": 91, "tone": "danger", "meta": "example.com · BOLA",
        }, 1)
        self.assertIn("data-decision-kind='candidate'", html)
        self.assertIn("Review authorization boundary", html)
        self.assertIn("91", html)
        self.assertIn("/bug-candidate?id=BC-1", html)

    def test_analysis_navigation_exposes_only_the_workspace(self) -> None:
        analysis = next(section for section in NAV_SECTIONS if section[0] == "analysis")
        paths = [href for href,_,_ in analysis[4]]
        self.assertEqual(paths, ["/analysis"])
        page = _layout("Security reasoning", "<p>body</p>", current_path="/security-reasoning")
        self.assertIn("class='nav-item active' href='/analysis'", page)
        self.assertNotIn("Security reasoning</span>", page)
        self.assertNotIn("Behavior changes</span>", page)

    def test_system_menu_has_no_workspace_route_duplicates(self) -> None:
        workspace_paths = {href for _,_,_,_,links in NAV_SECTIONS for href,_,_ in links}
        system_paths = {href for _,links in ADVANCED_NAV_SECTIONS for href,_,_ in links}
        self.assertFalse(workspace_paths & system_paths)
        self.assertNotIn('/assets', system_paths)
        self.assertNotIn('/cases', system_paths)
        self.assertNotIn('/change-intelligence', system_paths)

    def test_recon_security_categories_are_multilabel(self) -> None:
        labels = _recon_security_categories('endpoint', '/api/v2/admin/users/{id}/export', 'authenticated route')
        self.assertIn('apis', labels)
        self.assertIn('admin_internal', labels)
        self.assertIn('data_object', labels)
        self.assertIn('file_upload', labels)
        self.assertGreater(_recon_interest_score('endpoint', labels, 85, 'new', 2), 70)

    def test_recon_surface_items_preserve_provenance_and_security_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = AppPaths.from_root(Path(tmp)); paths.ensure(); db = Database(paths.db)
            try:
                now = "2026-08-08T00:00:00Z"
                db.execute("INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    ("example.com","/api/admin/users/{id}/export","rest","api",88,json.dumps(["api"]),json.dumps(["identifier"]),json.dumps(["javascript","crawler"]),now,now,"run-1"))
                items, _ = _recon_surface_items(db, "example.com")
                item = next(x for x in items if x["kind"] == "endpoint")
                self.assertIn("apis", item["categories"])
                self.assertIn("admin_internal", item["categories"])
                self.assertIn("data_object", item["categories"])
                self.assertIn("file_upload", item["categories"])
                self.assertEqual(item["sources"], ["javascript","crawler"])
                self.assertGreaterEqual(item["interest"], 70)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
