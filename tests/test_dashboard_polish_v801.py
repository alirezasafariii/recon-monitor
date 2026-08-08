from __future__ import annotations

import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Config, Logger, ReconError
from dashboard import _candidate_confidence_story, _layout
from dashboard_service import _port_listener_details, start_dashboard


class DashboardPolishV801Tests(unittest.TestCase):
    def test_primary_sidebar_is_four_direct_workspaces(self) -> None:
        page = _layout("Recon", "<p>body</p>", current_path="/recon")
        self.assertIn("class='nav-item active' href='/recon'", page)
        self.assertIn("data-primary-workspace='1'", page)
        self.assertIn("03 · Potential Findings", page)
        self.assertIn("04 · Alerts", page)
        self.assertIn("<strong>More tools</strong>", page)
        self.assertIn("href='/cases'", page)

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


if __name__ == "__main__":
    unittest.main()
