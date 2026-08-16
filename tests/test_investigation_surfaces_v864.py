from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Database
import api_server
import recon_monitor


SAMPLE_QUEUE = [
    {
        "cluster_id": "cluster-1",
        "target": "example.com",
        "queue_score": 86,
        "primary_bug": "BOLA / IDOR",
        "primary_family": "broken_object_authorization",
        "bug_proximity_score": 91,
        "target_evidence_confidence": 61,
        "hunt_priority": "HIGH",
        "cluster_strength": 84,
        "endpoints": ["/api/users/{userId}", "/api/orders/{orderId}"],
        "families": [{"family": "broken_object_authorization", "score": 91}],
        "status": "investigation_queue_not_confirmed",
    }
]


class InvestigationSurfacesV864Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = AppPaths.from_root(self.root)
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.db = Database(self.paths.db)

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def test_api_payload_has_stable_safety_envelope(self) -> None:
        with mock.patch("api_server.investigation_queue", return_value=SAMPLE_QUEUE) as queue:
            payload = api_server.investigation_queue_payload(
                self.db,
                analysis_id="A1",
                target="example.com",
                limit=25,
            )
        self.assertEqual(payload["analysis_id"], "A1")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["items"][0]["queue_score"], 86)
        self.assertEqual(payload["safety"]["status"], "investigation_queue_not_confirmed")
        self.assertTrue(payload["safety"]["queue_is_not_vulnerability_confirmation"])
        self.assertTrue(payload["safety"]["correlation_cannot_satisfy_admission"])
        self.assertIn("meta_ranker", payload["engines"])
        self.assertIn("correlation", payload["engines"])
        queue.assert_called_once_with(self.db, "A1", target="example.com", limit=25)

    def test_api_handler_adds_only_investigation_queue_get_surface(self) -> None:
        self.assertEqual(api_server.APIHandler.do_GET.__name__, "_do_get_with_investigation_queue")
        self.assertTrue(hasattr(api_server.APIHandler, "do_POST"))
        self.assertTrue(hasattr(api_server, "serve_api"))
        self.assertTrue(hasattr(api_server, "create_token"))

    def test_cli_parser_accepts_queue_inside_existing_analysis_command(self) -> None:
        parser = recon_monitor.build_parser()
        args = parser.parse_args(
            ["analysis", "investigation-queue", "--id", "A1", "--target", "example.com", "--limit", "7"]
        )
        self.assertEqual(args.command, "analysis")
        self.assertEqual(args.action, "investigation-queue")
        self.assertEqual(args.analysis_id, "A1")
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.limit, 7)

    def test_cli_payload_matches_investigation_only_semantics(self) -> None:
        with mock.patch("recon_monitor.investigation_queue", return_value=SAMPLE_QUEUE) as queue:
            payload = recon_monitor.investigation_queue_cli_payload(
                self.db,
                analysis_id="A1",
                target="example.com",
                limit=9,
            )
        self.assertEqual(payload["analysis_id"], "A1")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["items"][0]["status"], "investigation_queue_not_confirmed")
        self.assertTrue(payload["safety"]["queue_is_not_vulnerability_confirmation"])
        self.assertTrue(payload["safety"]["target_evidence_confidence_uses_target_observations_only"])
        queue.assert_called_once_with(self.db, "A1", target="example.com", limit=9)


if __name__ == "__main__":
    unittest.main()
