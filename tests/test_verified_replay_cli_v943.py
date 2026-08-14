from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from recon_monitor import (
    build_parser,
    verified_replay_drafts_cli_payload,
)


class _EmptyReplayDB:
    def all(self, _query, _params=()):
        return []


class VerifiedReplayCliV943Tests(unittest.TestCase):
    def test_analysis_parser_accepts_verified_replay_drafts(self):
        parser = build_parser()
        args = parser.parse_args(["analysis", "verified-replay-drafts", "--limit", "25"])
        self.assertEqual(args.command, "analysis")
        self.assertEqual(args.action, "verified-replay-drafts")
        self.assertEqual(args.limit, 25)

    def test_existing_investigation_queue_action_remains_available(self):
        parser = build_parser()
        args = parser.parse_args(["analysis", "investigation-queue", "--limit", "10"])
        self.assertEqual(args.action, "investigation-queue")
        self.assertEqual(args.limit, 10)

    def test_empty_database_returns_safe_review_draft_payload(self):
        payload = verified_replay_drafts_cli_payload(_EmptyReplayDB(), limit=25)
        self.assertEqual(payload["action"], "verified-replay-drafts")
        self.assertEqual(payload["draft_count"], 0)
        self.assertEqual(payload["positive_drafts"], 0)
        self.assertEqual(payload["negative_drafts"], 0)
        self.assertEqual(payload["drafts"], [])
        self.assertFalse(payload["safety"]["network_requests"])
        self.assertFalse(payload["safety"]["changes_calibration_activation"])
        self.assertTrue(payload["operator_guidance"]["output_is_review_draft"])
        self.assertTrue(payload["operator_guidance"]["production_calibration_remains_shadow_only"])

    def test_cli_payload_bounds_collection_limit(self):
        class RecordingDB:
            def __init__(self):
                self.query_count = 0

            def all(self, _query, _params=()):
                self.query_count += 1
                return []

        db = RecordingDB()
        payload = verified_replay_drafts_cli_payload(db, limit=999999)
        self.assertEqual(payload["draft_count"], 0)
        self.assertEqual(db.query_count, 1)


if __name__ == "__main__":
    unittest.main()
