from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from recon_monitor import build_parser, corpus_v1_auto_evaluate_cli_payload


class SourceAttestedCorpusV1CliTests(unittest.TestCase):
    def test_parser_exposes_one_command_auto_evaluate(self):
        parser = build_parser()
        args = parser.parse_args([
            "analysis",
            "corpus-v1-auto-evaluate",
        ])
        self.assertEqual(args.action, "corpus-v1-auto-evaluate")
        self.assertEqual(args.corpus_scores, [])

    def test_default_checked_in_corpus_attests_without_human_review(self):
        parser = build_parser()
        args = parser.parse_args([
            "analysis",
            "corpus-v1-auto-evaluate",
        ])
        payload = corpus_v1_auto_evaluate_cli_payload(args)
        self.assertEqual(payload["action"], "corpus-v1-auto-evaluate")
        self.assertEqual(payload["status"], "awaiting_current_engine_replay")
        self.assertGreaterEqual(payload["attestation"]["eligible_origin_count"], 19)
        self.assertEqual(
            payload["attestation"]["attested_record_count"],
            payload["attestation"]["eligible_origin_count"] * 2,
        )
        self.assertGreaterEqual(payload["attestation"]["family_count"], 11)
        self.assertTrue(
            payload["attestation"]["safety"]["human_review_required_for_this_mode"]
            is False
        )
        self.assertEqual(payload["evaluation"]["scored_record_count"], 0)

    def test_can_write_ground_truth_separate_from_blind_replay_manifest(self):
        parser = build_parser()
        with tempfile.TemporaryDirectory() as td:
            attested = Path(td) / "attested.json"
            blind = Path(td) / "blind.json"
            args = parser.parse_args([
                "analysis",
                "corpus-v1-auto-evaluate",
                "--attested-output",
                str(attested),
                "--blind-replay-output",
                str(blind),
            ])
            payload = corpus_v1_auto_evaluate_cli_payload(args)
            self.assertTrue(attested.exists())
            self.assertTrue(blind.exists())
            truth = json.loads(attested.read_text(encoding="utf-8"))
            replay = json.loads(blind.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(truth["records"]), 38)
            self.assertEqual(replay["case_count"], len(truth["records"]))
            self.assertIn("label", truth["records"][0])
            self.assertNotIn("label", replay["cases"][0])
            self.assertNotIn("family", replay["cases"][0])
            self.assertTrue(replay["safety"]["label_blind"])
            self.assertEqual(payload["blind_replay_output"], str(blind))


if __name__ == "__main__":
    unittest.main()
