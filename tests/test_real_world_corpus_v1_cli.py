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

from recon_monitor import (
    build_parser,
    corpus_v1_finalize_cli_payload,
    corpus_v1_review_status_cli_payload,
)


def pending_row() -> dict:
    return {
        "draft_id": "rwv1-review:origin:positive",
        "variant": "positive",
        "case_origin_id": "rwv1:origin",
        "evidence_snapshot_id": "sha256:" + ("a" * 64),
        "evidence_binding": {
            "boundary_semantics_human_confirmed": False,
        },
        "proposed_provenance": "curated_real_world_replay",
        "signals": [],
        "contradictions": [],
        "decision_readiness_score": None,
        "bug_proximity_score": None,
        "target_evidence_confidence": None,
        "review": {
            "family": None,
            "label": None,
            "human_verified": False,
            "label_source": None,
            "reviewer_id": None,
            "reviewed_at": None,
            "review_status": "pending_human_source_adjudication",
            "evidence_quality": {
                "reliability": None,
                "specificity": None,
                "directness": None,
                "freshness": None,
                "independence": None,
                "reproducibility": None,
                "uncertainty": None,
            },
        },
    }


class RealWorldCorpusV1CliTests(unittest.TestCase):
    def test_parser_exposes_review_actions(self):
        parser = build_parser()
        status = parser.parse_args([
            "analysis",
            "corpus-v1-review-status",
            "--corpus-review",
            "packet.json",
        ])
        self.assertEqual(status.action, "corpus-v1-review-status")
        self.assertEqual(status.corpus_review, ["packet.json"])

        finalize = parser.parse_args([
            "analysis",
            "corpus-v1-finalize",
            "--corpus-review",
            "packet.json",
            "--verified-output",
            "verified.jsonl",
        ])
        self.assertEqual(finalize.action, "corpus-v1-finalize")
        self.assertEqual(finalize.verified_output, "verified.jsonl")

    def test_status_reports_pending_review_without_promoting_anything(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "packet.json"
            path.write_text(
                json.dumps({"drafts": [pending_row()]}),
                encoding="utf-8",
            )
            payload = corpus_v1_review_status_cli_payload([str(path)])
        self.assertEqual(payload["status"]["draft_count"], 1)
        self.assertEqual(payload["status"]["verified_replay_ready_count"], 0)
        self.assertTrue(payload["safety"]["variant_is_not_a_label"])
        self.assertTrue(payload["safety"]["human_review_is_required"])

    def test_finalize_refuses_pending_rows_and_does_not_write_fake_records(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "packet.json"
            output = Path(td) / "verified.jsonl"
            path.write_text(
                json.dumps({"drafts": [pending_row()]}),
                encoding="utf-8",
            )
            payload = corpus_v1_finalize_cli_payload(
                [str(path)],
                verified_output=str(output),
            )
            self.assertEqual(payload["accepted_count"], 0)
            self.assertEqual(payload["rejected_count"], 1)
            self.assertTrue(output.exists())
            self.assertEqual(output.read_text(encoding="utf-8"), "")
            self.assertFalse(payload["production_activation_performed"])


if __name__ == "__main__":
    unittest.main()
