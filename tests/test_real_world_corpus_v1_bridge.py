from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_bridge as bridge


def draft() -> dict:
    return {
        "draft_id": "rwv1-review:GHSA-aaaa-bbbb-cccc:positive",
        "variant": "positive",
        "case_origin_id": "rwv1:GHSA-aaaa-bbbb-cccc",
        "evidence_snapshot_id": "sha256:" + ("a" * 64),
        "evidence_binding": {
            "boundary_semantics_human_confirmed": False,
        },
        "proposed_provenance": "curated_real_world_replay",
        "signals": ["server_fetch_observed"],
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


def reviewed() -> dict:
    row = draft()
    row["evidence_binding"]["boundary_semantics_human_confirmed"] = True
    row["decision_readiness_score"] = 82
    row["bug_proximity_score"] = 90
    row["target_evidence_confidence"] = 88
    row["review"] = {
        "family": "ssrf",
        "label": True,
        "human_verified": True,
        "label_source": "independent-source-review",
        "reviewer_id": "reviewer-1",
        "reviewed_at": "2026-09-18T00:00:00Z",
        "review_status": "accepted",
        "evidence_quality": {
            "reliability": 0.9,
            "specificity": 0.9,
            "directness": 0.8,
            "freshness": 0.8,
            "independence": 0.9,
            "reproducibility": 0.8,
            "uncertainty": 0.1,
        },
    }
    return row


class RealWorldCorpusV1BridgeTests(unittest.TestCase):
    def test_pending_variant_is_never_auto_labeled(self):
        result = bridge.finalize_draft(draft())
        self.assertFalse(result["valid"])
        self.assertIn("human_verified_true_required", result["errors"])
        self.assertIn("missing_human_label", result["errors"])
        self.assertIn(
            "boundary_semantics_human_confirmation_required",
            result["errors"],
        )

    def test_reviewed_and_current_engine_scored_record_validates(self):
        result = bridge.finalize_draft(reviewed())
        self.assertTrue(result["valid"], result["errors"])
        record = result["record"]
        self.assertEqual(record["family"], "ssrf")
        self.assertTrue(record["label"])
        self.assertEqual(record["decision_readiness_score"], 82)
        self.assertEqual(record["provenance"], "curated_real_world_replay")
        self.assertTrue(record["record_fingerprint"])

    def test_human_review_without_current_engine_scores_is_rejected(self):
        row = reviewed()
        row["decision_readiness_score"] = None
        row["bug_proximity_score"] = None
        row["target_evidence_confidence"] = None
        result = bridge.finalize_draft(row)
        self.assertFalse(result["valid"])
        self.assertIn(
            "missing_current_engine_decision_readiness_score",
            result["errors"],
        )
        self.assertIn(
            "missing_current_engine_bug_proximity_score",
            result["errors"],
        )
        self.assertIn(
            "missing_current_engine_target_evidence_confidence",
            result["errors"],
        )

    def test_secure_negative_still_requires_boundary_semantics_review(self):
        row = reviewed()
        row["variant"] = "secure_negative"
        row["review"]["label"] = False
        row["evidence_binding"]["boundary_semantics_human_confirmed"] = False
        result = bridge.finalize_draft(row)
        self.assertFalse(result["valid"])
        self.assertIn(
            "boundary_semantics_human_confirmation_required",
            result["errors"],
        )

    def test_sparse_noisy_does_not_require_revision_boundary_confirmation(self):
        row = reviewed()
        row["variant"] = "sparse_noisy"
        row["review"]["label"] = False
        row["evidence_binding"]["boundary_semantics_human_confirmed"] = False
        result = bridge.finalize_draft(row)
        self.assertTrue(result["valid"], result["errors"])

    def test_readiness_reports_review_and_score_progress_separately(self):
        pending = draft()
        complete = reviewed()
        status = bridge.review_readiness([pending, complete])
        self.assertEqual(status["draft_count"], 2)
        self.assertEqual(status["human_review_complete_count"], 1)
        self.assertEqual(status["current_engine_score_complete_count"], 1)
        self.assertEqual(status["verified_replay_ready_count"], 1)

    def test_collection_materializes_generators_and_deduplicates(self):
        row = reviewed()
        duplicate = reviewed()
        result = bridge.finalize_collection(x for x in (row, duplicate))
        self.assertEqual(result["accepted_count"], 1)
        self.assertEqual(result["rejected_count"], 1)
        self.assertIn(
            "duplicate_verified_replay",
            result["rejected"][0]["errors"],
        )
        self.assertEqual(result["readiness"]["draft_count"], 2)

    def test_jsonl_output_is_deterministic(self):
        row = bridge.finalize_draft(reviewed())["record"]
        first = bridge.render_jsonl([row])
        second = bridge.render_jsonl([row])
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
