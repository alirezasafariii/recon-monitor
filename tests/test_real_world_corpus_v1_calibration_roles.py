from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_calibration as calibration
import verified_replay_contract as contract


QUALITY = {
    "reliability": 0.9,
    "specificity": 0.9,
    "directness": 0.9,
    "freshness": 0.9,
    "independence": 0.9,
    "reproducibility": 0.9,
    "uncertainty": 0.1,
}


def record(origin: str, *, role: str = "fresh_candidate", suffix: str = "a") -> dict:
    return {
        "id": f"{origin}-{suffix}",
        "family": "ssrf",
        "label": True,
        "decision_readiness_score": 80,
        "bug_proximity_score": 70,
        "target_evidence_confidence": 80,
        "signals": ["server_fetch_observed"],
        "contradictions": [],
        "provenance": "human_verified_replay",
        "human_verified": True,
        "label_source": "analyst_case_review",
        "reviewer_id": "reviewer-1",
        "reviewed_at": "2026-08-14T16:00:00Z",
        "case_origin_id": origin,
        "evidence_snapshot_id": f"snapshot-{origin}-{suffix}",
        "evidence_quality": dict(QUALITY),
        "evaluation_role": role,
        "source_corpus_id": "real-world-corpus-v1",
    }


class RealWorldCorpusV1CalibrationRoleTests(unittest.TestCase):
    def test_contract_preserves_consumed_role(self):
        result = contract.validate_verified_replay_record(record("old", role="consumed_benchmark"))
        self.assertTrue(result["valid"])
        self.assertEqual(result["record"]["evaluation_role"], "consumed_benchmark")
        self.assertEqual(result["record"]["source_corpus_id"], "real-world-corpus-v1")

    def test_contract_rejects_reserved_blind(self):
        result = contract.validate_verified_replay_record(record("v6", role="reserved_blind"))
        self.assertFalse(result["valid"])
        self.assertIn("reserved_blind_not_eligible_for_verified_replay", result["errors"])

    def test_consumed_origin_is_train_only_even_when_hash_would_holdout(self):
        origin = next(
            f"consumed-{i}"
            for i in range(10000)
            if calibration._stable_bucket(f"consumed-{i}") < 20
        )
        split = calibration.deterministic_holdout_split([
            record(origin, role="consumed_benchmark"),
            record("fresh-one"),
            record("fresh-two"),
        ])
        train_origins = {row["case_origin_id"] for row in split["train"]}
        holdout_origins = {row["case_origin_id"] for row in split["holdout"]}
        self.assertIn(origin, train_origins)
        self.assertNotIn(origin, holdout_origins)
        self.assertEqual(split["forced_train_origin_count"], 1)
        self.assertTrue(split["safety"]["consumed_benchmark_is_train_only"])

    def test_development_only_origin_is_train_only(self):
        split = calibration.deterministic_holdout_split([
            record("development", role="development_only"),
            record("fresh-one"),
            record("fresh-two"),
        ])
        train_origins = {row["case_origin_id"] for row in split["train"]}
        holdout_origins = {row["case_origin_id"] for row in split["holdout"]}
        self.assertIn("development", train_origins)
        self.assertNotIn("development", holdout_origins)

    def test_mixed_origin_is_forced_wholly_to_train(self):
        rows = [
            record("mixed", role="fresh_candidate", suffix="fresh"),
            record("mixed", role="consumed_benchmark", suffix="old"),
            record("fresh-one"),
            record("fresh-two"),
        ]
        split = calibration.deterministic_holdout_split(rows)
        mixed_train = [row for row in split["train"] if row["case_origin_id"] == "mixed"]
        mixed_holdout = [row for row in split["holdout"] if row["case_origin_id"] == "mixed"]
        self.assertEqual(len(mixed_train), 2)
        self.assertFalse(mixed_holdout)
        self.assertEqual(split["origin_leakage_count"], 0)

    def test_default_role_remains_fresh_for_backward_compatibility(self):
        row = record("legacy")
        row.pop("evaluation_role")
        result = contract.validate_verified_replay_record(row)
        self.assertTrue(result["valid"])
        self.assertEqual(result["record"]["evaluation_role"], "fresh_candidate")


if __name__ == "__main__":
    unittest.main()
