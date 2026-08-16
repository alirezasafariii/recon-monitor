from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from verified_replay_contract import (
    CANONICAL_FAMILIES,
    EVIDENCE_QUALITY_DIMENSIONS,
    validate_verified_replay_collection,
    validate_verified_replay_record,
)


def _quality() -> dict[str, float]:
    return {
        "reliability": 0.95,
        "specificity": 0.90,
        "directness": 0.95,
        "freshness": 0.85,
        "independence": 0.90,
        "reproducibility": 0.85,
        "uncertainty": 0.10,
    }


def _valid_record(*, label: object = True, suffix: str = "1") -> dict[str, object]:
    family = sorted(CANONICAL_FAMILIES)[0]
    return {
        "id": f"case-{suffix}",
        "family": family,
        "label": label,
        "decision_readiness_score": 82 if label not in {False, "false", 0} else 18,
        "bug_proximity_score": 67,
        "target_evidence_confidence": 61,
        "signals": ["signal_a", "signal_b"],
        "contradictions": [],
        "provenance": "human_verified_replay",
        "human_verified": True,
        "label_source": "analyst_case_review",
        "reviewer_id": "reviewer-1",
        "reviewed_at": "2026-08-14T00:30:00Z",
        "case_origin_id": f"origin-{suffix}",
        "evidence_snapshot_id": f"snapshot-{suffix}",
        "evidence_quality": _quality(),
    }


class VerifiedReplayContractV941Tests(unittest.TestCase):
    def test_contract_uses_complete_canonical_family_catalog(self):
        self.assertEqual(len(CANONICAL_FAMILIES), 74)

    def test_valid_record_normalizes_strict_false_label(self):
        result = validate_verified_replay_record(_valid_record(label="false"))
        self.assertTrue(result["valid"])
        self.assertFalse(result["record"]["label"])
        self.assertEqual(set(result["record"]["evidence_quality"]), set(EVIDENCE_QUALITY_DIMENSIONS))
        self.assertEqual(len(result["record"]["record_fingerprint"]), 64)

    def test_unknown_family_is_rejected(self):
        record = _valid_record()
        record["family"] = "noncanonical_family"
        result = validate_verified_replay_record(record)
        self.assertFalse(result["valid"])
        self.assertIn("unknown_family", result["errors"])

    def test_missing_snapshot_and_quality_are_rejected(self):
        record = _valid_record()
        record.pop("evidence_snapshot_id")
        record["evidence_quality"] = {"reliability": 0.9}
        result = validate_verified_replay_record(record)
        self.assertFalse(result["valid"])
        self.assertIn("missing_evidence_snapshot_id", result["errors"])
        self.assertIn("missing_quality_specificity", result["errors"])
        self.assertIn("missing_quality_uncertainty", result["errors"])

    def test_collection_deduplicates_same_evidence_snapshot(self):
        first = _valid_record(suffix="dup")
        second = dict(first)
        second["id"] = "case-dup-copy"
        second["reviewer_id"] = "reviewer-2"
        report = validate_verified_replay_collection([first, second])
        self.assertEqual(report["accepted_count"], 1)
        self.assertEqual(report["duplicate_count"], 1)
        self.assertEqual(report["rejected_count"], 1)
        self.assertEqual(report["rejected"][0]["errors"], ["duplicate_verified_replay"])
        self.assertTrue(report["safety"]["offline_metadata_only"])
        self.assertFalse(report["safety"]["changes_analysis_decisions"])
        self.assertFalse(report["safety"]["changes_calibration_activation"])


if __name__ == "__main__":
    unittest.main()
