from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import load_golden_cases
from analysis_benchmark_v2 import (
    build_challenge_records,
    evidence_quality_profile,
    load_verified_replay_jsonl_with_diagnostics,
    quality_report,
)
from calibration_dataset import (
    activation_readiness,
    annotate_record,
    build_guarded_calibration_profile,
    is_activation_eligible,
)


GOOD_EVIDENCE_QUALITY = {
    "reliability": 0.95,
    "specificity": 0.90,
    "directness": 0.95,
    "freshness": 0.85,
    "independence": 0.90,
    "reproducibility": 0.85,
    "uncertainty": 0.10,
}


class CalibrationDatasetV920Tests(unittest.TestCase):
    def test_golden_and_synthetic_rows_can_never_unlock_production_activation(self):
        rows = []
        for index in range(500):
            rows.append(annotate_record(
                {
                    "family": f"family_{index % 50}",
                    "label": index % 2 == 0,
                    "score": 90 if index % 2 == 0 else 10,
                },
                provenance="golden_seed" if index % 2 == 0 else "synthetic_challenge",
                case_kind="regression",
                human_verified=False,
                label_source="generated",
            ))
        readiness = activation_readiness(rows)
        self.assertFalse(readiness["global_ready"])
        self.assertEqual(readiness["eligible_support"], 0)
        profile = build_guarded_calibration_profile(rows, requested_activation="production")
        self.assertEqual(profile["activation"], "shadow_only")
        self.assertTrue(profile["safety"]["requested_production_activation_was_blocked"])
        self.assertTrue(profile["safety"]["golden_or_synthetic_cannot_activate_production"])

    def test_human_verified_real_world_rows_can_unlock_only_when_minimums_are_met(self):
        rows = []
        for index in range(8):
            rows.append(annotate_record(
                {
                    "family": "verified_family",
                    "label": index < 4,
                    "score": 85 if index < 4 else 15,
                },
                provenance="human_verified_replay",
                case_kind="real_world_replay",
                human_verified=True,
                label_source="analyst_case_review",
            ))
        self.assertTrue(all(is_activation_eligible(row) for row in rows))
        profile = build_guarded_calibration_profile(
            rows,
            requested_activation="production",
            min_global_cases=4,
            min_family_cases=4,
            min_family_positive=2,
            min_family_negative=2,
            min_global_verified=8,
            min_verified_families=1,
            min_family_verified=8,
            min_verified_family_positive=4,
            min_verified_family_negative=4,
        )
        self.assertEqual(profile["activation"], "production")
        self.assertTrue(profile["activation_readiness"]["global_ready"])
        self.assertTrue(profile["activation_readiness"]["family_status"]["verified_family"]["ready"])

    def test_challenge_generator_builds_three_activation_ineligible_cases_per_family(self):
        cases = load_golden_cases([
            ROOT / "tests" / "fixtures" / "vulnerability_intelligence_golden_v1.json",
            ROOT / "tests" / "fixtures" / "vulnerability_intelligence_phase2_golden_v2.json",
        ])
        challenges = build_challenge_records(cases)
        self.assertEqual(len(cases), 74)
        self.assertEqual(len(challenges), 222)
        self.assertEqual({row["case_kind"] for row in challenges}, {
            "partial_evidence", "cross_family_noise", "contradiction_heavy"
        })
        self.assertTrue(all(row["provenance"] == "synthetic_challenge" for row in challenges))
        self.assertTrue(all(not row["activation_eligible"] for row in challenges))
        self.assertTrue(all("bug_proximity_score" in row for row in challenges))
        self.assertTrue(all("decision_readiness_score" in row for row in challenges))

    def test_verified_replay_loader_requires_snapshot_binding_and_quality(self):
        good = {
            "id": "case-001",
            "family": "broken_object_authorization",
            "label": "false",
            "decision_readiness_score": 18,
            "bug_proximity_score": 61,
            "target_evidence_confidence": 31,
            "signals": ["object_identifier", "object_operation"],
            "contradictions": ["cross_context_denied"],
            "provenance": "human_verified_replay",
            "human_verified": True,
            "label_source": "analyst_case_review",
            "reviewer_id": "reviewer-7",
            "reviewed_at": "2026-08-13T15:00:00Z",
            "case_origin_id": "case-origin-001",
            "evidence_snapshot_id": "snapshot-sha256-001",
            "evidence_quality": GOOD_EVIDENCE_QUALITY,
        }
        bad = {
            "id": "case-002",
            "family": "broken_object_authorization",
            "label": True,
            "score": 90,
            "provenance": "human_verified_replay",
            "human_verified": True,
            "label_source": "analyst_case_review",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "verified.jsonl"
            path.write_text(json.dumps(good) + "\n" + json.dumps(bad) + "\n", encoding="utf-8")
            loaded = load_verified_replay_jsonl_with_diagnostics([path])

        self.assertEqual(loaded["accepted_count"], 1)
        self.assertEqual(loaded["rejected_count"], 1)
        self.assertFalse(loaded["records"][0]["label"])
        self.assertGreaterEqual(loaded["records"][0]["evidence_quality_profile"]["score"], 70)
        errors = set(loaded["rejected"][0]["errors"])
        self.assertIn("missing_reviewer_id", errors)
        self.assertIn("missing_evidence_snapshot_id", errors)
        self.assertIn("incomplete_evidence_quality", errors)

    def test_verified_replay_loader_deduplicates_same_reviewed_snapshot(self):
        first = {
            "id": "case-a",
            "family": "authentication_session",
            "label": True,
            "score": 88,
            "provenance": "curated_real_world_replay",
            "human_verified": True,
            "label_source": "dual_review",
            "reviewer_id": "reviewer-a",
            "reviewed_at": "2026-08-13T15:10:00Z",
            "case_origin_id": "origin-auth-1",
            "evidence_snapshot_id": "snapshot-auth-1",
            "evidence_quality": GOOD_EVIDENCE_QUALITY,
        }
        second = dict(first)
        second["id"] = "case-b"
        second["label"] = False
        second["reviewer_id"] = "reviewer-b"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "verified.jsonl"
            path.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8")
            loaded = load_verified_replay_jsonl_with_diagnostics([path])

        self.assertEqual(loaded["accepted_count"], 1)
        self.assertEqual(loaded["duplicate_count"], 1)
        self.assertEqual(loaded["rejected_count"], 1)
        self.assertEqual(loaded["rejected"][0]["errors"], ["duplicate_verified_replay"])

    def test_evidence_quality_profile_fails_closed_on_missing_dimensions(self):
        incomplete = evidence_quality_profile({
            "evidence_quality": {
                "reliability": 0.9,
                "specificity": 0.9,
                "directness": 0.9,
            }
        })
        self.assertFalse(incomplete["complete"])
        self.assertEqual(incomplete["score"], 0)
        self.assertIn("independence", incomplete["missing_dimensions"])
        complete = evidence_quality_profile({"evidence_quality": GOOD_EVIDENCE_QUALITY})
        self.assertTrue(complete["complete"])
        self.assertGreaterEqual(complete["score"], 70)
        self.assertTrue(complete["advisory_only"])

    def test_quality_report_keeps_seed_and_challenges_separate_and_fail_closed(self):
        report = quality_report(ROOT, requested_activation="production")
        self.assertEqual(report["coverage"]["families"], 74)
        self.assertEqual(report["coverage"]["golden_records"], 148)
        self.assertEqual(report["coverage"]["challenge_records"], 222)
        self.assertEqual(report["coverage"]["verified_records"], 0)
        self.assertEqual(report["coverage"]["verified_rejected_records"], 0)
        self.assertEqual(report["coverage"]["verified_duplicate_records"], 0)
        self.assertEqual(report["coverage"]["total_diagnostic_records"], 370)
        self.assertEqual(report["score_semantics"], "decision_readiness_score")
        self.assertEqual(report["calibration_profile"]["activation"], "shadow_only")
        self.assertFalse(report["calibration_profile"]["activation_readiness"]["global_ready"])
        self.assertEqual(report["calibration_profile"]["activation_readiness"]["eligible_support"], 0)
        for kind in ("partial_evidence", "cross_family_noise", "contradiction_heavy"):
            metrics = report["challenge_metrics_by_kind"][kind]
            self.assertEqual(metrics["support"], 74)
            self.assertEqual(metrics["fp"], 0, kind)
            self.assertEqual(metrics["false_positive_rate"], 0.0, kind)
        self.assertEqual(report["challenge_ordering_failure_count"], 0)
        self.assertEqual(report["challenge_ordering_failures"], [])
        self.assertTrue(report["safety"]["bug_proximity_remains_investigation_oriented"])
        self.assertTrue(report["safety"]["decision_readiness_is_advisory_only"])
        self.assertTrue(report["safety"]["synthetic_challenges_are_activation_ineligible"])
        self.assertTrue(report["safety"]["production_activation_requires_human_verified_real_world_labels"])
        self.assertTrue(report["safety"]["verified_replay_requires_snapshot_binding"])
        self.assertTrue(report["safety"]["evidence_quality_is_advisory_only"])
        self.assertTrue(report["safety"]["rejected_replay_rows_never_enter_calibration"])


if __name__ == "__main__":
    unittest.main()
