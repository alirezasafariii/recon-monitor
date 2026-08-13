from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import load_golden_cases
from analysis_benchmark_v2 import build_challenge_records, quality_report
from calibration_dataset import (
    activation_readiness,
    annotate_record,
    build_guarded_calibration_profile,
    is_activation_eligible,
)


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

    def test_quality_report_keeps_seed_and_challenges_separate_and_fail_closed(self):
        report = quality_report(ROOT, requested_activation="production")
        self.assertEqual(report["coverage"]["families"], 74)
        self.assertEqual(report["coverage"]["golden_records"], 148)
        self.assertEqual(report["coverage"]["challenge_records"], 222)
        self.assertEqual(report["coverage"]["verified_records"], 0)
        self.assertEqual(report["coverage"]["total_diagnostic_records"], 370)
        self.assertEqual(report["calibration_profile"]["activation"], "shadow_only")
        self.assertFalse(report["calibration_profile"]["activation_readiness"]["global_ready"])
        self.assertEqual(report["calibration_profile"]["activation_readiness"]["eligible_support"], 0)
        for kind in ("partial_evidence", "cross_family_noise", "contradiction_heavy"):
            self.assertEqual(report["challenge_metrics_by_kind"][kind]["support"], 74)
        self.assertTrue(report["safety"]["synthetic_challenges_are_activation_ineligible"])
        self.assertTrue(report["safety"]["production_activation_requires_human_verified_real_world_labels"])


if __name__ == "__main__":
    unittest.main()
