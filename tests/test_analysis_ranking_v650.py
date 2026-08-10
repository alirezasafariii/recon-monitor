from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import BENCHMARK_ENGINE_VERSION, REAL_WORLD_CORPUS, benchmark_file
from analysis_ranking import RANKING_ENGINE_VERSION, admission_confidence, family_compatibility, rank_families
from hypothesis_admission import assess_admission
from security_reasoning import REASONING_ENGINE_VERSION, _family_score


class AnalysisRankingV650Tests(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(RANKING_ENGINE_VERSION, "2.1.0")
        self.assertEqual(BENCHMARK_ENGINE_VERSION, "3.1.0")
        self.assertEqual(REASONING_ENGINE_VERSION, "6.9.0")

    def test_security_control_reduces_condition_not_family_fit(self):
        support = [
            {"type": "privileged_function", "source": "semantic", "source_group": "function_surface"},
            {"type": "state_change", "source": "endpoint_contract", "source_group": "operation_surface"},
        ]
        contradict = [
            {"type": "lower_privilege_denied", "source": "stored_behavior", "source_group": "authorization_behavior"},
        ]
        assessment = assess_admission("broken_function_authorization", support, contradict)
        self.assertFalse(assessment["admitted"])
        self.assertEqual(assessment["state"], "shadow_contradicted")
        self.assertEqual(admission_confidence(assessment), 0.04)

        bfla = family_compatibility("broken_function_authorization", support, contradict)
        business = family_compatibility("business_logic", support, contradict)
        self.assertGreater(bfla["family_fit_score"], business["family_fit_score"])
        self.assertEqual(bfla["control_evidence"], ["lower_privilege_denied"])
        self.assertEqual(rank_families(support, contradict)[0]["family"], "broken_function_authorization")

    def test_production_family_score_keeps_control_out_of_fit_penalty(self):
        support_types = {"privileged_function", "state_change"}
        controlled, reason = _family_score(
            "broken_function_authorization",
            "broken_function_authorization",
            support_types,
            {"confirmed_role_enforcement"},
            "admin state change",
        )
        uncontrolled, _ = _family_score(
            "broken_function_authorization",
            "broken_function_authorization",
            support_types,
            set(),
            "admin state change",
        )
        self.assertEqual(controlled, uncontrolled)
        self.assertEqual(reason["matched_contradict"], ["confirmed_role_enforcement"])
        self.assertFalse(reason["contradictions_affect_family_fit"])

    def test_development_ranking_has_no_known_top1_confusion(self):
        report = benchmark_file(REAL_WORLD_CORPUS)
        development = report["partitions"]["development"]
        self.assertEqual(development["metrics"]["top1_accuracy"], 1.0)
        self.assertEqual(development["ranking_errors"], [])

    def test_full_confusion_matrix_is_not_hard_only(self):
        report = benchmark_file(REAL_WORLD_CORPUS)
        held = report["partitions"]["held_out"]
        self.assertEqual(report["held_out_confusion_matrix"], held["confusion_matrix"])
        self.assertIn("held_out_ranking_errors", report)
        self.assertGreater(sum(sum(v.values()) for v in report["held_out_confusion_matrix"].values()), 0)


if __name__ == "__main__":
    unittest.main()
