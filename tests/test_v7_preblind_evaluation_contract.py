from __future__ import annotations

import unittest

import v7_preblind_evaluation_contract as module


class V7PreblindEvaluationContractTests(unittest.TestCase):
    def test_safe_ratio_zero_denominator_is_none(self) -> None:
        self.assertIsNone(module.safe_ratio(0, 0))
        self.assertEqual(module.safe_ratio(1, 2), 0.5)

    def test_admission_confusion_metrics(self) -> None:
        metrics = module.admission_confusion_metrics(tp=8, fp=2, tn=18, fn=2)
        self.assertAlmostEqual(metrics["precision"], 0.8)
        self.assertAlmostEqual(metrics["recall"], 0.8)
        self.assertAlmostEqual(metrics["false_positive_rate"], 0.1)
        self.assertAlmostEqual(metrics["false_negative_rate"], 0.2)

    def test_confusion_rejects_negative_counts(self) -> None:
        with self.assertRaises(ValueError):
            module.admission_confusion_metrics(tp=1, fp=-1, tn=2, fn=0)

    def test_abstention_metrics(self) -> None:
        self.assertEqual(module.abstention_metrics(5, 20)["abstention_rate"], 0.25)
        self.assertIsNone(module.abstention_metrics(0, 0)["abstention_rate"])
        with self.assertRaises(ValueError):
            module.abstention_metrics(3, 2)

    def test_contract_is_descriptive_and_threshold_free(self) -> None:
        contract = module.build_contract()
        self.assertTrue(contract["descriptive_only"])
        self.assertTrue(all(value is None for value in contract["performance_thresholds"].values()))
        lineage = contract["v6_evaluator_lineage"]
        self.assertEqual(lineage["version"], module.EXPECTED_V6_EVALUATOR_FREEZE_VERSION)
        self.assertEqual(lineage["rule_version"], module.EXPECTED_V6_EVALUATOR_FREEZE_RULE)
        self.assertEqual(lineage["evaluator_sha256"], module.EXPECTED_V6_EVALUATOR_SHA256)
        self.assertFalse(lineage["engine_output_allowed_as_ground_truth"])

    def test_contract_has_no_invented_top3_metric(self) -> None:
        contract = module.build_contract()
        metrics = set(contract["v7_metric_contract"]["evaluated_metrics"]) | set(contract["v7_metric_contract"]["report_only_metrics"])
        self.assertTrue(contract["v7_metric_contract"]["no_top3_metric"])
        self.assertFalse(any("top3" in metric or "top_3" in metric for metric in metrics))

    def test_first_blind_lifecycle_is_one_shot(self) -> None:
        contract = module.build_contract()
        lifecycle = contract["first_blind_lifecycle"]
        self.assertTrue(lifecycle["one_shot"])
        self.assertTrue(lifecycle["mark_consumed_on_scoring_start"])
        self.assertFalse(lifecycle["v7_reblind_after_tuning_allowed"])
        self.assertEqual(lifecycle["fresh_blind_required_after_tuning"], "V8_or_later")
        self.assertFalse(contract["scoring_executed"])
        self.assertFalse(contract["first_blind_consumed"])

    def test_ground_truth_uses_source_grounded_standards_adjudication_not_humans(self) -> None:
        contract = module.build_contract()
        truth = contract["ground_truth_contract"]
        gates = contract["integrity_gates"]
        self.assertFalse(truth["human_review_required"])
        self.assertEqual(truth["minimum_distinct_human_reviewers"], 0)
        self.assertEqual(truth["required_human_verified_variant_count"], 0)
        self.assertTrue(truth["standards_used_as_interpretation_rubric"])
        self.assertTrue(truth["writeups_used_as_interpretation_rubric"])
        self.assertFalse(truth["standards_count_as_target_evidence"])
        self.assertFalse(truth["writeups_count_as_target_evidence"])
        self.assertFalse(truth["engine_output_allowed_as_ground_truth"])
        self.assertFalse(gates["human_review_required_before_scoring"])
        self.assertEqual(gates["human_verified_variant_count_required_before_scoring"], 0)
        self.assertTrue(gates["machine_semantic_adjudication_complete_required_before_scoring"])
        self.assertEqual(gates["source_grounded_accepted_variant_count_required_before_scoring"], 144)
        self.assertEqual(gates["unresolved_variant_count_required_before_scoring"], 0)

    def test_current_incomplete_adjudication_blocks_scoring_readiness(self) -> None:
        contract = module.build_contract()
        readiness = contract["pre_scoring_readiness"]
        self.assertEqual(readiness["accepted_variant_count"] + readiness["unresolved_variant_count"], 144)
        if readiness["unresolved_variant_count"]:
            self.assertFalse(readiness["ready"])
            self.assertIsNotNone(readiness["blocking_reason"])


if __name__ == "__main__":
    unittest.main()
