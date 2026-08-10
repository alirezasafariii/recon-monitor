from __future__ import annotations

import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import (
    BENCHMARK_ENGINE_VERSION,
    DEFAULT_CORPUS,
    benchmark_file,
    evaluate_case,
    load_golden_cases,
    quality_gate,
    run_benchmark,
)
from hypothesis_admission import assess_admission


class AnalysisGoldenBenchmarkV620Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = load_golden_cases(DEFAULT_CORPUS)
        cls.report = run_benchmark(cls.cases)

    def test_version_and_seed_shape(self):
        self.assertEqual(BENCHMARK_ENGINE_VERSION, "3.0.0")
        self.assertEqual(len(self.cases), 45)
        families = defaultdict(set)
        for case in self.cases:
            families[case["family"]].add(case["case_kind"])
        self.assertEqual(len(families), 15)
        for family, kinds in families.items():
            self.assertEqual(kinds, {"positive", "near_miss", "secure_negative"}, family)

    def test_seed_provenance_distribution(self):
        positive = [case for case in self.cases if case["case_kind"] == "positive"]
        counts = Counter(case["provenance"]["source_kind"] for case in positive)
        self.assertEqual(counts["real_writeup"], 10)
        self.assertEqual(counts["owasp_reference"], 5)
        self.assertTrue(all(str(case["provenance"].get("url") or "").startswith("https://") for case in positive))

    def test_positive_cases_promote_only_expected_family(self):
        for case in self.cases:
            if case["case_kind"] != "positive":
                continue
            result = evaluate_case(case)
            self.assertTrue(result["pass"], result)
            self.assertEqual(result["admitted_families"], [case["family"]], result)

    def test_near_miss_and_secure_negative_cases_abstain(self):
        for case in self.cases:
            if case["case_kind"] == "positive":
                continue
            result = evaluate_case(case)
            self.assertTrue(result["pass"], result)
            self.assertEqual(result["admitted_families"], [], result)

    def test_family_ranking_keeps_expected_family_in_top3(self):
        for case in self.cases:
            result = evaluate_case(case)
            self.assertTrue(result["top3_correct"], result)

    def test_ranking_score_is_separate_from_admission_confidence(self):
        for case in self.cases:
            result = evaluate_case(case)
            self.assertIn("expected_family_score", result)
            self.assertIn("expected_family_confidence", result)
            if case["case_kind"] == "positive":
                self.assertGreaterEqual(result["expected_family_confidence"], 0.90, result)
            else:
                self.assertLess(result["expected_family_confidence"], 0.50, result)
                # A strong near-miss/secure family match may rank highly while the
                # vulnerability-condition confidence deliberately remains low.
                self.assertGreater(result["expected_family_score"], result["expected_family_confidence"], result)

    def test_baseline_quality_gate(self):
        gate = quality_gate(self.report)
        self.assertTrue(gate["passed"], gate)
        metrics = self.report["metrics"]
        self.assertGreaterEqual(metrics["precision"], 0.95)
        self.assertGreaterEqual(metrics["recall"], 0.90)
        self.assertGreaterEqual(metrics["top1_accuracy"], 0.90)
        self.assertGreaterEqual(metrics["top3_accuracy"], 0.98)
        self.assertGreaterEqual(metrics["abstention_accuracy"], 0.95)
        self.assertLessEqual(metrics["false_promotion_rate"], 0.05)
        self.assertLessEqual(metrics["brier_score"], 0.12)
        self.assertLessEqual(metrics["ece"], 0.12)

    def test_benchmark_file_attaches_gate_and_corpus(self):
        report = benchmark_file(DEFAULT_CORPUS)
        self.assertIn("quality_gate", report)
        self.assertTrue(report["quality_gate"]["passed"], report["quality_gate"])
        self.assertTrue(str(report["corpus"]).endswith("analysis_golden_v1.jsonl"))

    def test_writeup_provenance_never_counts_as_target_evidence(self):
        # Even a perfectly labeled external write-up, with no target-specific facts,
        # must remain a hidden hypothesis. Provenance is intentionally not passed to
        # assess_admission and cannot satisfy independent-source or decisive evidence gates.
        for family in sorted({case["family"] for case in self.cases}):
            result = assess_admission(
                family,
                [{"type": "knowledge_reference", "source": "external_writeup", "source_group": "knowledge"}],
                [],
            )
            self.assertFalse(result["admitted"], (family, result))


if __name__ == "__main__":
    unittest.main()
