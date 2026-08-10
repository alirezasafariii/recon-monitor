from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import (
    BENCHMARK_ENGINE_VERSION,
    DEFAULT_CORPUS,
    HARD_CORPUS,
    benchmark_file,
    load_golden_cases,
    run_benchmark,
)


class AnalysisHardBenchmarkV630Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed = load_golden_cases(DEFAULT_CORPUS)
        cls.cases = load_golden_cases(HARD_CORPUS)
        cls.report = run_benchmark(cls.cases)

    def test_v2_shape(self):
        self.assertEqual(BENCHMARK_ENGINE_VERSION, "3.1.0")
        self.assertEqual(len(self.seed), 45)
        self.assertEqual(len(self.cases), 69)
        hard = [case for case in self.cases if case.get("difficulty") == "hard"]
        self.assertEqual(len(hard), 24)
        self.assertEqual(sum(1 for case in hard if case["case_kind"] == "positive"), 20)
        self.assertEqual(sum(1 for case in hard if case["case_kind"] != "positive"), 4)

    def test_hard_cases_have_standards_provenance_and_confounders(self):
        for case in self.cases:
            if case.get("difficulty") != "hard":
                continue
            self.assertTrue(case.get("confounders"), case["id"])
            provenance = case.get("provenance") or {}
            self.assertEqual(provenance.get("source_kind"), "standards_confounder", case["id"])
            self.assertTrue(provenance.get("wstg_ids"), case["id"])
            self.assertTrue(provenance.get("cwe_urls"), case["id"])

    def test_no_confounder_family_is_promoted(self):
        self.assertEqual(self.report["confounder_leaks"], 0, self.report["failures"])
        self.assertEqual(self.report["metrics"]["confounder_leak_rate"], 0.0)

    def test_hard_ranking_and_abstention_gate(self):
        metrics = self.report["metrics"]
        self.assertGreaterEqual(metrics["hard_top1_accuracy"], 0.90)
        self.assertGreaterEqual(metrics["hard_top3_accuracy"], 0.98)
        self.assertGreaterEqual(metrics["hard_abstention_accuracy"], 0.95)

    def test_all_analysis_families_have_standard_grounding(self):
        self.assertEqual(self.report["metrics"]["standards_coverage"], 1.0)
        self.assertEqual(self.report["standards_errors"], [])

    def test_v2_quality_gate_passes(self):
        report = benchmark_file(HARD_CORPUS)
        self.assertTrue(report["quality_gate"]["passed"], report["quality_gate"])
        self.assertEqual(report["failures"], [])


if __name__ == "__main__":
    unittest.main()
