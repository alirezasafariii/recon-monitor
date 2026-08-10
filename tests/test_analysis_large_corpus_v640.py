from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import BENCHMARK_ENGINE_VERSION, REAL_WORLD_CORPUS, benchmark_file, load_golden_cases
from analysis_corpus import CORPUS_VALIDATOR_VERSION, validate_corpus
from analysis_standards import standards_for_family
from hypothesis_admission import assess_admission

class AnalysisLargeCorpusV640Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = load_golden_cases(REAL_WORLD_CORPUS)
        cls.validation = validate_corpus(cls.cases)
        cls.report = benchmark_file(REAL_WORLD_CORPUS)

    def test_version_and_large_corpus_shape(self):
        self.assertEqual(BENCHMARK_ENGINE_VERSION, "3.1.0")
        self.assertEqual(CORPUS_VALIDATOR_VERSION, "1.0.0")
        self.assertEqual(len(self.cases), 179)
        self.assertGreaterEqual(self.validation["real_positive_source_roots"], 40)
        self.assertGreaterEqual(self.validation["source_project_count"], 25)

    def test_held_out_source_roots_never_leak_into_development(self):
        self.assertTrue(self.validation["passed"], self.validation["errors"])
        self.assertEqual(self.validation["source_root_leakage_count"], 0)
        self.assertGreaterEqual(self.validation["held_out_root_count"], 10)
        self.assertGreaterEqual(self.validation["held_out_case_count"], 30)

    def test_held_out_quality_gate_is_independent_and_passes(self):
        metrics = self.report["metrics"]
        self.assertGreaterEqual(metrics["heldout_precision"], 0.93)
        self.assertGreaterEqual(metrics["heldout_recall"], 0.85)
        self.assertGreaterEqual(metrics["heldout_top1_accuracy"], 0.80)
        self.assertGreaterEqual(metrics["heldout_top3_accuracy"], 0.95)
        self.assertGreaterEqual(metrics["heldout_abstention_accuracy"], 0.90)
        self.assertLessEqual(metrics["heldout_false_promotion_rate"], 0.05)
        self.assertLessEqual(metrics["heldout_ece"], 0.15)
        self.assertTrue(self.report["quality_gate"]["passed"], self.report["quality_gate"])

    def test_held_out_has_reliability_buckets(self):
        buckets = self.report["held_out_reliability_buckets"]
        self.assertTrue(buckets)
        self.assertEqual(sum(bucket["count"] for bucket in buckets), self.report["held_out_case_count"])

    def test_real_world_cases_carry_wstg_and_cwe_grounding(self):
        for case in self.cases:
            if ":real_world:" not in case["id"]:
                continue
            standards = case["standards"]
            canonical = standards_for_family(case["family"])
            self.assertTrue(set(standards["wstg"]).issubset({x["id"] for x in canonical["wstg"]}))
            self.assertTrue(set(standards["cwe"]).issubset({x["id"] for x in canonical["cwe"]}))

    def test_external_provenance_never_counts_as_target_evidence(self):
        for family in {case["family"] for case in self.cases}:
            result = assess_admission(family, [
                {"type": "knowledge_reference", "source": "external_writeup", "source_group": "knowledge"},
                {"type": "wstg_reference", "source": "OWASP WSTG", "source_group": "knowledge"},
                {"type": "cwe_reference", "source": "MITRE CWE", "source_group": "knowledge"},
            ], [])
            self.assertFalse(result["admitted"], (family, result))

    def test_noisy_held_out_recon_abstains(self):
        noisy = [case for case in self.cases if case.get("difficulty") == "noisy"]
        self.assertEqual(len(noisy), 11)
        for case in noisy:
            result = assess_admission(case["family"], case["support"], case.get("contradict") or [])
            self.assertFalse(result["admitted"], case["id"])

if __name__ == "__main__":
    unittest.main()
