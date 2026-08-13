from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_benchmark import RAW_QUALITY_GATES
from raw_recon_v4_blind import (
    RAW_RECON_V4_BLIND_RULE_VERSION,
    RAW_RECON_V4_BLIND_VERSION,
    V4_BLIND_QUALITY_GATES,
)


class RawReconV4FirstBlind6260Tests(unittest.TestCase):
    def test_blind_lineage_is_pre_registered(self) -> None:
        self.assertEqual(RAW_RECON_V4_BLIND_VERSION, "1.0.0")
        self.assertEqual(RAW_RECON_V4_BLIND_RULE_VERSION, "2026.08.13.6.26")

    def test_existing_raw_quality_gates_are_inherited_without_relaxation(self) -> None:
        for metric, gate in RAW_QUALITY_GATES.items():
            self.assertEqual(V4_BLIND_QUALITY_GATES.get(metric), gate, metric)

    def test_v4_negative_control_gates_are_fixed_before_scoring(self) -> None:
        self.assertEqual(V4_BLIND_QUALITY_GATES["near_miss_abstention_accuracy"], ("min", 0.90))
        self.assertEqual(V4_BLIND_QUALITY_GATES["secure_negative_rejection_accuracy"], ("min", 0.95))
        self.assertEqual(V4_BLIND_QUALITY_GATES["sparse_noisy_abstention_accuracy"], ("min", 0.90))
        self.assertEqual(V4_BLIND_QUALITY_GATES["positive_end_to_end_accuracy"], ("min", 0.75))

    def test_first_blind_runner_refuses_report_overwrite_and_does_not_mutate_inputs(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_blind.py").read_text(encoding="utf-8")
        self.assertIn("first blind report already exists and is immutable", source)
        self.assertIn("frozen corpus hash mismatch", source)
        self.assertIn("frozen shortlist hash mismatch", source)
        self.assertNotIn("write_text(json.dumps(shortlist", source)
        self.assertNotIn("write_text(json.dumps(freeze", source)
        self.assertNotIn("raw_recon_v4_materialize", source)
        self.assertNotIn("source_discovery", source)

    def test_report_has_all_36_family_result_channel(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_blind.py").read_text(encoding="utf-8")
        self.assertIn('report["family_results"]', source)
        self.assertIn('"positive_admitted"', source)
        self.assertIn('"positive_top1_correct"', source)
        self.assertIn('"positive_condition_misses"', source)
        self.assertIn('"near_miss_abstained"', source)
        self.assertIn('"secure_negative_abstained"', source)
        self.assertIn('"sparse_noisy_abstained"', source)
        self.assertIn('"wrong_promotions"', source)

    def test_first_blind_execution_is_explicit_and_single_consumption(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_blind.py").read_text(encoding="utf-8")
        self.assertIn('"first_blind_single_consumption"', source)
        self.assertIn("run_raw_benchmark(cases, validation=validation)", source)
        self.assertIn("validate_v4_corpus(cases, shortlist=shortlist)", source)
        self.assertIn("Never make the first execution disappear", source)


if __name__ == "__main__":
    unittest.main()
