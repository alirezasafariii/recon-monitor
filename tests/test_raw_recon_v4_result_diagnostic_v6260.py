from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v4_result_diagnostic import DIAGNOSTIC_RULE_VERSION, DIAGNOSTIC_VERSION


class RawReconV4ResultDiagnostic6260Tests(unittest.TestCase):
    def test_lineage_is_exact(self) -> None:
        self.assertEqual(DIAGNOSTIC_VERSION, "1.0.0")
        self.assertEqual(DIAGNOSTIC_RULE_VERSION, "2026.08.13.6.26")

    def test_diagnostic_never_reruns_analysis_engine(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_result_diagnostic.py").read_text(encoding="utf-8")
        for token in (
            "run_raw_benchmark(",
            "evaluate_raw_case(",
            "execute_detector_intelligence(",
            "evaluate_family_detector(",
            "rank_families(",
            "assess_admission(",
            "raw_recon_v4_materialize",
        ):
            self.assertNotIn(token, source)
        self.assertIn('"diagnostic_reruns_holdout": False', source)
        self.assertIn('"frozen_inputs_mutated": False', source)

    def test_diagnostic_uses_immutable_report_receipt_hash(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_result_diagnostic.py").read_text(encoding="utf-8")
        self.assertIn("stored first-blind report hash does not match immutable consumption receipt", source)
        self.assertIn('receipt.get("report_sha256")', source)

    def test_failure_taxonomy_is_explicit(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_result_diagnostic.py").read_text(encoding="utf-8")
        for label in (
            "execution_extraction_gap",
            "condition_reconstruction_gap",
            "admission_gap",
            "routing_top3_gap",
            "routing_top1_gap",
            "cross_family_precision_gap",
        ):
            self.assertIn(label, source)


if __name__ == "__main__":
    unittest.main()
