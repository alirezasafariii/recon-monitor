from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v4_freeze import FREEZE_RULE_VERSION, FREEZE_VERSION


class RawReconV4Freeze6260Tests(unittest.TestCase):
    def test_freeze_contract_is_pre_first_blind_and_hash_locked(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_freeze.py").read_text(encoding="utf-8")
        self.assertIn('"status": "frozen_pre_first_blind"', source)
        self.assertIn('"first_blind_scoring_executed": False', source)
        self.assertIn('"corpus_mutation_after_freeze": "forbidden"', source)
        self.assertIn('"benchmark_repairs_after_first_blind": "forbidden"', source)
        self.assertIn('"corpus_sha256": corpus_sha', source)
        self.assertIn('"shortlist_sha256": _sha256(shortlist_path)', source)
        self.assertIn('"source_family_audit_sha256": _sha256(audit_path)', source)
        self.assertIn('"materialization_report_sha256": _sha256(materialization_path)', source)

    def test_freeze_executes_no_analysis_scoring(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_freeze.py").read_text(encoding="utf-8")
        for token in (
            "rank_families(",
            "assess_admission(",
            "run_raw_benchmark(",
            "evaluate_raw_case(",
            "execute_detector_intelligence(",
            "evaluate_family_detector(",
            "reason_family(",
        ):
            self.assertNotIn(token, source)

    def test_freeze_requires_clean_36_family_validation(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_freeze.py").read_text(encoding="utf-8")
        self.assertIn('validation["source_root_count"] != 36', source)
        self.assertIn('validation["source_project_count"] != 36', source)
        self.assertIn('validation["positive_family_count"] != 36', source)
        self.assertIn('validation["label_leakage_count"] != 0', source)
        self.assertIn('validation["positive_observable_delta_rate"] != 1.0', source)

    def test_lineage_is_exact(self) -> None:
        self.assertEqual(FREEZE_VERSION, "1.0.0")
        self.assertEqual(FREEZE_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
