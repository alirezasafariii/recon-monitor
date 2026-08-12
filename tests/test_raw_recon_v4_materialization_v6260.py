from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_v4_corpus import (
    RAW_V4_CORPUS_VALIDATOR_RULE_VERSION,
    RAW_V4_CORPUS_VALIDATOR_VERSION,
    V4_EXACT_POSITIVE_FAMILIES,
    V4_EXACT_SOURCE_PROJECTS,
    V4_EXACT_SOURCE_ROOTS,
    V4_VARIANTS,
)
from raw_recon_v4_materialize import (
    EXPECTED_CONDITION,
    LEGACY_TEMPLATE_FAMILIES,
    MATERIALIZER_RULE_VERSION,
    MATERIALIZER_VERSION,
)


class RawReconV4Materialization6260Tests(unittest.TestCase):
    def test_materializer_exactly_covers_all_36_sealed_families(self) -> None:
        self.assertEqual(len(DETECTOR_SPECS), 36)
        self.assertEqual(set(EXPECTED_CONDITION), set(DETECTOR_SPECS))
        self.assertEqual(len(EXPECTED_CONDITION), 36)
        self.assertEqual(len(LEGACY_TEMPLATE_FAMILIES), 20)
        for family, condition in EXPECTED_CONDITION.items():
            self.assertIn(condition, DETECTOR_SPECS[family].condition_signals, family)

    def test_v4_collection_contract_is_exact(self) -> None:
        self.assertEqual(V4_EXACT_SOURCE_ROOTS, 36)
        self.assertEqual(V4_EXACT_SOURCE_PROJECTS, 36)
        self.assertEqual(V4_EXACT_POSITIVE_FAMILIES, 36)
        self.assertEqual(V4_VARIANTS, ("positive", "near_miss", "secure_negative", "sparse_noisy"))

    def test_materialization_and_validation_execute_no_analysis_scoring(self) -> None:
        for rel in ("app/raw_recon_v4_materialize.py", "app/raw_recon_v4_corpus.py"):
            source = (ROOT / rel).read_text(encoding="utf-8")
            for token in (
                "rank_families(",
                "assess_admission(",
                "run_raw_benchmark(",
                "evaluate_raw_case(",
                "execute_detector_intelligence(",
                "evaluate_family_detector(",
                "reason_family(",
            ):
                self.assertNotIn(token, source, rel)

    def test_expected_labels_are_outside_raw_template_generation(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_materialize.py").read_text(encoding="utf-8")
        self.assertIn('"expected": {', source)
        self.assertIn('"raw": raw,', source)
        self.assertIn('"scoring_executed": False', source)
        self.assertNotIn('"runtime_reachable_flow":', source)
        self.assertNotIn('"active_legacy_endpoint":', source)
        self.assertNotIn('"known_vulnerable_component_observed":', source)
        self.assertNotIn('"security_event_not_logged":', source)

    def test_lineage_is_exact(self) -> None:
        self.assertEqual(MATERIALIZER_VERSION, "1.0.0")
        self.assertEqual(MATERIALIZER_RULE_VERSION, "2026.08.12.6.26")
        self.assertEqual(RAW_V4_CORPUS_VALIDATOR_VERSION, "1.0.0")
        self.assertEqual(RAW_V4_CORPUS_VALIDATOR_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
