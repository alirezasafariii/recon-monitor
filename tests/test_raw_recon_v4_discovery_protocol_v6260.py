from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_recon_v4_source_discovery import (
    PRIOR_CORPORA,
    PRIOR_DISCOVERY_FILES,
    SOURCE_DISCOVERY_RULE_VERSION,
    SOURCE_DISCOVERY_VERSION,
    _family_cwes,
)


class RawReconV4DiscoveryProtocol6260Tests(unittest.TestCase):
    def test_discovery_covers_exactly_all_36_sealed_families(self) -> None:
        buckets = _family_cwes()
        self.assertEqual(len(FAMILY_ADMISSION_POLICIES), 36)
        self.assertEqual(set(buckets), set(FAMILY_ADMISSION_POLICIES))
        self.assertEqual(set(buckets), set(FAMILY_STANDARDS))
        self.assertTrue(all(values for values in buckets.values()))
        self.assertTrue(all(all(value.startswith("CWE-") for value in values) for values in buckets.values()))

    def test_v4_excludes_every_prior_raw_corpus_and_prior_discovery_exposure(self) -> None:
        names = {path.name for path in PRIOR_CORPORA}
        self.assertTrue({"analysis_raw_v1.jsonl", "analysis_raw_v2.jsonl", "analysis_raw_v3.jsonl"} <= names)
        exposure_names = {path.name for path in PRIOR_DISCOVERY_FILES}
        self.assertIn("v2_candidates.json", exposure_names)
        self.assertIn("v3_candidates.json", exposure_names)
        self.assertIn("v3_shortlist.json", exposure_names)

    def test_discovery_is_pre_scoring_by_construction(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_source_discovery.py").read_text(encoding="utf-8")
        forbidden = (
            "rank_families(",
            "assess_admission(",
            "run_raw_benchmark(",
            "evaluate_raw_case(",
            "execute_detector_intelligence(",
        )
        for token in forbidden:
            self.assertNotIn(token, source)
        self.assertIn("_grounding_writeup_urls", source)
        self.assertIn("excluded_prior_project_count", source)

    def test_protocol_lineage_is_exact(self) -> None:
        self.assertEqual(SOURCE_DISCOVERY_VERSION, "1.0.0")
        self.assertEqual(SOURCE_DISCOVERY_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
