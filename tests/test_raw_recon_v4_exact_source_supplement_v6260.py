from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v4_exact_source_supplement import (
    EXACT_SOURCE_SPECS,
    EXACT_SUPPLEMENT_RULE_VERSION,
    EXACT_SUPPLEMENT_VERSION,
)


class RawReconV4ExactSourceSupplement6260Tests(unittest.TestCase):
    def test_exact_source_registry_is_narrow_and_pre_registered(self) -> None:
        self.assertEqual(set(EXACT_SOURCE_SPECS), {
            "nosql_injection",
            "source_map_exposure",
            "unsafe_api_consumption",
        })
        self.assertEqual(EXACT_SOURCE_SPECS["nosql_injection"]["source_root"], "GHSA-hgq6-9jg2-wf3f")
        self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_root"], "GHSA-rg65-45m7-hq57")
        self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_project"], "esm-dev/esm.sh")
        self.assertEqual(EXACT_SOURCE_SPECS["unsafe_api_consumption"]["source_root"], "CVE-2020-13482")

    def test_exact_sources_use_complete_novelty_firewall(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_exact_source_supplement.py").read_text(encoding="utf-8")
        self.assertIn("_prior_exposure_index", source)
        self.assertIn("_grounding_writeup_urls", source)
        self.assertIn('root in excluded["roots"]', source)
        self.assertIn('urls & excluded["urls"]', source)
        self.assertIn('urls & grounding', source)
        self.assertIn('project in excluded["projects"]', source)
        for token in (
            "rank_families(",
            "assess_admission(",
            "run_raw_benchmark(",
            "evaluate_raw_case(",
            "execute_detector_intelligence(",
            "evaluate_family_detector(",
        ):
            self.assertNotIn(token, source)

    def test_exact_source_semantics_have_multiple_required_groups(self) -> None:
        for family, spec in EXACT_SOURCE_SPECS.items():
            groups = spec["required_groups"]
            self.assertGreaterEqual(len(groups), 3, family)
            self.assertTrue(all(group for group in groups), family)

    def test_lineage_is_exact(self) -> None:
        self.assertEqual(EXACT_SUPPLEMENT_VERSION, "1.0.0")
        self.assertEqual(EXACT_SUPPLEMENT_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
