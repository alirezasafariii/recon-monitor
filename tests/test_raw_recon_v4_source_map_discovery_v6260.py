from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v4_source_map_discovery import (
    REQUIRED_GROUPS,
    SEARCH_CWES,
    SOURCE_MAP_DISCOVERY_RULE_VERSION,
    SOURCE_MAP_DISCOVERY_VERSION,
)


class RawReconV4SourceMapDiscovery6260Tests(unittest.TestCase):
    def test_search_order_and_semantics_are_pre_registered(self) -> None:
        self.assertEqual(SEARCH_CWES, ("CWE-219", "CWE-200", "CWE-22"))
        self.assertEqual(len(REQUIRED_GROUPS), 3)
        self.assertTrue(any("source map" in group for group in REQUIRED_GROUPS))
        self.assertTrue(all(group for group in REQUIRED_GROUPS))

    def test_discovery_uses_complete_novelty_firewall_without_scoring(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_source_map_discovery.py").read_text(encoding="utf-8")
        self.assertIn("_prior_exposure_index", source)
        self.assertIn("_grounding_writeup_urls", source)
        self.assertIn('root in excluded["roots"]', source)
        self.assertIn('project in excluded["projects"]', source)
        self.assertIn('urls & excluded["urls"]', source)
        self.assertIn('urls & grounding', source)
        for token in (
            "rank_families(",
            "assess_admission(",
            "run_raw_benchmark(",
            "evaluate_raw_case(",
            "execute_detector_intelligence(",
            "evaluate_family_detector(",
        ):
            self.assertNotIn(token, source)

    def test_lineage_is_exact(self) -> None:
        self.assertEqual(SOURCE_MAP_DISCOVERY_VERSION, "1.0.0")
        self.assertEqual(SOURCE_MAP_DISCOVERY_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
