from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v4_inventory_discovery import (
    API_SURFACE_MARKERS,
    INVENTORY_DISCOVERY_RULE_VERSION,
    INVENTORY_DISCOVERY_VERSION,
    LIFECYCLE_MARKERS,
    REACHABILITY_MARKERS,
    SEARCH_CWES,
    WEAKER_CONTROL_MARKERS,
)


class RawReconV4InventoryDiscovery6260Tests(unittest.TestCase):
    def test_search_and_semantic_groups_are_pre_registered(self) -> None:
        self.assertEqual(SEARCH_CWES, ("CWE-200", "CWE-306", "CWE-862", "CWE-284", "CWE-400"))
        self.assertTrue(LIFECYCLE_MARKERS)
        self.assertTrue(API_SURFACE_MARKERS)
        self.assertTrue(REACHABILITY_MARKERS)
        self.assertTrue(WEAKER_CONTROL_MARKERS)
        self.assertIn("deprecated endpoint", LIFECYCLE_MARKERS)
        self.assertIn("legacy api", LIFECYCLE_MARKERS)
        self.assertIn("staging endpoint", LIFECYCLE_MARKERS)
        self.assertIn("without authentication", REACHABILITY_MARKERS)

    def test_discovery_reuses_complete_v4_novelty_firewall_without_scoring(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_inventory_discovery.py").read_text(encoding="utf-8")
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
        self.assertEqual(INVENTORY_DISCOVERY_VERSION, "1.0.0")
        self.assertEqual(INVENTORY_DISCOVERY_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
