from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v4_primary_supplement import SUPPLEMENT_RULE_VERSION, SUPPLEMENT_SEARCH_SPECS, SUPPLEMENT_VERSION


class RawReconV4PrimarySupplement6260Tests(unittest.TestCase):
    def test_supplement_is_limited_to_specialized_protocol_families(self) -> None:
        self.assertEqual(set(SUPPLEMENT_SEARCH_SPECS), {"graphql_authorization", "websocket_authorization"})
        graphql = SUPPLEMENT_SEARCH_SPECS["graphql_authorization"]
        websocket = SUPPLEMENT_SEARCH_SPECS["websocket_authorization"]
        self.assertTrue({"CWE-862", "CWE-863"} <= set(graphql["cwes"]))
        self.assertIn("graphql", graphql["required_text_groups"][0])
        self.assertTrue({"CWE-862", "CWE-863", "CWE-352", "CWE-287"} <= set(websocket["cwes"]))
        self.assertIn("websocket", websocket["required_text_groups"][0])

    def test_supplement_reuses_the_same_v4_novelty_firewall(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_primary_supplement.py").read_text(encoding="utf-8")
        self.assertIn("_prior_exposure_index", source)
        self.assertIn("_grounding_writeup_urls", source)
        self.assertIn('root in excluded["roots"]', source)
        self.assertIn('project in excluded["projects"]', source)
        self.assertIn('all_urls & excluded["urls"]', source)
        self.assertIn('all_urls & grounding', source)
        for token in (
            "rank_families(",
            "assess_admission(",
            "run_raw_benchmark(",
            "evaluate_raw_case(",
            "execute_detector_intelligence(",
            "evaluate_family_detector(",
        ):
            self.assertNotIn(token, source)

    def test_supplement_search_is_semantically_strict(self) -> None:
        for family, spec in SUPPLEMENT_SEARCH_SPECS.items():
            groups = spec["required_text_groups"]
            self.assertGreaterEqual(len(groups), 3, family)
            self.assertTrue(all(group for group in groups), family)
            self.assertTrue(spec["cwes"], family)

    def test_supplement_lineage_is_exact(self) -> None:
        self.assertEqual(SUPPLEMENT_VERSION, "1.1.0")
        self.assertEqual(SUPPLEMENT_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
