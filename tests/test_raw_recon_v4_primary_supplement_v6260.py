from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v4_primary_supplement import SUPPLEMENT_RULE_VERSION, SUPPLEMENT_SPECS, SUPPLEMENT_VERSION


class RawReconV4PrimarySupplement6260Tests(unittest.TestCase):
    def test_supplement_is_limited_to_specialized_protocol_families(self) -> None:
        self.assertEqual(set(SUPPLEMENT_SPECS), {"graphql_authorization", "websocket_authorization"})
        self.assertEqual(SUPPLEMENT_SPECS["graphql_authorization"]["ghsa_id"], "GHSA-gj2p-p9m4-c8gw")
        self.assertEqual(SUPPLEMENT_SPECS["graphql_authorization"]["expected_project"], "craftcms/cms")
        self.assertEqual(SUPPLEMENT_SPECS["websocket_authorization"]["ghsa_id"], "GHSA-7fch-4f2f-jcgm")
        self.assertEqual(SUPPLEMENT_SPECS["websocket_authorization"]["expected_project"], "spring-projects/spring-framework")

    def test_supplement_reuses_the_same_v4_novelty_firewall(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_primary_supplement.py").read_text(encoding="utf-8")
        self.assertIn("_prior_exposure_index", source)
        self.assertIn("_grounding_writeup_urls", source)
        self.assertIn('source root already exposed in prior corpus/discovery', source)
        self.assertIn('source project already exposed in prior corpus/discovery', source)
        self.assertIn('source overlaps current detector-grounding write-up knowledge', source)
        for token in (
            "rank_families(",
            "assess_admission(",
            "run_raw_benchmark(",
            "evaluate_raw_case(",
            "execute_detector_intelligence(",
        ):
            self.assertNotIn(token, source)

    def test_supplement_lineage_is_exact(self) -> None:
        self.assertEqual(SUPPLEMENT_VERSION, "1.0.0")
        self.assertEqual(SUPPLEMENT_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
