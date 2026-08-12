from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v4_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION, HARD_ANCHORS


class RawReconV4SourceAudit6260Tests(unittest.TestCase):
    def test_hard_anchor_registry_exactly_covers_36_families(self) -> None:
        self.assertEqual(len(HARD_ANCHORS), 36)
        self.assertTrue(all(len(groups) >= 2 for groups in HARD_ANCHORS.values()))
        self.assertTrue(all(all(group for group in groups) for groups in HARD_ANCHORS.values()))

    def test_specialized_families_have_protocol_specific_hard_anchors(self) -> None:
        self.assertIn("graphql", HARD_ANCHORS["graphql_authorization"][0])
        self.assertIn("graphql", HARD_ANCHORS["graphql_data_exposure"][0])
        self.assertIn("websocket", HARD_ANCHORS["websocket_authorization"][0])
        self.assertIn("postmessage", HARD_ANCHORS["postmessage_trust"][0])
        self.assertTrue(any("source map" in group for group in HARD_ANCHORS["source_map_exposure"]))
        self.assertTrue(any("dom xss" in group for group in HARD_ANCHORS["dom_xss"]))
        self.assertTrue(any("deprecated endpoint" in group for group in HARD_ANCHORS["improper_inventory_management"]))
        self.assertTrue(any("hostname validation" in group for group in HARD_ANCHORS["unsafe_api_consumption"]))

    def test_audit_is_pre_scoring_by_construction(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_source_audit.py").read_text(encoding="utf-8")
        for token in (
            "rank_families(",
            "assess_admission(",
            "run_raw_benchmark(",
            "evaluate_raw_case(",
            "execute_detector_intelligence(",
            "evaluate_family_detector(",
        ):
            self.assertNotIn(token, source)
        self.assertNotIn("family_detectors", source)
        self.assertNotIn("analysis_ranking", source)
        self.assertNotIn("hypothesis_admission", source)

    def test_audit_lineage_is_exact(self) -> None:
        self.assertEqual(AUDIT_VERSION, "1.1.0")
        self.assertEqual(AUDIT_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
