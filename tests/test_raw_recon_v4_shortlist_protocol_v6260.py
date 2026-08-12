from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_v4_shortlist import (
    SEMANTIC_GROUPS,
    SHORTLIST_RULE_VERSION,
    SHORTLIST_VERSION,
    TARGET_FAMILY_COUNT,
    TARGET_PROJECT_COUNT,
    TARGET_ROOT_COUNT,
)


class RawReconV4ShortlistProtocol6260Tests(unittest.TestCase):
    def test_shortlist_protocol_has_all_36_family_semantics(self) -> None:
        self.assertEqual(len(SEMANTIC_GROUPS), 36)
        self.assertTrue(all(groups and all(group for group in groups) for groups in SEMANTIC_GROUPS.values()))
        self.assertEqual(TARGET_FAMILY_COUNT, 36)
        self.assertEqual(TARGET_ROOT_COUNT, 36)
        self.assertEqual(TARGET_PROJECT_COUNT, 36)

    def test_shortlist_is_pre_scoring_by_construction(self) -> None:
        source = (ROOT / "app" / "raw_recon_v4_shortlist.py").read_text(encoding="utf-8")
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
        self.assertNotIn("hypothesis_admission", source)
        self.assertNotIn("analysis_ranking", source)

    def test_shortlist_lineage_is_exact(self) -> None:
        self.assertEqual(SHORTLIST_VERSION, "1.0.0")
        self.assertEqual(SHORTLIST_RULE_VERSION, "2026.08.12.6.26")


if __name__ == "__main__":
    unittest.main()
