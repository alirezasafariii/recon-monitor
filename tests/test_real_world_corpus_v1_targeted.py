from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_targeted as targeted
from family_reasoning import FAMILY_ORDER


class RealWorldCorpusV1TargetedTests(unittest.TestCase):
    def test_canonical_cwe_map_covers_all_families_as_keys(self):
        mapping = targeted.canonical_family_cwes()
        self.assertEqual(tuple(mapping), tuple(FAMILY_ORDER))
        self.assertEqual(len(mapping), 74)

    def test_known_families_use_current_canonical_names(self):
        mapping = targeted.canonical_family_cwes()
        self.assertIn("CWE-639", mapping["broken_object_authorization"])
        self.assertIn("CWE-89", mapping["sql_injection"])
        self.assertIn("CWE-1336", mapping["ssti"])
        self.assertNotIn("server_side_template_injection", mapping)

    def test_target_is_discovery_only_not_final_label(self):
        self.assertEqual(targeted.TARGET_MIN_FAMILIES, 50)
        self.assertGreaterEqual(targeted.TARGET_BUFFER_FAMILIES, targeted.TARGET_MIN_FAMILIES)

    def test_query_is_cwe_scoped_and_reviewed(self):
        url = targeted._query_url("CWE-918")
        self.assertIn("cwes=CWE-918", url)
        self.assertIn("type=reviewed", url)
        self.assertNotIn("page=", url)

    def test_extra_historical_corpora_are_loaded_by_hardened_layer(self):
        names = {item[0] for item in targeted.hardened.EXTRA_CONSUMED_CORPORA}
        self.assertEqual(names, {"analysis_raw_v4", "analysis_raw_v5"})


if __name__ == "__main__":
    unittest.main()
