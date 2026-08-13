from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_detectors import get_detector_spec
from raw_family_collectors import FILE_REMOTE_COLLECTOR_RULE_VERSION, FILE_REMOTE_FAMILIES


class Analysis618SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_618(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 18, 0))
        self.assertEqual(analysis_engine.RULE_VERSION, bug_candidates.CANDIDATE_RULE_VERSION)
        self.assertEqual(analysis_engine.RULE_VERSION, security_reasoning.REASONING_RULE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.RULE_VERSION.split(".")), (2026, 8, 12, 6))
        self.assertEqual(FILE_REMOTE_COLLECTOR_RULE_VERSION, "2026.08.12.6.18")

    def test_file_remote_families_remain_standards_and_writeup_grounded(self) -> None:
        self.assertEqual(set(FILE_REMOTE_FAMILIES), {"ssrf", "file_upload", "path_traversal"})
        for family in FILE_REMOTE_FAMILIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.principle.strip(), family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)


if __name__ == "__main__":
    unittest.main()
