from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, validate_family_standards
from family_detectors import DETECTOR_ENGINE_VERSION, detector_rule_ids, get_detector_spec, validate_detector_registry
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_family_collectors import CLIENT_SIDE_COLLECTOR_RULE_VERSION, CLIENT_SIDE_FAMILIES


class Analysis619SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_619(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 19, 0))
        self.assertEqual(analysis_engine.RULE_VERSION, bug_candidates.CANDIDATE_RULE_VERSION)
        self.assertEqual(analysis_engine.RULE_VERSION, security_reasoning.REASONING_RULE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.RULE_VERSION.split(".")), (2026, 8, 12, 6))
        self.assertEqual(CLIENT_SIDE_COLLECTOR_RULE_VERSION, "2026.08.12.6.19")
        self.assertGreaterEqual(tuple(int(part) for part in STANDARDS_ENGINE_VERSION.split(".")), (1, 3, 0))
        self.assertGreaterEqual(tuple(int(part) for part in DETECTOR_ENGINE_VERSION.split(".")), (1, 1, 0))
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")

    def test_all_families_are_four_layer_grounded(self) -> None:
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])
        self.assertGreaterEqual(len(FAMILY_ADMISSION_POLICIES), 31)
        for family in FAMILY_ADMISSION_POLICIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.principle.strip(), family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
            rules = detector_rule_ids(family)
            self.assertTrue(any(rule.startswith("wstg:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("owasp:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("cwe:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("writeup:") for rule in rules), family)

    def test_client_side_family_grounding_is_exact(self) -> None:
        self.assertEqual(set(CLIENT_SIDE_FAMILIES), {"dom_xss", "postmessage_trust", "open_redirect"})
        expected = {
            "dom_xss": ({"WSTG-CLNT-01"}, {"A05:2025"}, {"CWE-79"}),
            "postmessage_trust": ({"WSTG-CLNT-11"}, {"A07:2025"}, {"CWE-940", "CWE-346"}),
            "open_redirect": ({"WSTG-CLNT-04"}, {"A01:2025"}, {"CWE-601"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)


if __name__ == "__main__":
    unittest.main()
