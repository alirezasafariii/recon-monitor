from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, validate_family_standards
from family_detectors import DETECTOR_ENGINE_VERSION, detector_rule_ids, get_detector_spec, validate_detector_registry
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_family_collectors import AUTHENTICATION_COLLECTOR_RULE_VERSION, AUTHENTICATION_FAMILIES


class Analysis622SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_622(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 22, 0))
        self.assertEqual(analysis_engine.RULE_VERSION, bug_candidates.CANDIDATE_RULE_VERSION)
        self.assertEqual(analysis_engine.RULE_VERSION, security_reasoning.REASONING_RULE_VERSION)
        self.assertTrue(analysis_engine.RULE_VERSION.startswith("2026.08.12.6."))
        self.assertEqual(AUTHENTICATION_COLLECTOR_RULE_VERSION, "2026.08.12.6.22")
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")
        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.1.0")
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")

    def test_all_31_families_keep_four_layer_grounding(self) -> None:
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])
        self.assertGreaterEqual(len(FAMILY_ADMISSION_POLICIES), 31)
        for family in FAMILY_ADMISSION_POLICIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
            rules = detector_rule_ids(family)
            self.assertTrue(any(rule.startswith("wstg:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("owasp:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("cwe:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("writeup:") for rule in rules), family)

    def test_authentication_family_grounding_is_exact(self) -> None:
        self.assertEqual(set(AUTHENTICATION_FAMILIES), {"authentication_session", "account_enumeration"})
        expected = {
            "authentication_session": ({"WSTG-ATHN-04", "WSTG-SESS-01"}, {"A07:2025", "API2:2023"}, {"CWE-287"}),
            "account_enumeration": ({"WSTG-IDNT-04"}, {"A07:2025", "API2:2023"}, {"CWE-204"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
        auth = get_detector_spec("authentication_session")
        self.assertEqual(auth.writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/")
        enum = get_detector_spec("account_enumeration")
        self.assertEqual(enum.writeups[0].url, "https://github.com/advisories/GHSA-5qxg-5vwh-7j5j")
        self.assertEqual(enum.writeups[0].source, "GitHub Advisory Database")
        self.assertEqual(enum.writeups[0].relation, "exact")


if __name__ == "__main__":
    unittest.main()
