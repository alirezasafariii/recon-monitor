from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, validate_family_standards
from family_detectors import DETECTOR_ENGINE_VERSION, detector_rule_ids, get_detector_spec, validate_detector_registry
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_family_collectors import EXPOSURE_HEADERS_COLLECTOR_RULE_VERSION, EXPOSURE_HEADERS_FAMILIES


class Analysis623SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_623(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.23.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.23.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.23.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.23")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.23")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.23")
        self.assertEqual(EXPOSURE_HEADERS_COLLECTOR_RULE_VERSION, "2026.08.12.6.23")
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")
        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.1.0")
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")

    def test_all_31_families_keep_four_layer_grounding(self) -> None:
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])
        self.assertEqual(len(FAMILY_ADMISSION_POLICIES), 31)
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

    def test_exposure_header_family_grounding_is_exact(self) -> None:
        self.assertEqual(set(EXPOSURE_HEADERS_FAMILIES), {"information_disclosure", "cors_misconfiguration", "sensitive_caching"})
        expected = {
            "information_disclosure": ({"WSTG-ERRH-01", "WSTG-ERRH-02"}, {"A01:2025"}, {"CWE-200"}),
            "cors_misconfiguration": ({"WSTG-CLNT-07"}, {"A02:2025"}, {"CWE-942"}),
            "sensitive_caching": ({"WSTG-ATHN-06"}, {"A06:2025"}, {"CWE-524", "CWE-525"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
        self.assertEqual(get_detector_spec("information_disclosure").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2026-037_Wekan/")
        self.assertEqual(get_detector_spec("cors_misconfiguration").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2024-161_GHSL-2024-162_rembg/")
        cache = get_detector_spec("sensitive_caching")
        self.assertEqual(cache.writeups[0].url, "https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-fw5r-6m3x-rh7p")
        self.assertEqual(cache.writeups[0].source, "GitHub Repository Security Advisory")
        self.assertEqual(cache.writeups[0].relation, "exact")
        self.assertIn("browser_cache_no_store_missing", set(cache.condition_signals))
        self.assertIn("browser_cache_no_store_missing", set().union(*FAMILY_ADMISSION_POLICIES["sensitive_caching"]["required"]))


if __name__ == "__main__":
    unittest.main()
