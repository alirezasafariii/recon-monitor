from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, validate_family_standards
from family_detectors import DETECTOR_ENGINE_VERSION, detector_rule_ids, get_detector_spec, validate_detector_registry
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_family_collectors import API_CONFIGURATION_COLLECTOR_RULE_VERSION, API_CONFIGURATION_FAMILIES


class Analysis620SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_620(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")), (6, 20, 0))
        self.assertEqual(analysis_engine.RULE_VERSION, bug_candidates.CANDIDATE_RULE_VERSION)
        self.assertEqual(analysis_engine.RULE_VERSION, security_reasoning.REASONING_RULE_VERSION)
        self.assertGreaterEqual(tuple(int(part) for part in analysis_engine.RULE_VERSION.split(".")), (2026, 8, 12, 6))
        self.assertEqual(API_CONFIGURATION_COLLECTOR_RULE_VERSION, "2026.08.12.6.20")
        self.assertGreaterEqual(tuple(int(part) for part in STANDARDS_ENGINE_VERSION.split(".")), (1, 3, 0))
        self.assertGreaterEqual(tuple(int(part) for part in DETECTOR_ENGINE_VERSION.split(".")), (1, 1, 0))
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

    def test_api_configuration_taxonomy_and_writeup_lineage(self) -> None:
        self.assertEqual(set(API_CONFIGURATION_FAMILIES), {
            "unrestricted_resource_consumption", "sensitive_business_flow_abuse",
            "security_misconfiguration", "improper_inventory_management", "unsafe_api_consumption",
        })
        expected_api = {
            "unrestricted_resource_consumption": "API4:2023",
            "sensitive_business_flow_abuse": "API6:2023",
            "security_misconfiguration": "API8:2023",
            "improper_inventory_management": "API9:2023",
            "unsafe_api_consumption": "API10:2023",
        }
        for family, api_id in expected_api.items():
            spec = get_detector_spec(family)
            self.assertIn(api_id, set(spec.owasp_ids), family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
        resource_urls = {ref.url for ref in get_detector_spec("unrestricted_resource_consumption").writeups}
        flow_urls = {ref.url for ref in get_detector_spec("sensitive_business_flow_abuse").writeups}
        self.assertIn("https://securitylab.github.com/advisories/GHSL-2023-225_GHSL-2023-226_Mealie/", resource_urls)
        self.assertIn("https://securitylab.github.com/advisories/GHSL-2025-038_github_branch-deploy_action/", flow_urls)


if __name__ == "__main__":
    unittest.main()
