from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS, OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, validate_family_standards
from family_detectors import DETECTOR_ENGINE_VERSION, detector_rule_ids, get_detector_spec, validate_detector_registry
from family_evidence_extractors import FAMILY_EVIDENCE_EXTRACTOR_PROFILES, FAMILY_EXTRACTION_IDENTITY_GATES
from family_reasoners import FAMILY_IDENTITY_GATES, FAMILY_REASONER_PROFILES
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_family_collectors import OWASP_TOP10_2025_COLLECTOR_RULE_VERSION, OWASP_TOP10_2025_FAMILIES, validate_owasp_top10_2025_collectors
from static_family_collectors import STATIC_SPECIALIZED_FAMILIES, validate_static_specialized_collectors


NEW_FAMILIES = {
    "software_supply_chain_failure",
    "cryptographic_failure",
    "software_data_integrity_failure",
    "security_logging_alerting_failure",
    "exceptional_condition_mishandling",
}


class Analysis625SealTests(unittest.TestCase):
    def test_analysis_layer_versions_preserve_625_or_newer_lineage(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        def version(value: str) -> tuple[int, ...]:
            return tuple(int(part) for part in value.split("."))

        self.assertGreaterEqual(version(analysis_engine.ENGINE_VERSION), (6, 25, 0))
        self.assertGreaterEqual(version(bug_candidates.CANDIDATE_ENGINE_VERSION), (6, 25, 0))
        self.assertGreaterEqual(version(security_reasoning.REASONING_ENGINE_VERSION), (6, 25, 0))
        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertEqual(OWASP_TOP10_2025_COLLECTOR_RULE_VERSION, "2026.08.12.6.25")
        self.assertGreaterEqual(version(STANDARDS_ENGINE_VERSION), (1, 3, 0))
        self.assertGreaterEqual(version(DETECTOR_ENGINE_VERSION), (1, 1, 0))
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")

    def test_all_36_families_have_exact_cross_layer_ownership(self) -> None:
        families = set(FAMILY_ADMISSION_POLICIES)
        self.assertEqual(len(families), 36)
        self.assertEqual(set(FAMILY_EVIDENCE_EXTRACTOR_PROFILES), families)
        self.assertEqual(set(FAMILY_EXTRACTION_IDENTITY_GATES), families)
        self.assertEqual(set(FAMILY_REASONER_PROFILES), families)
        self.assertEqual(set(FAMILY_IDENTITY_GATES), families)
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])
        self.assertEqual(validate_owasp_top10_2025_collectors(), [])
        self.assertEqual(validate_static_specialized_collectors(), [])
        self.assertEqual(set(OWASP_TOP10_2025_FAMILIES), NEW_FAMILIES)
        self.assertEqual(len(STATIC_SPECIALIZED_FAMILIES), 5)
        for family in families:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
            rules = detector_rule_ids(family)
            self.assertTrue(any(rule.startswith("wstg:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("owasp:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("cwe:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("writeup:") for rule in rules), family)

    def test_owasp_top10_2025_and_api_top10_2023_are_both_ten_of_ten(self) -> None:
        top10 = {
            str(ref.get("id"))
            for profile in FAMILY_STANDARDS.values()
            for ref in profile.get("owasp", [])
            if str(ref.get("id") or "").startswith("A") and str(ref.get("id") or "").endswith(":2025")
        }
        api = {
            str(ref.get("id"))
            for profile in FAMILY_STANDARDS.values()
            for ref in profile.get("owasp", [])
            if str(ref.get("id") or "").startswith("API") and str(ref.get("id") or "").endswith(":2023")
        }
        self.assertEqual(top10, {f"A{i:02d}:2025" for i in range(1, 11)})
        self.assertEqual(api, {f"API{i}:2023" for i in range(1, 11)})

    def test_new_family_grounding_and_writeups_are_exact(self) -> None:
        expected = {
            "software_supply_chain_failure": ({"WSTG-CONF-01", "WSTG-CONF-02"}, {"A03:2025"}, {"CWE-1104", "CWE-1357", "CWE-1395"}, "https://securitylab.github.com/advisories/GHSL-2024-171_QGIS/"),
            "cryptographic_failure": ({"WSTG-CRYP-01"}, {"A04:2025"}, {"CWE-319", "CWE-327", "CWE-338", "CWE-757"}, "https://securitylab.github.com/advisories/GHSL-2021-1012-keypair/"),
            "software_data_integrity_failure": ({"WSTG-CONF-02"}, {"A08:2025"}, {"CWE-345", "CWE-494", "CWE-502", "CWE-829"}, "https://securitylab.github.com/advisories/GHSL-2024-301_274056675_springboot-openai-chatgpt/"),
            "security_logging_alerting_failure": ({"WSTG-CONF-02", "WSTG-ERRH-01"}, {"A09:2025"}, {"CWE-117", "CWE-532", "CWE-778"}, "https://github.com/advisories/GHSA-vqf5-2xx6-9wfm"),
            "exceptional_condition_mishandling": ({"WSTG-ERRH-01", "WSTG-ERRH-02"}, {"A10:2025"}, {"CWE-248", "CWE-636", "CWE-703", "CWE-755"}, "https://securitylab.github.com/advisories/GHSL-2023-116_MySQL/"),
        }
        for family, (wstg, owasp, cwe, url) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertEqual(spec.writeups[0].url, url, family)
            self.assertFalse(spec.writeups[0].counts_as_target_evidence, family)


if __name__ == "__main__":
    unittest.main()
