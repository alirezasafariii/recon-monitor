from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, validate_family_standards
from family_detectors import DETECTOR_ENGINE_VERSION, detector_rule_ids, get_detector_spec, validate_detector_registry
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from static_family_collectors import STATIC_SPECIALIZED_COLLECTOR_RULE_VERSION, STATIC_SPECIALIZED_FAMILIES, validate_static_specialized_collectors


class Analysis624SealTests(unittest.TestCase):
    def test_analysis_layer_versions_are_sealed_at_624(self) -> None:
        import analysis_engine
        import bug_candidates
        import security_reasoning

        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.24.0")
        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.24.0")
        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.24.0")
        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.24")
        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.24")
        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.24")
        self.assertEqual(STATIC_SPECIALIZED_COLLECTOR_RULE_VERSION, "2026.08.12.6.24")
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")
        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.1.0")
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")

    def test_all_31_families_keep_four_layer_grounding(self) -> None:
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])
        self.assertEqual(validate_static_specialized_collectors(), [])
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

    def test_specialized_static_family_grounding_is_exact(self) -> None:
        self.assertEqual(set(STATIC_SPECIALIZED_FAMILIES), {
            "source_map_exposure", "secret_exposure", "graphql_authorization",
            "graphql_data_exposure", "websocket_authorization",
        })
        expected = {
            "source_map_exposure": ({"WSTG-CONF-04"}, {"A01:2025"}, {"CWE-200"}),
            "secret_exposure": ({"WSTG-CONF-04"}, {"A07:2025"}, {"CWE-798", "CWE-200"}),
            "graphql_authorization": ({"WSTG-APIT-02", "WSTG-ATHZ-02"}, {"API1:2023", "A01:2025"}, {"CWE-862", "CWE-863"}),
            "graphql_data_exposure": ({"WSTG-APIT-03"}, {"API3:2023", "A01:2025"}, {"CWE-200"}),
            "websocket_authorization": ({"WSTG-CLNT-10", "WSTG-ATHZ-02"}, {"A01:2025"}, {"CWE-862", "CWE-863"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
        self.assertEqual(get_detector_spec("source_map_exposure").writeups[0].url, "https://nvd.nist.gov/vuln/detail/CVE-2024-27257")
        self.assertEqual(get_detector_spec("graphql_authorization").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2025-130_Sentry/")
        self.assertEqual(get_detector_spec("websocket_authorization").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2025-117_GHSL-2025-118_Outline/")


if __name__ == "__main__":
    unittest.main()
