from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS, OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, standards_for_family, validate_family_standards
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission, knowledge_for_family


class AnalysisStandardsV630Tests(unittest.TestCase):
    def test_every_admission_family_has_wstg_owasp_and_cwe_grounding(self):
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")
        self.assertEqual(set(FAMILY_STANDARDS), set(FAMILY_ADMISSION_POLICIES))
        self.assertGreaterEqual(len(FAMILY_STANDARDS), 31)
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        for family, profile in FAMILY_STANDARDS.items():
            self.assertTrue(profile["wstg"], family)
            self.assertTrue(profile["owasp"], family)
            self.assertTrue(profile["cwe"], family)
            self.assertTrue(all(item["id"].startswith("WSTG-") for item in profile["wstg"]), family)
            self.assertTrue(all(item["id"].startswith(("A", "API")) for item in profile["owasp"]), family)
            self.assertTrue(all(item["id"].startswith("CWE-") for item in profile["cwe"]), family)

    def test_standards_never_admit_a_surface_by_themselves(self):
        for family in FAMILY_ADMISSION_POLICIES:
            result = assess_admission(
                family,
                [
                    {"type": "wstg_reference", "source": "OWASP WSTG", "source_group": "knowledge"},
                    {"type": "owasp_reference", "source": "OWASP Top 10", "source_group": "knowledge"},
                    {"type": "cwe_reference", "source": "MITRE CWE", "source_group": "knowledge"},
                ],
                [],
            )
            self.assertFalse(result["admitted"], (family, result))
            self.assertIn("standards", result)
            self.assertEqual(result["standards"]["assigned_cwe"], [])

    def test_direct_cwe_is_assigned_only_after_admission(self):
        near = assess_admission(
            "sql_injection",
            [
                {"type": "input_parameter", "source": "endpoint_schema", "source_group": "input_surface"},
                {"type": "sql_query_surface", "source": "semantic", "source_group": "query_surface"},
            ],
            [],
        )
        self.assertFalse(near["admitted"])
        self.assertEqual(near["standards"]["assigned_cwe"], [])

        admitted = assess_admission(
            "sql_injection",
            [
                {"type": "input_parameter", "source": "endpoint_schema", "source_group": "input_surface"},
                {"type": "sql_query_surface", "source": "semantic", "source_group": "query_surface"},
                {"type": "database_time_delay_observed", "source": "stored_behavior", "source_group": "database_behavior"},
            ],
            [],
        )
        self.assertTrue(admitted["admitted"])
        self.assertEqual(admitted["standards"]["assigned_cwe"], ["CWE-89"])

    def test_broad_family_uses_decisive_signal_for_cwe(self):
        result = assess_admission(
            "security_misconfiguration",
            [
                {"type": "debug_surface", "source": "semantic", "source_group": "configuration_surface"},
                {"type": "stack_trace_exposed", "source": "stored_behavior", "source_group": "configuration_behavior"},
            ],
            [],
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["standards"]["assigned_cwe"], ["CWE-209"])

        result = assess_admission(
            "security_misconfiguration",
            [
                {"type": "deployment_configuration_surface", "source": "semantic", "source_group": "configuration_surface"},
                {"type": "debug_mode_exposed", "source": "stored_behavior", "source_group": "configuration_behavior"},
            ],
            [],
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["standards"]["assigned_cwe"], ["CWE-489"])

    def test_knowledge_references_include_wstg_owasp_and_cwe_for_every_family(self):
        for family in FAMILY_ADMISSION_POLICIES:
            refs = knowledge_for_family(family)
            sources = {str(item.get("source") or "") for item in refs}
            self.assertIn("OWASP WSTG", sources, family)
            self.assertTrue({"OWASP Top 10", "OWASP API Security Top 10"} & sources, family)
            self.assertIn("MITRE CWE", sources, family)

    def test_contextual_families_do_not_force_ambiguous_root_cause(self):
        profile = standards_for_family(
            "broken_function_authorization",
            admitted=True,
            decisive_signals={"privileged_function", "state_change", "lower_privilege_success"},
        )
        self.assertEqual(profile["assigned_cwe"], [])
        self.assertEqual(profile["assignment_state"], "manual_root_cause_review")
        self.assertEqual({item["id"] for item in profile["cwe"]}, {"CWE-862", "CWE-863"})


if __name__ == "__main__":
    unittest.main()
