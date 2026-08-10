from __future__ import annotations

import importlib
import unittest
from pathlib import Path

from analysis_standards import FAMILY_STANDARDS, STANDARDS_ENGINE_VERSION
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from family_detectors import DETECTOR_ENGINE_VERSION, detector_rule_ids, evaluate_family_detector, get_detector_spec, validate_detector_registry
from family_detectors.registry import DETECTOR_SPECS


class PhysicalFamilyDetectors690Tests(unittest.TestCase):
    def test_exact_31_family_physical_coverage(self):
        self.assertEqual(set(DETECTOR_SPECS), set(FAMILY_ADMISSION_POLICIES))
        self.assertEqual(len(DETECTOR_SPECS), 31)
        infrastructure = {"__init__", "base", "registry", "execution"}
        modules = {p.stem for p in Path("app/family_detectors").glob("*.py")} - infrastructure
        self.assertEqual(modules, set(FAMILY_ADMISSION_POLICIES))
        self.assertEqual(validate_detector_registry(), [])

    def test_every_module_is_importable_and_named_for_its_family(self):
        for family in FAMILY_ADMISSION_POLICIES:
            module = importlib.import_module(f"family_detectors.{family}")
            self.assertEqual(module.SPEC.family, family)
            self.assertTrue(module.SPEC.strategy)

    def test_wstg_and_cwe_are_exactly_bound_to_canonical_standards(self):
        for family, spec in DETECTOR_SPECS.items():
            standards = FAMILY_STANDARDS[family]
            self.assertEqual(spec.wstg_ids, tuple(x["id"] for x in standards["wstg"]))
            self.assertEqual(spec.cwe_ids, tuple(x["id"] for x in standards["cwe"]))
            self.assertTrue(spec.wstg_ids)
            self.assertTrue(spec.cwe_ids)

    def test_bfla_uses_current_explicit_api_wstg(self):
        spec = get_detector_spec("broken_function_authorization")
        self.assertIn("WSTG-APIT-04", spec.wstg_ids)
        self.assertIn("WSTG-ATHZ-02", spec.wstg_ids)
        self.assertIn("WSTG-ATHZ-03", spec.wstg_ids)

    def test_writeups_are_context_only_never_target_evidence(self):
        for family, spec in DETECTOR_SPECS.items():
            self.assertTrue(spec.writeups, family)
            for ref in spec.writeups:
                self.assertTrue(ref.url.startswith("https://"), (family, ref.url))
                self.assertFalse(ref.counts_as_target_evidence, family)
                self.assertIn(ref.relation, {"exact", "exact_pattern", "adjacent_primary_case"})
        result = evaluate_family_detector("ssrf", [{"type": "url_parameter", "source": "schema"}], [])
        serialized_support = repr(result["support"])
        self.assertNotIn("securitylab.github.com", serialized_support)
        self.assertNotIn("WSTG-INPV-19", serialized_support)
        self.assertNotIn("CWE-918", serialized_support)

    def test_condition_and_control_contract_comes_from_admission_policy(self):
        for family, spec in DETECTOR_SPECS.items():
            policy = FAMILY_ADMISSION_POLICIES[family]
            expected_condition = set(policy["required"][-1]) | set(policy.get("override_signals", set()))
            self.assertEqual(set(spec.condition_signals), expected_condition, family)
            self.assertEqual(set(spec.blocking_controls), set(policy.get("blocking_contradictions", set())), family)

    def test_cross_family_signal_stays_surface_in_wrong_detector(self):
        sql = evaluate_family_detector("sql_injection", [
            {"type": "body_parameter", "source": "schema"},
            {"type": "sql_query_surface", "source": "semantic"},
            {"type": "query_structure_influence", "source": "stored_behavior"},
        ], [])
        self.assertEqual(sql["support"][-1]["detector_signal_class"], "condition")
        nosql = evaluate_family_detector("nosql_injection", sql["support"], [])
        self.assertEqual(nosql["rejected_cross_family_count"], len(sql["support"]))

    def test_unscoped_confounder_is_preserved_but_cannot_count_for_wrong_family(self):
        redirect = evaluate_family_detector("open_redirect", [
            {"type": "url_parameter", "source": "schema"},
            {"type": "server_fetch_observed", "source": "stored_behavior"},
        ], [])
        classes = {x["type"]: x["detector_signal_class"] for x in redirect["support"]}
        self.assertEqual(classes["url_parameter"], "surface")
        self.assertEqual(classes["server_fetch_observed"], "surface")
        self.assertFalse(any(x["detector_counts_as_target_evidence"] for x in redirect["support"]))

    def test_ssrf_vs_open_redirect_is_physical_not_score_only(self):
        ssrf = get_detector_spec("ssrf")
        redirect = get_detector_spec("open_redirect")
        self.assertIn("open_redirect", ssrf.confounders)
        self.assertIn("ssrf", redirect.confounders)
        self.assertIn("server_fetch_observed", ssrf.condition_signals)
        self.assertNotIn("server_fetch_observed", redirect.condition_signals)
        self.assertIn("external_destination", redirect.condition_signals)
        self.assertNotIn("external_destination", ssrf.condition_signals)

    def test_sql_nosql_command_ssti_have_distinct_interpreter_conditions(self):
        sql = get_detector_spec("sql_injection")
        nosql = get_detector_spec("nosql_injection")
        cmd = get_detector_spec("command_injection")
        ssti = get_detector_spec("server_side_template_injection")
        self.assertIn("query_structure_influence", sql.condition_signals)
        self.assertIn("nosql_operator_accepted", nosql.condition_signals)
        self.assertIn("command_output_observed", cmd.condition_signals)
        self.assertIn("template_expression_evaluated", ssti.condition_signals)
        self.assertNotIn("template_expression_evaluated", cmd.condition_signals)
        self.assertNotIn("command_output_observed", ssti.condition_signals)

    def test_file_upload_and_path_traversal_are_not_interchangeable(self):
        upload = get_detector_spec("file_upload")
        traversal = get_detector_spec("path_traversal")
        self.assertIn("dangerous_type_accepted", upload.condition_signals)
        self.assertNotIn("dangerous_type_accepted", traversal.condition_signals)
        self.assertIn("path_escape_observed", traversal.condition_signals)
        self.assertNotIn("path_escape_observed", upload.condition_signals)

    def test_detector_rule_ids_are_taxonomy_metadata_not_evidence(self):
        rules = detector_rule_ids("broken_object_authorization")
        self.assertTrue(any(x.startswith("physical-detector:") for x in rules))
        self.assertIn("wstg:WSTG-APIT-02", rules)
        self.assertIn("cwe:CWE-639", rules)

    def test_versions(self):
        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.0.0")
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.2.0")


if __name__ == "__main__":
    unittest.main()
