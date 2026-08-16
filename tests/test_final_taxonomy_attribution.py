from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_specs.registry import MIGRATED_FAMILIES, get_detection_spec, validate_family_spec_registry
from family_specs.taxonomy_attribution import evaluate_taxonomy_attribution
from hypothesis_admission import assess_admission


class FinalTaxonomyAttributionTests(unittest.TestCase):
    def test_every_migrated_reference_has_exactly_one_policy(self):
        self.assertEqual(validate_family_spec_registry(), [])
        for family in MIGRATED_FAMILIES:
            spec = get_detection_spec(family)
            expected = {
                (namespace, ref)
                for namespace, refs in spec.taxonomy().items()
                for ref in refs
            }
            actual = {
                (item["namespace"], item["ref"])
                for item in spec.taxonomy_attribution_policy()
            }
            self.assertEqual(actual, expected, family)
            self.assertEqual(len(actual), len(spec.taxonomy_attribution_policy()), family)

    def test_sql_injection_cwe_is_assigned_only_after_admission(self):
        hidden = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request"},
            {"type": "sql_query_sink", "source_group": "sink"},
        ])
        self.assertFalse(hidden["admitted"])
        self.assertEqual(hidden["taxonomy_attribution"]["assigned_taxonomy"]["cwe"], [])

        admitted = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request"},
            {"type": "sql_query_sink", "source_group": "sink"},
            {"type": "sql_query_influence_observed", "source_group": "behavior"},
        ])
        self.assertTrue(admitted["admitted"])
        self.assertIn("CWE-89", admitted["taxonomy_attribution"]["assigned_taxonomy"]["cwe"])
        self.assertFalse(admitted["taxonomy_attribution"]["counts_as_target_evidence"])

    def test_bfla_generic_authorization_cwes_remain_manual(self):
        spec = get_detection_spec("broken_function_authorization")
        packet = evaluate_taxonomy_attribution(
            spec,
            admitted=True,
            decisive_signals={"privileged_function", "state_change", "unauthorized_function_success"},
        )
        self.assertEqual(packet["assigned_taxonomy"]["cwe"], [])
        manual_refs = {item["ref"] for item in packet["manual_review"]}
        self.assertIn("CWE-862", manual_refs)
        self.assertIn("CWE-863", manual_refs)

    def test_authentication_cwe_assignment_is_condition_specific(self):
        spec = get_detection_spec("authentication_session")
        recovery = evaluate_taxonomy_attribution(
            spec, admitted=True, decisive_signals={"recovery_bypass"}
        )
        self.assertIn("CWE-640", recovery["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-287", recovery["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-613", recovery["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-384", recovery["assigned_taxonomy"]["cwe"])

        logout = evaluate_taxonomy_attribution(
            spec, admitted=True, decisive_signals={"session_reuse_after_logout"}
        )
        self.assertIn("CWE-613", logout["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-640", logout["assigned_taxonomy"]["cwe"])

        non_rotation = evaluate_taxonomy_attribution(
            spec, admitted=True, decisive_signals={"token_not_rotated"}
        )
        self.assertNotIn("CWE-384", non_rotation["assigned_taxonomy"]["cwe"])

    def test_wstg_and_capec_never_auto_assign(self):
        for family in MIGRATED_FAMILIES:
            spec = get_detection_spec(family)
            packet = evaluate_taxonomy_attribution(
                spec,
                admitted=True,
                decisive_signals={
                    signal
                    for group in spec.promotion_required
                    for signal in group
                },
            )
            self.assertEqual(packet["assigned_taxonomy"]["wstg"], [], family)
            self.assertEqual(packet["assigned_taxonomy"]["capec"], [], family)

    def test_graphql_object_boundary_can_assign_specific_key_bypass_cwe(self):
        spec = get_detection_spec("graphql_authorization")
        packet = evaluate_taxonomy_attribution(
            spec,
            admitted=True,
            decisive_signals={"graphql_authorization_differential"},
        )
        self.assertIn("CWE-639", packet["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-862", packet["assigned_taxonomy"]["cwe"])
        self.assertNotIn("CWE-863", packet["assigned_taxonomy"]["cwe"])

    def test_taxonomy_assignment_does_not_create_admission(self):
        spec = get_detection_spec("ssrf")
        taxonomy = evaluate_taxonomy_attribution(
            spec, admitted=False, decisive_signals={"server_fetch_observed"}
        )
        self.assertEqual(taxonomy["assigned_taxonomy"]["cwe"], [])
        self.assertEqual(taxonomy["assignment_state"], "not_admitted")


if __name__ == "__main__":
    unittest.main()
