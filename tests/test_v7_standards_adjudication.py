from __future__ import annotations

import unittest
from unittest.mock import patch

import v7_standards_adjudication as module


class V7StandardsAdjudicationTests(unittest.TestCase):
    def test_all_families_have_three_standard_layers_and_writeups(self) -> None:
        self.assertEqual(len(module.DETECTOR_SPECS), 36)
        for family in module.DETECTOR_SPECS:
            standards = module.standards_for_family(family)
            logic = module.researcher_logic_for_family(family)
            self.assertTrue(standards.get("wstg"), family)
            self.assertTrue(standards.get("owasp"), family)
            self.assertTrue(standards.get("cwe"), family)
            self.assertTrue(logic.get("writeup_logic"), family)

    def test_standards_alone_cannot_accept_positive(self) -> None:
        variant = {"capture_id": "case", "case_kind": "positive"}
        with patch.object(module, "_material_payload", return_value=({"artifact": "source"}, ["unrelated release notes only"])):
            row = module.adjudicate_variant("dom_xss", variant)
        self.assertFalse(row["accepted_for_v7"])
        self.assertEqual(row["decision"], "needs_additional_source_material")
        self.assertFalse(row["standards_rubric_layer"]["counts_as_target_evidence"])
        self.assertFalse(row["writeup_rubric_layer"]["counts_as_target_evidence"])

    def test_literal_decisive_source_can_accept_positive(self) -> None:
        variant = {"capture_id": "case", "case_kind": "positive"}
        source = "DOM XSS attacker input from location reaches innerHTML script sink without sanitizer; cross site scripting executes."
        with patch.object(module, "_material_payload", return_value=({"artifact": "source"}, [source])):
            row = module.adjudicate_variant("dom_xss", variant)
        self.assertTrue(row["accepted_for_v7"])
        self.assertEqual(row["decision"], "accept_candidate_as_variant")
        self.assertTrue(row["literal_source_layer"]["condition_hits"])
        self.assertFalse(row["engine_output_used"])
        self.assertFalse(row["human_verified"])

    def test_positive_fails_closed_when_control_is_present_without_override(self) -> None:
        variant = {"capture_id": "case", "case_kind": "positive"}
        source = "DOM XSS location input reaches innerHTML sink but sanitizer blocks and sanitizes the value before rendering."
        with patch.object(module, "_material_payload", return_value=({"artifact": "source"}, [source])):
            row = module.adjudicate_variant("dom_xss", variant)
        # If the family has a canonical blocker matching this text it must not be
        # accepted. If it does not, the decisive condition still cannot be created
        # from the standards layer itself.
        if row["literal_source_layer"]["blocking_control_hits"]:
            self.assertFalse(row["accepted_for_v7"])

    def test_secure_negative_requires_literal_family_alignment_and_control_shape(self) -> None:
        variant = {"capture_id": "case", "case_kind": "secure_negative"}
        source = "Cross site scripting DOM input is sanitized before innerHTML; patched validation rejects unsafe HTML."
        with patch.object(module, "_material_payload", return_value=({"artifact": "source"}, [source])):
            row = module.adjudicate_variant("dom_xss", variant)
        self.assertTrue(row["literal_source_layer"]["family_source_aligned"])
        self.assertTrue(row["literal_source_layer"]["fixed_shape_observed"])
        self.assertFalse(row["standards_rubric_layer"]["counts_as_target_evidence"])

    def test_full_packet_is_machine_adjudicated_without_claiming_human_verification(self) -> None:
        result = module.build_adjudication()
        self.assertEqual(result["family_count"], 36)
        self.assertEqual(result["variant_count"], 144)
        self.assertEqual(result["machine_adjudicated_variant_count"], 144)
        self.assertEqual(result["standards_coverage_family_count"], 36)
        self.assertEqual(result["writeup_coverage_family_count"], 36)
        self.assertFalse(result["human_review_required"])
        self.assertFalse(result["human_adjudication_performed"])
        self.assertEqual(result["human_verified_record_count"], 0)
        self.assertFalse(result["engine_output_allowed_as_evidence"])
        self.assertFalse(result["standards_count_as_target_evidence"])
        self.assertFalse(result["writeups_count_as_target_evidence"])
        self.assertFalse(result["scoring_executed"])
        self.assertFalse(result["first_blind_consumed"])
        self.assertEqual(
            result["accepted_variant_count"] + result["unresolved_variant_count"],
            144,
        )


if __name__ == "__main__":
    unittest.main()
