from __future__ import annotations

import unittest

import v7_standards_priority0_role_pack as module


class V7Priority0RolePackTests(unittest.TestCase):
    def test_role_classifier_separates_vulnerability_from_fix(self) -> None:
        self.assertEqual(
            module.role_from_heading_and_text("Impact", "An attacker can bypass authorization."),
            "vulnerable_or_impact_state",
        )
        self.assertEqual(
            module.role_from_heading_and_text("Recommended fix", "Upgrade to the patched release."),
            "fixed_or_remediation_state",
        )

    def test_pack_is_source_locked_and_unscored(self) -> None:
        result = module.build()
        self.assertEqual(result["family_count"], 11)
        self.assertEqual(result["capture_count"], 11)
        self.assertTrue(result["source_assignment_locked"])
        self.assertFalse(result["source_replacement_allowed"])
        self.assertFalse(result["source_replacement_used"])
        self.assertFalse(result["standards_count_as_target_evidence"])
        self.assertFalse(result["writeups_count_as_target_evidence"])
        self.assertFalse(result["engine_output_used"])
        self.assertFalse(result["human_review_required"])
        self.assertFalse(result["third_party_code_executed"])
        self.assertFalse(result["target_contact_performed"])
        self.assertFalse(result["scoring_executed"])
        self.assertFalse(result["first_blind_consumed"])

    def test_every_record_is_hash_bound_upstream_text(self) -> None:
        result = module.build()
        for family in result["families"]:
            self.assertTrue(family["source_root"])
            self.assertTrue(family["source_project"])
            for record in family["records"]:
                self.assertTrue(record["text"])
                self.assertEqual(record["text_sha256"], module.sha_text(record["text"]))
                self.assertIn(
                    record["source_state_role"],
                    {
                        "vulnerable_or_impact_state",
                        "vulnerable_parent_state",
                        "fixed_or_remediation_state",
                        "fixed_test_control_state",
                        "unclassified_source_state",
                    },
                )


if __name__ == "__main__":
    unittest.main()
