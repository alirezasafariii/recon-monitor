from __future__ import annotations

import unittest

import v7_human_review_contract as module


class V7HumanReviewContractTests(unittest.TestCase):
    def test_template_is_balanced_and_unstarted(self) -> None:
        template = module.build_template()
        self.assertEqual(template["family_count"], 36)
        self.assertEqual(template["variant_count"], 144)
        self.assertEqual(template["family_adjudication_required_count"], 11)
        self.assertEqual(
            {slot: load["family_count"] for slot, load in template["reviewer_load"].items()},
            {"reviewer_a": 24, "reviewer_b": 24, "reviewer_c": 24},
        )
        self.assertTrue(all(load["variant_count"] == 96 for load in template["reviewer_load"].values()))
        self.assertFalse(template["human_review_started"])
        self.assertFalse(template["human_review_complete"])
        self.assertEqual(template["human_verified_record_count"], 0)
        self.assertFalse(template["first_blind_consumed"])

    def test_blank_template_structurally_valid_but_not_complete(self) -> None:
        result = module.validate_structure(module.build_template(), require_complete=False)
        self.assertEqual(result["variant_count"], 144)
        self.assertFalse(result["complete_validation"])
        self.assertFalse(result["human_review_complete"])
        self.assertFalse(result["ready_for_evidence_materialization"])

    def test_timezone_aware_timestamp_required(self) -> None:
        with self.assertRaises(RuntimeError):
            module.parse_aware_iso("2026-08-15T12:00:00", "naive")
        parsed = module.parse_aware_iso("2026-08-15T12:00:00+09:00", "aware")
        self.assertIsNotNone(parsed.utcoffset())

    def test_vote_reviewer_id_must_match_assigned_slot(self) -> None:
        review = {
            "primary_votes": [
                {
                    "reviewer_slot": "reviewer_a",
                    "reviewer_id": "wrong-person",
                    "reviewed_at": "2026-08-15T12:00:00+09:00",
                    "decision": "accept_candidate_as_variant",
                    "notes": None,
                    "source_material_checked": True,
                    "engine_output_used": False,
                },
                {
                    "reviewer_slot": "reviewer_b",
                    "reviewer_id": "bob",
                    "reviewed_at": "2026-08-15T12:01:00+09:00",
                    "decision": "accept_candidate_as_variant",
                    "notes": None,
                    "source_material_checked": True,
                    "engine_output_used": False,
                },
            ],
            "tie_break_vote": module.blank_vote("reviewer_c"),
            "tie_break_required": False,
            "consensus_decision": "accept_candidate_as_variant",
            "consensus_notes": None,
            "human_verified": True,
        }
        with self.assertRaises(RuntimeError):
            module._validate_vote_set(
                "case",
                review,
                ["reviewer_a", "reviewer_b"],
                "reviewer_c",
                module.VARIANT_DECISIONS,
                {"reviewer_a": "alice", "reviewer_b": "bob", "reviewer_c": "carol"},
            )

    def test_agreement_does_not_allow_spurious_tie_break(self) -> None:
        review = {
            "primary_votes": [
                {
                    "reviewer_slot": "reviewer_a",
                    "reviewer_id": "alice",
                    "reviewed_at": "2026-08-15T12:00:00+09:00",
                    "decision": "accept_candidate_as_variant",
                    "notes": None,
                    "source_material_checked": True,
                    "engine_output_used": False,
                },
                {
                    "reviewer_slot": "reviewer_b",
                    "reviewer_id": "bob",
                    "reviewed_at": "2026-08-15T12:01:00+09:00",
                    "decision": "accept_candidate_as_variant",
                    "notes": None,
                    "source_material_checked": True,
                    "engine_output_used": False,
                },
            ],
            "tie_break_vote": {
                "reviewer_slot": "reviewer_c",
                "reviewer_id": "carol",
                "reviewed_at": "2026-08-15T12:02:00+09:00",
                "decision": "accept_candidate_as_variant",
                "notes": None,
                "source_material_checked": True,
                "engine_output_used": False,
            },
            "tie_break_required": False,
            "consensus_decision": "accept_candidate_as_variant",
            "consensus_notes": None,
            "human_verified": True,
        }
        with self.assertRaises(RuntimeError):
            module._validate_vote_set(
                "case",
                review,
                ["reviewer_a", "reviewer_b"],
                "reviewer_c",
                module.VARIANT_DECISIONS,
                {"reviewer_a": "alice", "reviewer_b": "bob", "reviewer_c": "carol"},
            )


if __name__ == "__main__":
    unittest.main()
