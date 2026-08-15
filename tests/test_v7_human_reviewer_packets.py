from __future__ import annotations

import unittest

import v7_human_reviewer_packets as packets


class V7HumanReviewerPacketsTests(unittest.TestCase):
    def test_decision_vocabulary_is_explicit_and_non_semantic(self) -> None:
        self.assertEqual(
            packets.VARIANT_DECISIONS,
            (
                "accept_candidate_as_variant",
                "reject_candidate",
                "needs_additional_source_material",
            ),
        )
        self.assertNotIn("positive", packets.VARIANT_DECISIONS)
        self.assertNotIn("negative", packets.VARIANT_DECISIONS)

    def test_blank_decision_cannot_claim_review(self) -> None:
        vote = packets.blank_decision()
        self.assertIsNone(vote["reviewer_id"])
        self.assertIsNone(vote["decision"])
        self.assertFalse(vote["source_material_checked"])
        self.assertFalse(vote["engine_output_used"])


if __name__ == "__main__":
    unittest.main()
