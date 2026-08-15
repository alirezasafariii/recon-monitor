from __future__ import annotations

import unittest

import v7_semantic_review_packet_v2 as module


class V7SemanticReviewPacketV2Tests(unittest.TestCase):
    def test_stage_artifacts_are_source_metadata_only(self) -> None:
        self.assertEqual(
            set(module.STAGE_ARTIFACTS),
            {"second_pass", "third_pass", "fourth_pass", "sixth_pass", "final_residual_control"},
        )
        for mapping in module.STAGE_ARTIFACTS.values():
            self.assertIn("benchmarks/raw/sources", mapping["resolution"])
            self.assertIn("benchmarks/raw/sources", mapping["literal_material"])

    def test_human_decision_vocab_does_not_auto_confirm(self) -> None:
        self.assertIn("reject_candidate", module.ALLOWED_VARIANT_DECISIONS)
        self.assertIn("needs_additional_source_material", module.ALLOWED_VARIANT_DECISIONS)
        self.assertIn("reject_family_mapping", module.ALLOWED_FAMILY_DECISIONS)
        self.assertNotIn("human_verified", module.ALLOWED_VARIANT_DECISIONS)

    def test_candidate_binding_requires_refs(self) -> None:
        with self.assertRaises(RuntimeError):
            module.candidate_binding("second_pass", "v7-x-positive", {"second_pass": {}})

    def test_output_is_review_metadata_not_final_evidence(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))
        self.assertEqual(module.VERSION, "2.0.0")


if __name__ == "__main__":
    unittest.main()
