from __future__ import annotations

import unittest

import v7_third_pass_resolution_queue as module


class V7ThirdPassResolutionQueueTests(unittest.TestCase):
    def test_pair_ref_remains_unadjudicated(self) -> None:
        pair = {
            "parent_sha": "a" * 40,
            "fix_sha": "b" * 40,
            "discovery_basis": "release_range_commit",
            "pair_candidate_sha256": "c" * 64,
            "parent_snippet_count": 4,
            "fix_snippet_count": 5,
            "test_control_candidate_count": 1,
            "semantic_role": "unadjudicated_third_pass_literal_revision_pair_candidate",
        }
        ref = module.pair_ref(pair)
        self.assertEqual(ref["semantic_role"], "unadjudicated_third_pass_literal_revision_pair_candidate")
        self.assertNotIn("label", ref)
        self.assertNotIn("confirmed", ref)

    def test_output_never_targets_evidence_directory(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))
        self.assertIn("third-pass.resolve", module.RULE_VERSION)


if __name__ == "__main__":
    unittest.main()
