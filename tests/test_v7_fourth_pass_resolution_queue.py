from __future__ import annotations

import unittest

import v7_fourth_pass_resolution_queue as module


class V7FourthPassResolutionQueueTests(unittest.TestCase):
    def test_pair_ref_remains_unadjudicated(self) -> None:
        ref = module.pair_ref({
            "parent_sha": "a" * 40,
            "fix_sha": "b" * 40,
            "pair_candidate_sha256": "c" * 64,
            "parent_snippet_count": 2,
            "fix_snippet_count": 3,
            "semantic_role": "unadjudicated_third_pass_literal_revision_pair_candidate",
        })
        self.assertNotIn("label", ref)
        self.assertNotIn("confirmed", ref)

    def test_control_ref_is_metadata_only(self) -> None:
        ref = module.control_ref({
            "path": "tests/test_auth.py",
            "controls": [{"text_sha256": "d" * 64}],
            "semantic_role": "unadjudicated_fourth_pass_upstream_test_control_candidate",
        })
        self.assertEqual(ref["control_count"], 1)
        self.assertNotIn("verdict", ref)

    def test_output_is_not_evidence(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))


if __name__ == "__main__":
    unittest.main()
