from __future__ import annotations

import unittest

import v7_sixth_pass_resolution_queue as module


class V7SixthPassResolutionQueueTests(unittest.TestCase):
    def test_release_ref_is_unadjudicated_metadata(self) -> None:
        ref = module.release_ref({
            "parent_sha": "a" * 40,
            "fix_sha": "b" * 40,
            "fixed_release_tag": "v2.0.1",
            "adjacent_older_tag": "v2.0.0",
            "source_code_parent_snippet_count": 3,
            "source_code_fix_snippet_count": 4,
            "semantic_role": "unadjudicated_sixth_pass_explicit_release_boundary_candidate",
        })
        self.assertNotIn("label", ref)
        self.assertNotIn("confirmed", ref)
        self.assertEqual(ref["source_code_parent_snippet_count"], 3)

    def test_tree_test_ref_is_metadata_only(self) -> None:
        ref = module.tree_test_ref({
            "path": "tests/auth/test_graphql.py",
            "ref": "main",
            "tree_sha": "c" * 40,
            "path_term_match_count": 2,
            "file_sha256": "d" * 64,
            "test_case_count": 5,
            "semantic_role": "unadjudicated_sixth_pass_adjacent_tree_test_file_candidate",
        })
        self.assertEqual(ref["test_case_count"], 5)
        self.assertNotIn("verdict", ref)

    def test_resolution_reads_item_level_fourth_pass_queue(self) -> None:
        self.assertIn("v7_fourth_pass_resolution_queue.json", str(module.FOURTH_RESOLUTION))
        self.assertEqual(module.VERSION, "1.0.1")


if __name__ == "__main__":
    unittest.main()
