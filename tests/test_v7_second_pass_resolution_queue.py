from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import v7_second_pass_resolution_queue as module


class V7SecondPassResolutionQueueTests(unittest.TestCase):
    def test_pair_ref_never_adjudicates_semantics(self) -> None:
        pair = {
            "parent_sha": "a" * 40,
            "fix_sha": "b" * 40,
            "basis": "identifier_or_frozen_reference",
            "pair_candidate_sha256": "c" * 64,
            "source_code_file_count": 2,
            "source_code_parent_snippet_count": 3,
            "source_code_fix_snippet_count": 4,
            "test_control_candidate_count": 1,
            "failure": None,
            "semantic_role": "unadjudicated_literal_revision_pair_candidate",
        }
        ref = module.pair_ref(pair)
        self.assertEqual(ref["semantic_role"], "unadjudicated_literal_revision_pair_candidate")
        self.assertNotIn("label", ref)
        self.assertNotIn("verdict", ref)
        self.assertNotIn("confirmed", ref)

    def test_rule_version_is_unscored_second_pass(self) -> None:
        self.assertEqual(module.VERSION, "1.0.0")
        self.assertIn("second-pass.resolve", module.RULE_VERSION)

    def test_output_paths_are_benchmark_source_metadata_only(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertIn("benchmarks/raw/sources", str(module.REPORT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))


if __name__ == "__main__":
    unittest.main()
