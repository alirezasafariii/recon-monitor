from __future__ import annotations

import unittest
from unittest.mock import patch

import v7_second_pass_source_capture as mod


class V7SecondPassSourceCaptureTests(unittest.TestCase):
    def test_capture_pair_keeps_semantics_unadjudicated(self) -> None:
        payload = {
            "files": [{"filename": "src/auth.py", "status": "modified", "patch": "@@ -1 +1 @@\n-old\n+new"}]
        }
        with patch.object(mod, "api", return_value=payload), patch.object(
            mod, "file_bytes", side_effect=[b"old\n", b"new\n"]
        ):
            row = mod.capture_pair("acme/widget", "parent", "fix", "token", "identifier")
        self.assertEqual(row["semantic_role"], "unadjudicated_literal_revision_pair_candidate")
        self.assertEqual(row["source_code_file_count"], 1)
        self.assertGreaterEqual(row["source_code_parent_snippet_count"], 1)
        self.assertGreaterEqual(row["source_code_fix_snippet_count"], 1)
        self.assertNotIn("label", row)

    def test_documentation_only_pair_not_counted_as_source_code(self) -> None:
        payload = {
            "files": [{"filename": "CHANGELOG.md", "status": "modified", "patch": "@@ -1 +1 @@\n-old\n+new"}]
        }
        with patch.object(mod, "api", return_value=payload), patch.object(
            mod, "file_bytes", side_effect=[b"old\n", b"new\n"]
        ):
            row = mod.capture_pair("acme/widget", "parent", "fix", "token", "identifier")
        self.assertEqual(row["source_code_file_count"], 0)
        self.assertEqual(row["source_code_parent_snippet_count"], 0)
        self.assertEqual(row["source_code_fix_snippet_count"], 0)

    def test_failed_compare_is_explicit_and_not_promoted(self) -> None:
        with patch.object(mod, "api", side_effect=RuntimeError("no compare")):
            row = mod.capture_compare_pair("acme/widget", "old", "new", "token")
        self.assertEqual(row["failure"], "RuntimeError")
        self.assertEqual(row["files"], [])
        self.assertEqual(row["semantic_role"], "unadjudicated_literal_version_pair_candidate")


if __name__ == "__main__":
    unittest.main()
