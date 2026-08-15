from __future__ import annotations

import unittest

import v7_standards_priority0_deep_reference as module


class V7Priority0DeepReferenceTests(unittest.TestCase):
    def test_same_project_filter_is_strict(self) -> None:
        project = "owner/repo"
        self.assertTrue(module._same_project_url("https://github.com/owner/repo/commit/abc", project))
        self.assertTrue(module._same_project_url("https://github.com/owner/repo/pull/12", project))
        self.assertFalse(module._same_project_url("https://github.com/other/repo/commit/abc", project))
        self.assertFalse(module._same_project_url("https://example.com/owner/repo/commit/abc", project))
        self.assertFalse(module._same_project_url("https://github.com/owner/repo/wiki/x", project))

    def test_patch_partition_keeps_removed_and_added_states_separate(self) -> None:
        patch = "@@ -1,2 +1,2 @@\n-dangerous shell command injection\n+validated safe command allowlist\n context"
        rows = module._patch_records(
            "command_injection",
            patch,
            url="https://github.com/sebhildebrandt/systeminformation/commit/abc",
            filename="lib/x.js",
            origin="unit_patch",
            ref_metadata={},
        )
        roles = {row["source_state_role"] for row in rows}
        self.assertIn("vulnerable_parent_state", roles)
        self.assertIn("fixed_or_remediation_state", roles)
        for row in rows:
            self.assertEqual(row["text_sha256"], module.sha_text(row["text"]))

    def test_github_api_mapping_never_changes_project(self) -> None:
        project = "owner/repo"
        kind, api = module._github_api("https://github.com/owner/repo/issues/7", project) or (None, None)
        self.assertEqual(kind, "issue")
        self.assertIn("/repos/owner/repo/issues/7", api or "")
        self.assertIsNone(module._github_api("https://github.com/owner/other/issues/7", project))

    def test_standard_and_writeup_terms_only_drive_selection(self) -> None:
        terms = module._family_query_tokens("sql_injection")
        self.assertTrue(terms)
        self.assertTrue(module._relevant("sql_injection", "SQL query injection reaches database query execution"))
        # The resulting record remains literal source text; no standard text is
        # inserted into the body or promoted to evidence.
        row = module._record(
            "sql_injection",
            "unit",
            "vulnerable_or_impact_state",
            "SQL query injection reaches database query execution",
            url="https://github.com/owner/repo/issues/1",
        )
        self.assertIsNotNone(row)
        self.assertNotIn("WSTG", row["text"])


if __name__ == "__main__":
    unittest.main()
