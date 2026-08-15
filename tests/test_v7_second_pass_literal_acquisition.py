from __future__ import annotations

import unittest
from unittest.mock import patch

import v7_second_pass_literal_acquisition as mod


class V7SecondPassLiteralAcquisitionTests(unittest.TestCase):
    def test_identifiers_are_only_frozen_public_ids(self) -> None:
        row = {
            "snapshot_payload": {
                "ghsa_id": "GHSA-abcd-1234-efgh",
                "cve_id": "CVE-2026-12345",
                "description": "also CVE-2026-12345 and GHSA-abcd-1234-efgh",
            }
        }
        self.assertEqual(
            mod.identifiers(row, "GHSA-abcd-1234-efgh"),
            ["GHSA-ABCD-1234-EFGH", "CVE-2026-12345"],
        )

    def test_link_extraction_rejects_cross_project_references(self) -> None:
        value = " ".join(
            [
                "https://github.com/acme/widget/commit/abcdef1234567",
                "https://github.com/acme/widget/pull/42",
                "https://github.com/acme/widget/issues/41",
                "https://github.com/evil/other/commit/deadbeef12345",
            ]
        )
        commits, pulls, issues = mod.extract_linked_refs(value, "acme/widget")
        self.assertEqual(commits, {"abcdef1234567"})
        self.assertEqual(pulls, {42})
        self.assertEqual(issues, {41})

    def test_version_tag_candidates_remain_unadjudicated(self) -> None:
        tags = [
            {"name": "v2.0.0", "commit": {"sha": "fixsha"}},
            {"name": "v1.9.9", "commit": {"sha": "oldsha"}},
        ]
        with patch.object(mod, "repo_api", return_value=tags):
            rows = mod.version_tag_candidates(
                "acme/widget",
                [{"patched_version": "2.0.0", "vulnerable_version_range": "< 2.0.0"}],
                "token",
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["patched_tag_commit_sha"], "fixsha")
        self.assertEqual(rows[0]["adjacent_older_tag_commit_sha"], "oldsha")
        self.assertEqual(rows[0]["semantic_role"], "unadjudicated_version_boundary_candidate")

    def test_commit_candidate_does_not_adjudicate_semantics(self) -> None:
        payload = {
            "sha": "abc123",
            "html_url": "https://github.com/acme/widget/commit/abc123",
            "parents": [{"sha": "parent123"}],
            "commit": {"message": "fix security regression"},
            "files": [
                {
                    "filename": "tests/test_security.py",
                    "status": "modified",
                    "patch": "@@ -1 +1 @@\n-old\n+new",
                }
            ],
        }
        with patch.object(mod, "repo_api", return_value=payload), patch.object(
            mod, "file_bytes", return_value=b"def test_safe():\n    assert True\n"
        ):
            row = mod.commit_candidate("acme/widget", "abc123", "token", ["identifier_search:CVE-2026-1"])
        self.assertIsNotNone(row)
        assert row is not None
        self.assertTrue(row["single_parent_pair_candidate"])
        self.assertEqual(row["semantic_role"], "unadjudicated_identifier_linked_revision_candidate")
        self.assertNotIn("label", row)


if __name__ == "__main__":
    unittest.main()
