from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_revision_capture as revision


def pack(i: int = 0) -> dict:
    return {
        "source_root": f"GHSA-{i:04d}-aaaa-bbbb",
        "source_project": f"owner/project-{i:04d}",
        "family_target": "ssrf",
        "target_cwe": "CWE-918",
        "candidate_fix_commit_sha": "fix123",
        "candidate_vulnerable_parent_sha": "parent123",
    }


def fix_commit() -> dict:
    return {
        "sha": "fix123",
        "commit": {"tree": {"sha": "fixtree"}},
        "parents": [{"sha": "parent123"}],
        "files": [
            {
                "filename": "app.py",
                "status": "modified",
                "sha": "fixblob",
                "additions": 2,
                "deletions": 1,
                "changes": 3,
                "patch": "@@ -1 +1 @@\n-old\n+new",
            },
            {
                "filename": "new.py",
                "status": "added",
                "sha": "newblob",
                "additions": 4,
                "deletions": 0,
                "changes": 4,
                "patch": "@@ -0,0 +1 @@\n+new",
            },
        ],
    }


def parent_commit() -> dict:
    return {
        "sha": "parent123",
        "commit": {"tree": {"sha": "parenttree"}},
        "parents": [{"sha": "older"}],
        "files": [],
    }


def tree_payload(sha: str) -> dict:
    if sha == "fixtree":
        return {
            "sha": "fixtree",
            "truncated": False,
            "tree": [
                {"path": "app.py", "type": "blob", "sha": "fixblob", "size": 20, "mode": "100644"},
                {"path": "new.py", "type": "blob", "sha": "newblob", "size": 10, "mode": "100644"},
            ],
        }
    return {
        "sha": "parenttree",
        "truncated": False,
        "tree": [
            {"path": "app.py", "type": "blob", "sha": "parentblob", "size": 18, "mode": "100644"},
        ],
    }


class RevisionPairCaptureTests(unittest.TestCase):
    @patch.object(revision, "_api_get_json")
    def test_exact_pair_captures_parent_fix_blob_identities_without_contents(self, mock_get):
        def fake(url: str, token: str = ""):
            if url.endswith("/commits/fix123"):
                return fix_commit()
            if url.endswith("/commits/parent123"):
                return parent_commit()
            if "fixtree" in url:
                return tree_payload("fixtree")
            if "parenttree" in url:
                return tree_payload("parenttree")
            raise AssertionError(url)
        mock_get.side_effect = fake
        result = revision.capture_revision_pair(pack(), token="")
        self.assertTrue(result["revision_pair_complete"])
        self.assertEqual(result["changed_file_count"], 2)
        modified = next(row for row in result["file_pairs"] if row["filename"] == "app.py")
        added = next(row for row in result["file_pairs"] if row["filename"] == "new.py")
        self.assertEqual(modified["parent_blob_sha"], "parentblob")
        self.assertEqual(modified["fix_blob_sha"], "fixblob")
        self.assertFalse(added["parent_present"])
        self.assertTrue(added["fix_present"])
        self.assertFalse(result["source_contents_persisted"])
        self.assertFalse(result["patch_contents_persisted"])
        self.assertFalse(result["human_verified"])
        self.assertFalse(result["scoring_executed"])
        self.assertFalse(result["target_contact_performed"])

    @patch.object(revision, "_api_get_json")
    def test_tree_truncation_fails_pair_closed(self, mock_get):
        def fake(url: str, token: str = ""):
            if url.endswith("/commits/fix123"):
                return fix_commit()
            if url.endswith("/commits/parent123"):
                return parent_commit()
            payload = tree_payload("fixtree" if "fixtree" in url else "parenttree")
            payload["truncated"] = True
            return payload
        mock_get.side_effect = fake
        result = revision.capture_revision_pair(pack(), token="")
        self.assertFalse(result["revision_pair_complete"])

    @patch.object(revision, "capture_revision_pair")
    def test_all_66_pair_gate_and_unique_hashes(self, mock_pair):
        def fake(row, token=""):
            i = int(row["source_root"].split("-")[1])
            return {
                "source_root": row["source_root"],
                "source_project": row["source_project"],
                "family_target": "ssrf",
                "changed_file_count": 2,
                "revision_pair_complete": True,
                "revision_pair_sha256": f"{i+1:064x}"[-64:],
                "source_contents_persisted": False,
                "patch_contents_persisted": False,
                "human_verified": False,
                "scoring_executed": False,
                "target_contact_performed": False,
            }
        mock_pair.side_effect = fake
        rows = [pack(i) for i in range(66)]
        result = revision.capture_all_pairs(rows, token="")
        self.assertTrue(result["passed"])
        self.assertEqual(result["captured_pair_count"], 66)
        self.assertEqual(result["changed_file_pair_count"], 132)
        self.assertEqual(result["literal_positive_source_boundary_count"], 66)
        self.assertEqual(result["literal_secure_negative_source_boundary_count"], 66)
        self.assertEqual(result["human_verified_record_count"], 0)

    def test_file_pair_detects_fix_blob_mismatch(self):
        changed = {
            "filename": "app.py",
            "status": "modified",
            "fix_blob_sha_from_commit": "wrongblob",
            "patch_sha256": "x",
        }
        parent_tree = {"entries": {"app.py": {"blob_sha": "parentblob", "size": 1}}}
        fix_tree = {"entries": {"app.py": {"blob_sha": "fixblob", "size": 2}}}
        result = revision._file_pair(changed, parent_tree, fix_tree)
        self.assertFalse(result["pair_complete"])


if __name__ == "__main__":
    unittest.main()
