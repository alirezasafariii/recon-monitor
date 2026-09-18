from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_public_capture as capture


def source(i: int = 0) -> dict:
    return {
        "source_root": f"GHSA-{i:04d}-aaaa-bbbb",
        "source_project": f"owner/project-{i:04d}",
        "family_target": "ssrf",
        "target_cwe": "CWE-918",
        "capture_feasibility": "strong_revision_boundary",
        "version_boundaries": [{
            "ecosystem": "pip",
            "package": "pkg",
            "vulnerable_version_range": "< 2.0.0",
            "first_patched_version": "2.0.0",
        }],
        "reference_inventory": {
            "commits": [f"https://github.com/owner/project-{i:04d}/commit/abcdef1234567890"],
            "compares": [],
            "pulls": [],
            "releases": [],
        },
    }


def advisory(i: int = 0) -> dict:
    return {
        "ghsa_id": f"GHSA-{i:04d}-aaaa-bbbb",
        "cve_id": f"CVE-2026-{10000+i}",
        "summary": "Public advisory summary",
        "severity": "high",
        "published_at": "2026-08-01T00:00:00Z",
        "updated_at": "2026-08-02T00:00:00Z",
        "withdrawn_at": None,
        "repository_advisory_url": f"https://api.github.com/repos/owner/project-{i:04d}/security-advisories/GHSA-{i:04d}-aaaa-bbbb",
        "source_code_location": f"https://github.com/owner/project-{i:04d}",
        "cwes": [{"cwe_id": "CWE-918", "name": "SSRF"}],
        "vulnerabilities": [{
            "package": {"ecosystem": "pip", "name": "pkg"},
            "vulnerable_version_range": "< 2.0.0",
            "first_patched_version": {"identifier": "2.0.0"},
        }],
        "references": [f"https://github.com/owner/project-{i:04d}/commit/abcdef1234567890"],
    }


def commit_payload(i: int = 0) -> dict:
    return {
        "sha": "abcdef1234567890",
        "html_url": f"https://github.com/owner/project-{i:04d}/commit/abcdef1234567890",
        "commit": {
            "tree": {"sha": "tree123"},
            "author": {"date": "2026-08-01T00:00:00Z"},
            "committer": {"date": "2026-08-01T00:00:00Z"},
        },
        "parents": [{"sha": "parent123"}],
        "files": [{
            "filename": "app/module.py",
            "status": "modified",
            "additions": 4,
            "deletions": 2,
            "changes": 6,
            "blob_url": "https://github.com/owner/project/blob/abcdef/app/module.py",
            "raw_url": "https://raw.githubusercontent.com/owner/project/abcdef/app/module.py",
            "patch": "@@ -1 +1 @@\n-old\n+new",
        }],
    }


class PublicSourceCaptureTests(unittest.TestCase):
    def test_advisory_snapshot_is_minimal_and_hashable(self):
        snapshot = capture._selected_advisory_snapshot(advisory())
        self.assertEqual(snapshot["ghsa_id"], "GHSA-0000-AAAA-BBBB")
        self.assertEqual(snapshot["vulnerabilities"][0]["first_patched_version"], "2.0.0")
        self.assertEqual(len(capture._canonical_hash(snapshot)), 64)
        self.assertNotIn("description", snapshot)

    @patch.object(capture, "_api_get_json")
    def test_source_capture_records_revision_pair_without_labeling_it_true(self, mock_get):
        def fake(url: str, token: str = ""):
            if "/advisories/" in url:
                return advisory()
            if "/commits/" in url:
                return commit_payload()
            raise AssertionError(url)
        mock_get.side_effect = fake
        result = capture.capture_source(source(), token="")
        self.assertEqual(result["candidate_fix_commit_sha"], "abcdef1234567890")
        self.assertEqual(result["candidate_vulnerable_parent_sha"], "parent123")
        self.assertEqual(result["capture_channels"]["revision_boundary"], "captured_candidate")
        self.assertFalse(result["boundary_semantics_human_confirmed"])
        self.assertFalse(result["family_label_human_confirmed"])
        self.assertFalse(result["human_verified"])
        self.assertFalse(result["scoring_executed"])
        self.assertFalse(result["target_contact_performed"])

    @patch.object(capture, "_api_get_json")
    def test_patch_content_is_not_persisted_only_hash(self, mock_get):
        mock_get.return_value = commit_payload()
        result = capture._commit_snapshot("owner/project-0000", "abcdef1234567890", token="")
        self.assertNotIn("patch", result["files"][0])
        self.assertEqual(len(result["files"][0]["patch_sha256"]), 64)

    @patch.object(capture, "capture_source")
    def test_100_source_capture_gate(self, mock_capture):
        def fake(row, token=""):
            i = int(row["source_root"].split("-")[1])
            snapshot_hash = f"{i:064x}"[-64:]
            return {
                "source_root": row["source_root"],
                "source_project": row["source_project"],
                "advisory_snapshot_sha256": snapshot_hash,
                "boundary_reference_failure_count": 0,
                "human_verified": False,
                "scoring_executed": False,
                "target_contact_performed": False,
                "capture_channels": {"revision_boundary": "captured_candidate"},
                "planned_variant_evidence": {
                    "positive": "candidate_vulnerable_parent_revision_captured",
                    "secure_negative": "candidate_fix_revision_captured",
                    "near_miss": "control_contract_ready_observation_pending",
                    "sparse_noisy": "literal_public_advisory_snapshot_captured",
                },
            }
        mock_capture.side_effect = fake
        result = capture.capture_all_sources([source(i) for i in range(100)], token="")
        self.assertTrue(result["passed"])
        self.assertEqual(result["captured_source_count"], 100)
        self.assertEqual(result["unique_advisory_snapshot_count"], 100)
        self.assertEqual(result["candidate_revision_pair_count"], 100)
        self.assertEqual(result["literal_sparse_noisy_evidence_count"], 100)
        self.assertEqual(result["human_verified_record_count"], 0)

    def test_reference_url_outside_project_is_not_resolved(self):
        result = capture._reference_snapshot(
            "https://github.com/other/project/commit/abcdef1234567890",
            "owner/project-0000",
            token="",
        )
        self.assertEqual(result["kind"], "unhandled_reference")


if __name__ == "__main__":
    unittest.main()
