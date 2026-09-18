from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_coverage_capture as coverage_capture


def candidate(family: str = "host_header_injection") -> dict:
    return {
        "source_root": "GHSA-AAAA-BBBB-CCCC",
        "source_project": "owner/project",
        "family_target": family,
        "target_cwe": None,
    }


def assessed(family: str, feasibility: str = "strong_revision_boundary") -> dict:
    return {
        **candidate(family),
        "family_hints": [family],
        "source_taxonomy_match": {
            "family_target": family,
            "target_cwe": None,
            "target_cwe_present": False,
        },
        "capture_feasibility": feasibility,
    }


def pack(summary: str = "Host Header Injection in reset links", exact: bool = True) -> dict:
    return {
        "source_root": "GHSA-AAAA-BBBB-CCCC",
        "source_project": "owner/project",
        "advisory_snapshot": {
            "ghsa_id": "GHSA-AAAA-BBBB-CCCC",
            "summary": summary,
            "cwes": [],
        },
        "candidate_fix_commit_sha": "f" * 40 if exact else None,
        "candidate_vulnerable_parent_sha": "a" * 40 if exact else None,
    }


class CorpusV1CoverageCaptureTests(unittest.TestCase):
    @patch.object(coverage_capture, "capture_revision_pair")
    @patch.object(coverage_capture, "capture_source")
    @patch.object(coverage_capture, "assess_source")
    @patch.object(coverage_capture, "_api_get_json")
    def test_exact_revision_candidate_is_captured_without_fixed_count_gate(
        self,
        api_get,
        assess,
        source_capture,
        revision_capture,
    ):
        api_get.return_value = {"ghsa_id": "GHSA-AAAA-BBBB-CCCC"}
        assess.return_value = assessed("host_header_injection")
        source_capture.return_value = pack()
        revision_capture.return_value = {
            "revision_pair_complete": True,
            "revision_pair_sha256": "1" * 64,
        }

        result = coverage_capture.capture_coverage_candidates(
            [candidate()],
            token="token",
        )

        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["assessed_count"], 1)
        self.assertEqual(result["public_source_pack_count"], 1)
        self.assertEqual(result["revision_pair_count"], 1)
        self.assertEqual(result["resolved_family_count"], 1)
        self.assertEqual(result["exact_revision_family_count"], 1)
        self.assertEqual(
            result["cases"][0]["coverage_level"],
            "exact_revision_boundary",
        )
        self.assertTrue(result["safety"]["frozen_v1_artifacts_not_rewritten"])

    @patch.object(coverage_capture, "capture_source")
    @patch.object(coverage_capture, "assess_source")
    @patch.object(coverage_capture, "_api_get_json")
    def test_version_boundary_is_preserved_when_no_exact_commit_exists(
        self,
        api_get,
        assess,
        source_capture,
    ):
        api_get.return_value = {"ghsa_id": "GHSA-AAAA-BBBB-CCCC"}
        assess.return_value = assessed(
            "backup_unreferenced_file_exposure",
            "version_boundary_available",
        )
        source_capture.return_value = pack(
            summary="Backup file exposure",
            exact=False,
        )

        result = coverage_capture.capture_coverage_candidates(
            [candidate("backup_unreferenced_file_exposure")],
        )

        self.assertEqual(result["revision_pair_count"], 0)
        self.assertEqual(result["resolved_family_count"], 1)
        self.assertEqual(result["exact_revision_family_count"], 0)
        self.assertEqual(
            result["cases"][0]["coverage_level"],
            "version_boundary",
        )

    def test_duplicate_project_is_rejected_fail_closed(self):
        rows = [
            candidate(),
            {
                **candidate("business_logic"),
                "source_root": "GHSA-DDDD-EEEE-FFFF",
            },
        ]
        with patch.object(
            coverage_capture,
            "_api_get_json",
            return_value={"ghsa_id": "GHSA-AAAA-BBBB-CCCC"},
        ), patch.object(
            coverage_capture,
            "assess_source",
            return_value=assessed("host_header_injection"),
        ), patch.object(
            coverage_capture,
            "capture_source",
            return_value=pack(exact=False),
        ):
            result = coverage_capture.capture_coverage_candidates(rows)

        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual(result["case_count"], 1)
        self.assertEqual(result["failure_count"], 1)
        self.assertEqual(
            result["failures"][0]["error"],
            "duplicate_source_project",
        )


if __name__ == "__main__":
    unittest.main()
