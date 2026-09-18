from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_feasibility as feasibility


def advisory(project: str = "acme/widget"):
    return {
        "ghsa_id": "GHSA-0000-aaaa-bbbb",
        "cwes": [{"cwe_id": "CWE-918", "name": "SSRF"}],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "widget"},
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": "2.0.0",
            }
        ],
        "repository_advisory_url": f"https://api.github.com/repos/{project}/security-advisories/GHSA-0000-aaaa-bbbb",
        "references": [
            f"https://github.com/{project}/commit/abcdef1234567890",
            f"https://github.com/{project}/releases/tag/v2.0.0",
        ],
    }


class RealWorldCorpusV1FeasibilityTests(unittest.TestCase):
    def test_exact_target_cwe_is_source_taxonomy_match_not_final_label(self):
        row = {
            "source_root": "GHSA-0000-aaaa-bbbb",
            "source_project": "acme/widget",
            "family_target": "ssrf",
            "target_cwe": "CWE-918",
        }
        assessed = feasibility.assess_source(row, advisory())
        self.assertEqual(assessed["source_taxonomy_match"]["status"], "exact_target_cwe_match")
        self.assertTrue(assessed["source_taxonomy_match"]["target_cwe_present"])
        self.assertFalse(assessed["source_taxonomy_match"]["final_family_assigned"])
        self.assertIsNone(assessed["final_family"])
        self.assertFalse(assessed["human_verified"])
        self.assertFalse(assessed["scoring_executed"])

    def test_strong_revision_boundary_requires_range_patch_and_code_reference(self):
        row = {
            "source_root": "GHSA-0000-aaaa-bbbb",
            "source_project": "acme/widget",
            "family_target": "ssrf",
            "target_cwe": "CWE-918",
        }
        assessed = feasibility.assess_source(row, advisory())
        self.assertEqual(assessed["capture_feasibility"], "strong_revision_boundary")
        self.assertEqual(assessed["variant_feasibility"]["positive"], "candidate")
        self.assertEqual(assessed["variant_feasibility"]["secure_negative"], "candidate")
        self.assertEqual(assessed["variant_feasibility"]["near_miss"], "manual_control_design_required")

    def test_target_cwe_mismatch_requires_review(self):
        row = {
            "source_root": "GHSA-0000-aaaa-bbbb",
            "source_project": "acme/widget",
            "family_target": "sql_injection",
            "target_cwe": "CWE-89",
        }
        assessed = feasibility.assess_source(row, advisory())
        self.assertEqual(
            assessed["source_taxonomy_match"]["status"],
            "target_cwe_mismatch_requires_review",
        )
        self.assertIsNone(assessed["final_family"])

    def test_general_source_does_not_gain_a_family(self):
        row = {
            "source_root": "GHSA-0000-aaaa-bbbb",
            "source_project": "acme/widget",
            "family_target": None,
            "target_cwe": None,
        }
        assessed = feasibility.assess_source(row, advisory())
        self.assertEqual(
            assessed["source_taxonomy_match"]["status"],
            "not_applicable_general_source",
        )
        self.assertIsNone(assessed["final_family"])

    @patch.object(feasibility, "_api_get_json")
    def test_100_source_gate_passes_with_60_exact_target_families(self, mock_get):
        mock_get.side_effect = lambda url, token="": advisory(
            f"owner/project-{url.split('GHSA-')[1].split('-')[0]}"
        )
        rows = []
        for i in range(100):
            row = {
                "source_root": f"GHSA-{i:04d}-aaaa-bbbb",
                "source_project": f"owner/project-{i:04d}",
                "family_target": f"family_{i:04d}" if i < 60 else None,
                "target_cwe": "CWE-918" if i < 60 else None,
                "final_family": None,
                "human_verified": False,
                "scoring_executed": False,
            }
            rows.append(row)
        result = feasibility.assess_shortlist(rows)
        self.assertTrue(result["passed"])
        self.assertEqual(result["assessed_source_count"], 100)
        self.assertEqual(result["exact_target_family_count"], 60)
        self.assertEqual(result["failure_count"], 0)

    @patch.object(feasibility, "_api_get_json")
    def test_family_gate_fails_closed_below_50(self, mock_get):
        mock_get.return_value = advisory()
        rows = []
        for i in range(100):
            rows.append({
                "source_root": f"GHSA-{i:04d}-aaaa-bbbb",
                "source_project": f"owner/project-{i:04d}",
                "family_target": f"family_{i:04d}" if i < 49 else None,
                "target_cwe": "CWE-918" if i < 49 else None,
            })
        result = feasibility.assess_shortlist(rows)
        self.assertFalse(result["passed"])
        self.assertFalse(result["gates"]["minimum_50_exact_target_families"])


if __name__ == "__main__":
    unittest.main()
