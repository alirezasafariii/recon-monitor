from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_repair as repair


class RealWorldCorpusV1RepairTests(unittest.TestCase):
    def test_acceptable_feasibility_is_revision_or_version_boundary_only(self):
        self.assertEqual(
            repair.ACCEPTABLE_FEASIBILITY,
            {"strong_revision_boundary", "version_boundary_available"},
        )
        self.assertEqual(
            repair.WEAK_FEASIBILITY,
            {"source_reference_available", "manual_source_research_required"},
        )

    def test_combined_exposure_unions_all_identity_dimensions(self):
        a = {"roots": {"A"}, "projects": {"p/a"}, "urls": {"u1"}, "identifiers": {"I1"}}
        b = {"roots": {"B"}, "projects": {"p/b"}, "urls": {"u2"}, "identifiers": {"I2"}}
        result = repair._combined_exposure(a, b)
        self.assertEqual(result["roots"], {"A", "B"})
        self.assertEqual(result["projects"], {"p/a", "p/b"})
        self.assertEqual(result["urls"], {"u1", "u2"})
        self.assertEqual(result["identifiers"], {"I1", "I2"})

    @patch.object(repair.feasibility, "_api_get_json")
    def test_assess_candidate_rejects_source_reference_only(self, mock_get):
        mock_get.return_value = {
            "cwes": [{"cwe_id": "CWE-918"}],
            "vulnerabilities": [],
            "references": ["https://github.com/acme/widget/security/advisories/GHSA-aaaa-bbbb-cccc"],
            "repository_advisory_url": "https://api.github.com/repos/acme/widget/security-advisories/GHSA-aaaa-bbbb-cccc",
        }
        candidate = {
            "source_root": "GHSA-aaaa-bbbb-cccc",
            "source_project": "acme/widget",
            "family_target": "ssrf",
            "target_cwe": "CWE-918",
        }
        self.assertIsNone(repair._assess_candidate(candidate, token=""))

    @patch.object(repair.feasibility, "_api_get_json")
    def test_assess_candidate_accepts_version_boundary(self, mock_get):
        mock_get.return_value = {
            "cwes": [{"cwe_id": "CWE-918"}],
            "vulnerabilities": [{
                "package": {"ecosystem": "pip", "name": "widget"},
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": {"identifier": "2.0.0"},
            }],
            "references": [],
            "repository_advisory_url": "https://api.github.com/repos/acme/widget/security-advisories/GHSA-aaaa-bbbb-cccc",
        }
        candidate = {
            "source_root": "GHSA-aaaa-bbbb-cccc",
            "source_project": "acme/widget",
            "family_target": "ssrf",
            "target_cwe": "CWE-918",
        }
        assessed = repair._assess_candidate(candidate, token="")
        self.assertIsNotNone(assessed)
        self.assertEqual(assessed["capture_feasibility"], "version_boundary_available")


if __name__ == "__main__":
    unittest.main()
