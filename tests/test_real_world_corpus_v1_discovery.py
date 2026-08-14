from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_discovery as discovery


class RealWorldCorpusV1DiscoveryTests(unittest.TestCase):
    def test_project_from_repository_advisory_url(self):
        row = {
            "source_code_location": None,
            "repository_advisory_url": "https://api.github.com/repos/Acme/Widget/security-advisories/GHSA-aaaa-bbbb-cccc",
            "references": [],
        }
        self.assertEqual(discovery.resolve_source_project(row), "acme/widget")

    def test_project_from_web_security_advisory_reference(self):
        row = {
            "source_code_location": None,
            "repository_advisory_url": None,
            "references": ["https://github.com/Acme/Widget/security/advisories/GHSA-aaaa-bbbb-cccc"],
        }
        self.assertEqual(discovery.resolve_source_project(row), "acme/widget")

    def test_normalization_preserves_fail_closed_metadata(self):
        row = {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "cve_id": "CVE-2026-99999",
            "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            "repository_advisory_url": "https://api.github.com/repos/Acme/Widget/security-advisories/GHSA-aaaa-bbbb-cccc",
            "source_code_location": None,
            "severity": "high",
            "published_at": "2026-08-14T00:00:00Z",
            "updated_at": "2026-08-14T00:00:00Z",
            "references": [],
            "cwes": [{"cwe_id": "CWE-918"}],
        }
        normalized = discovery.normalize_advisory_with_project_fallback(row)
        self.assertEqual(normalized["source_project"], "acme/widget")
        self.assertFalse(normalized["human_verified"])
        self.assertFalse(normalized["scoring_executed"])
        self.assertEqual(normalized["evaluation_role"], "fresh_candidate")

    def test_prose_mentions_do_not_create_historical_source_exposure(self):
        identities = discovery.strict_identities_from_records([
            {
                "source_root": "GHSA-1111-2222-3333",
                "source_project": "used/project",
                "description": "Related reading mentions GHSA-aaaa-bbbb-cccc and CVE-2026-99999 but neither was the benchmark source.",
                "notes": "Do not promote text citations into source identity.",
            }
        ])
        self.assertIn("GHSA-1111-2222-3333", identities["roots"])
        self.assertNotIn("GHSA-AAAA-BBBB-CCCC", identities["roots"])
        self.assertNotIn("CVE-2026-99999", identities["identifiers"])

    def test_explicit_identifiers_remain_blocking(self):
        identities = discovery.strict_identities_from_records([
            {
                "source_root": "GHSA-1111-2222-3333",
                "source_project": "used/project",
                "identifiers": [{"type": "CVE", "value": "CVE-2026-12345"}],
                "canonical_advisory_url": "https://github.com/used/project/security/advisories/GHSA-1111-2222-3333",
            }
        ])
        self.assertIn("CVE-2026-12345", identities["identifiers"])
        self.assertIn("used/project", identities["projects"])
        self.assertIn(
            "https://github.com/used/project/security/advisories/ghsa-1111-2222-3333",
            identities["urls"],
        )

    def test_raw_v4_and_v5_are_registered_as_consumed(self):
        names = {item[0] for item in discovery.EXTRA_CONSUMED_CORPORA}
        self.assertEqual(names, {"analysis_raw_v4", "analysis_raw_v5"})
        for item in discovery.EXTRA_CONSUMED_CORPORA:
            self.assertEqual(item[3], "consumed_benchmark")


if __name__ == "__main__":
    unittest.main()
