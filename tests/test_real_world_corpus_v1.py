from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1 as corpus


class RealWorldCorpusV1Tests(unittest.TestCase):
    def test_protocol_targets_400_records_from_100_roots(self):
        self.assertEqual(corpus.TARGET_SOURCE_ROOTS, 100)
        self.assertEqual(corpus.TARGET_RECORDS, 400)
        self.assertEqual(corpus.VARIANTS_PER_ROOT, 4)
        self.assertEqual(corpus.TARGET_MIN_FAMILIES, 50)

    def test_json_and_jsonl_parsing(self):
        json_rows = corpus.records_from_text('[{"source_root":"GHSA-1111-2222-3333"}]')
        jsonl_rows = corpus.records_from_text('{"source_root":"GHSA-1111-2222-3333"}\n{"source_root":"GHSA-4444-5555-6666"}\n')
        self.assertEqual(len(json_rows), 1)
        self.assertEqual(len(jsonl_rows), 2)

    def test_identity_extraction_normalizes_project_and_identifiers(self):
        identities = corpus.identities_from_records([
            {
                "source_root": "GHSA-1111-2222-3333",
                "source_code_location": "https://github.com/Acme/Widget",
                "identifiers": [{"type": "CVE", "value": "CVE-2026-12345"}],
                "references": ["https://github.com/acme/widget/commit/abc"],
            }
        ])
        self.assertIn("GHSA-1111-2222-3333", identities["roots"])
        self.assertIn("acme/widget", identities["projects"])
        self.assertIn("CVE-2026-12345", identities["identifiers"])

    def test_firewall_rejects_root_project_identifier_and_url_reuse(self):
        exposed = {
            "roots": {"GHSA-1111-2222-3333"},
            "projects": {"acme/widget"},
            "identifiers": {"GHSA-1111-2222-3333", "CVE-2026-12345"},
            "urls": {"https://github.com/acme/widget/security/advisories/ghsa-1111-2222-3333"},
        }
        candidate = {
            "source_root": "GHSA-1111-2222-3333",
            "source_project": "Acme/Widget",
            "identifiers": ["CVE-2026-12345"],
            "canonical_advisory_url": "https://github.com/acme/widget/security/advisories/GHSA-1111-2222-3333",
        }
        reasons = corpus.exposure_reasons(candidate, exposed)
        self.assertIn("historical_source_root_overlap", reasons)
        self.assertIn("historical_source_project_overlap", reasons)
        self.assertIn("historical_identifier_overlap", reasons)
        self.assertIn("historical_url_overlap", reasons)

    def test_fresh_source_passes_empty_firewall(self):
        exposed = {"roots": set(), "projects": set(), "identifiers": set(), "urls": set()}
        candidate = {
            "source_root": "GHSA-aaaa-bbbb-cccc",
            "source_project": "fresh/project",
            "identifiers": ["CVE-2026-99999"],
            "canonical_advisory_url": "https://github.com/fresh/project/security/advisories/GHSA-aaaa-bbbb-cccc",
        }
        self.assertEqual(corpus.exposure_reasons(candidate, exposed), [])

    def test_consumed_and_development_records_are_forced_train(self):
        partition = corpus.partition_reviewed_records([
            {"id": "old", "evaluation_role": "consumed_benchmark"},
            {"id": "dev", "evaluation_role": "development_only"},
            {"id": "fresh", "evaluation_role": "fresh_candidate"},
            {"id": "v6", "evaluation_role": "reserved_blind"},
        ])
        self.assertEqual({row["id"] for row in partition["forced_train"]}, {"old", "dev"})
        self.assertEqual([row["id"] for row in partition["fresh_candidates"]], ["fresh"])
        self.assertEqual([row["id"] for row in partition["reserved_blind"]], ["v6"])

    def test_reserved_blind_never_enters_fresh_candidate_pool(self):
        partition = corpus.partition_reviewed_records([
            {"id": "v6-case", "evaluation_role": "reserved_blind"}
        ])
        self.assertFalse(partition["fresh_candidates"])
        self.assertEqual(partition["reserved_blind"][0]["id"], "v6-case")

    def test_advisory_normalization_is_metadata_only(self):
        row = {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "cve_id": "CVE-2026-99999",
            "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            "repository_advisory_url": "https://api.github.com/repos/fresh/project/security-advisories/GHSA-aaaa-bbbb-cccc",
            "source_code_location": "https://github.com/fresh/project",
            "severity": "high",
            "published_at": "2026-08-14T00:00:00Z",
            "updated_at": "2026-08-14T00:00:00Z",
            "references": ["https://github.com/fresh/project/commit/abc"],
            "cwes": [{"cwe_id": "CWE-918", "name": "SSRF"}],
        }
        normalized = corpus.normalize_advisory(row)
        self.assertEqual(normalized["source_project"], "fresh/project")
        self.assertIn("ssrf", normalized["family_hints"])
        self.assertEqual(normalized["family_hint_basis"], "cwe_only_not_final_adjudication")
        self.assertFalse(normalized["human_verified"])
        self.assertFalse(normalized["scoring_executed"])
        self.assertEqual(normalized["capture_status"], "not_started")


if __name__ == "__main__":
    unittest.main()
