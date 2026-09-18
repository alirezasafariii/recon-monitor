from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from real_world_corpus_v1_coverage_expander import (
    candidate_family_match,
    coverage_inventory,
)
from real_world_corpus_v1_family_match import (
    cwe_owners,
    resolve_source_family,
)


def _advisory(summary: str, *cwes: str) -> dict:
    return {
        "summary": summary,
        "cwes": [{"cwe_id": cwe} for cwe in cwes],
    }


class CorpusV1AllFamilyCoverageTests(unittest.TestCase):
    def test_checked_in_inventory_tracks_all_74_canonical_families(self):
        feasibility = json.loads(
            (ROOT / "benchmarks/real_world/v1/source_feasibility_final.json").read_text(
                encoding="utf-8"
            )
        )
        inventory = coverage_inventory(feasibility, quota=1)
        self.assertEqual(inventory["canonical_family_count"], 74)
        self.assertEqual(len(inventory["families"]), 74)
        self.assertEqual(inventory["represented_family_count"], 60)
        self.assertEqual(inventory["missing_family_count"], 14)
        self.assertEqual(
            set(inventory["missing_families"]),
            {
                "business_logic",
                "security_misconfiguration",
                "improper_inventory_management",
                "http_verb_tampering",
                "ssi_injection",
                "host_header_injection",
                "client_side_resource_manipulation",
                "xssi",
                "tls_hsts_weakness",
                "subdomain_takeover",
                "backup_unreferenced_file_exposure",
                "path_confusion",
                "oauth_oidc_weakness",
                "web_cache_poisoning",
            },
        )

    def test_every_canonical_family_has_a_discovery_strategy(self):
        feasibility = {"sources": []}
        inventory = coverage_inventory(feasibility, quota=1)
        self.assertEqual(inventory["missing_family_count"], 74)
        for row in inventory["families"]:
            self.assertIn(row["discovery_mode"], {"cwe", "semantic"})
            if row["discovery_mode"] == "semantic":
                self.assertTrue(row["semantic_terms"], row["family"])

    def test_unique_cwe_candidate_can_be_matched_without_semantic_guess(self):
        raw = _advisory(
            "Object access control weakness in a REST API",
            "CWE-639",
        )
        match = candidate_family_match(raw, "broken_object_authorization")
        self.assertTrue(match["matched"])
        self.assertEqual(match["basis"], "unique_canonical_cwe")

    def test_shared_xss_cwe_requires_unique_summary_semantics(self):
        raw = _advisory(
            "Widget has Stored XSS in profile rendering",
            "CWE-79",
        )
        stored = candidate_family_match(raw, "stored_xss")
        reflected = candidate_family_match(raw, "reflected_xss")
        self.assertTrue(stored["matched"])
        self.assertEqual(stored["basis"], "shared_cwe_plus_unique_semantics")
        self.assertFalse(reflected["matched"])

    def test_no_cwe_family_can_use_distinctive_semantics(self):
        raw = _advisory(
            "Framework is vulnerable to Web Cache Poisoning through an unkeyed header"
        )
        match = candidate_family_match(raw, "web_cache_poisoning")
        self.assertTrue(match["matched"])
        self.assertEqual(match["basis"], "unique_semantic_no_cwe")

    def test_generic_text_does_not_create_no_cwe_family_match(self):
        raw = _advisory("A security vulnerability can affect cached responses")
        match = candidate_family_match(raw, "web_cache_poisoning")
        self.assertFalse(match["matched"])

    def test_source_resolver_uses_unique_target_cwe_when_hint_is_missing(self):
        feasibility = {
            "family_hints": [],
            "source_taxonomy_match": {
                "family_target": "broken_object_authorization",
                "target_cwe": "CWE-639",
            },
        }
        result = resolve_source_family(
            feasibility,
            _advisory("Authorization issue", "CWE-639"),
        )
        self.assertTrue(result["resolved"])
        self.assertEqual(result["family"], "broken_object_authorization")
        self.assertEqual(result["basis"], "unique_canonical_target_cwe")

    def test_source_resolver_can_disambiguate_shared_cwe_with_summary(self):
        feasibility = {
            "family_hints": [],
            "source_taxonomy_match": {
                "family_target": "stored_xss",
                "target_cwe": "CWE-79",
            },
        }
        result = resolve_source_family(
            feasibility,
            _advisory("Stored XSS in user profile field", "CWE-79"),
        )
        self.assertTrue(result["resolved"])
        self.assertEqual(result["family"], "stored_xss")
        self.assertEqual(result["basis"], "shared_cwe_plus_unique_summary_semantics")

    def test_source_resolver_refuses_ambiguous_shared_cwe(self):
        feasibility = {
            "family_hints": [],
            "source_taxonomy_match": {
                "family_target": "stored_xss",
                "target_cwe": "CWE-79",
            },
        }
        result = resolve_source_family(
            feasibility,
            _advisory("Cross-site scripting issue", "CWE-79"),
        )
        self.assertFalse(result["resolved"])

    def test_cwe_owner_index_covers_known_shared_and_unique_taxonomy(self):
        owners = cwe_owners()
        self.assertEqual(owners["CWE-639"], ("broken_object_authorization",))
        self.assertIn("stored_xss", owners["CWE-79"])
        self.assertIn("reflected_xss", owners["CWE-79"])
        self.assertIn("dom_xss", owners["CWE-79"])


if __name__ == "__main__":
    unittest.main()
