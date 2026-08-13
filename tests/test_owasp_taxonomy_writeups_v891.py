from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_analyzers.api_expansion import (
    analyze_improper_inventory_management_signal,
    analyze_security_misconfiguration_signal,
    analyze_unsafe_api_consumption_signal,
)
from family_analyzers.ldap_injection import analyze_ldap_injection_signal
from family_analyzers.nosql_injection import analyze_nosql_injection_signal
from owasp_family_catalog import CANONICAL_TAXONOMY, NEW_FAMILY_ORDER
from vulnerability_knowledge import knowledge_context, knowledge_for_family, taxonomy_for_family


class OwaspTaxonomyWriteupsV891Tests(unittest.TestCase):
    def test_phase_one_canonical_taxonomy_has_only_stable_mapping_ids(self):
        self.assertEqual(tuple(CANONICAL_TAXONOMY), NEW_FAMILY_ORDER)
        self.assertEqual(CANONICAL_TAXONOMY["nosql_injection"]["wstg"], ["WSTG-INPV-05"])
        self.assertNotIn("WSTG-INPV-05.6", CANONICAL_TAXONOMY["nosql_injection"]["wstg"])
        self.assertIn("CAPEC-136", CANONICAL_TAXONOMY["ldap_injection"]["capec"])
        self.assertNotIn("CWE-16", CANONICAL_TAXONOMY["security_misconfiguration"]["cwe"])
        self.assertEqual(
            set(CANONICAL_TAXONOMY["security_misconfiguration"]["cwe"]),
            {"CWE-489", "CWE-548", "CWE-749", "CWE-319"},
        )
        self.assertEqual(CANONICAL_TAXONOMY["improper_inventory_management"]["wstg"], ["WSTG-APIT-01"])
        self.assertEqual(CANONICAL_TAXONOMY["unsafe_api_consumption"]["wstg"], [])
        self.assertNotIn("CWE-20", CANONICAL_TAXONOMY["unsafe_api_consumption"]["cwe"])

    def test_knowledge_profiles_consume_the_same_canonical_taxonomy(self):
        for family in NEW_FAMILY_ORDER:
            self.assertEqual(taxonomy_for_family(family), CANONICAL_TAXONOMY[family])

    def test_active_analyzer_sources_do_not_embed_deprecated_taxonomy_literals(self):
        nosql_source = (ROOT / "app" / "family_analyzers" / "nosql_injection.py").read_text(encoding="utf-8")
        api_source = (ROOT / "app" / "family_analyzers" / "api_expansion.py").read_text(encoding="utf-8")

        self.assertNotIn("WSTG-INPV-05.6", nosql_source)
        self.assertNotIn('"CWE-16"', api_source)
        self.assertNotIn('"WSTG-APIT"', api_source)
        self.assertIn('CANONICAL_TAXONOMY["nosql_injection"]', nosql_source)
        for family in (
            "unrestricted_resource_consumption",
            "sensitive_business_flow_abuse",
            "security_misconfiguration",
            "improper_inventory_management",
            "unsafe_api_consumption",
        ):
            self.assertIn(f'CANONICAL_TAXONOMY["{family}"]', api_source)

    def test_analyzer_output_uses_canonical_taxonomy(self):
        nosql = analyze_nosql_injection_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/login", method="POST",
            body_fields=["username"], details={"nosql_query_sink": True}, semantic_text="MongoDB findOne query",
        )
        self.assertIsNotNone(nosql)
        self.assertEqual(nosql["family_analyzer"]["taxonomy"], CANONICAL_TAXONOMY["nosql_injection"])

        ldap = analyze_ldap_injection_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/login", method="POST",
            body_fields=["username"], details={"ldap_filter_sink": True}, semantic_text="LDAP directory filter",
        )
        self.assertIsNotNone(ldap)
        self.assertEqual(ldap["family_analyzer"]["taxonomy"], CANONICAL_TAXONOMY["ldap_injection"])

        misconfig = analyze_security_misconfiguration_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/debug", method="GET",
            details={"debug_mode_publicly_exposed": True},
        )
        self.assertEqual(misconfig["family_analyzer"]["taxonomy"], CANONICAL_TAXONOMY["security_misconfiguration"])

        inventory = analyze_improper_inventory_management_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/api/v1/orders", method="GET",
            details={"inventory_drift_signal": True, "inventory_baseline": "v2 only"},
        )
        self.assertEqual(inventory["family_analyzer"]["taxonomy"], CANONICAL_TAXONOMY["improper_inventory_management"])

        upstream = analyze_unsafe_api_consumption_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/quote", method="GET",
            details={"upstream_service": "pricing", "downstream_sink": "quote", "upstream_tls_missing": True},
        )
        self.assertEqual(upstream["family_analyzer"]["taxonomy"], CANONICAL_TAXONOMY["unsafe_api_consumption"])

    def test_real_world_writeups_are_available_but_never_target_evidence(self):
        expected_ids = {
            "sql_injection": "ghsl-2026-059-chatwoot",
            "nosql_injection": "ghsl-2026-005-rocketchat",
            "command_injection": "ghsl-2020-111-standard-version",
            "ssti": "portswigger-2015-ssti",
            "ldap_injection": "ghsl-2024-009-redash",
            "unrestricted_resource_consumption": "ghsl-2023-047-049-comrak",
            "security_misconfiguration": "mitre-cwe-489-active-debug",
            "improper_inventory_management": "owasp-wstg-apit-01-recon",
            "unsafe_api_consumption": "ghsl-2020-097-twitter-stream",
        }
        for family, doc_id in expected_ids.items():
            refs = {doc["id"] for doc in knowledge_for_family(family)}
            self.assertIn(doc_id, refs)
            context = knowledge_context(family, [], endpoint="/api/test")
            self.assertEqual(context["role"], "classification_and_retrieval_only_not_target_evidence")
            self.assertIn("never satisfies admission", context["safety"])

    def test_writeup_retrieval_matches_target_signal_without_becoming_evidence(self):
        context = knowledge_context(
            "nosql_injection",
            [
                {"type": "nosql_input", "source_group": "request_schema", "text": "username"},
                {"type": "nosql_query_sink", "source_group": "query_context", "text": "MongoDB findOne"},
                {"type": "nosql_operator_injection_observed", "source_group": "controlled", "text": "operator-shaped input changed query semantics"},
            ],
            endpoint="/login",
            summary="controlled NoSQL query behavior",
        )
        ids = {doc["id"] for doc in context["retrieved_writeups"]}
        self.assertIn("ghsl-2026-005-rocketchat", ids)
        self.assertEqual(context["role"], "classification_and_retrieval_only_not_target_evidence")


if __name__ == "__main__":
    unittest.main()
