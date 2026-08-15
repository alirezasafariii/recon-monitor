from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_analyzers.authentication_session import AUTH_SESSION_METHOD, AUTH_SESSION_SPEC, AUTH_SESSION_TAXONOMY
from family_analyzers.graphql_authorization import GRAPHQL_AUTHORIZATION_METHOD, GRAPHQL_AUTHORIZATION_SPEC, GRAPHQL_AUTHORIZATION_TAXONOMY
from family_analyzers.open_redirect import OPEN_REDIRECT_METHOD, OPEN_REDIRECT_SPEC, OPEN_REDIRECT_TAXONOMY
from family_analyzers.postmessage_trust import POSTMESSAGE_METHOD, POSTMESSAGE_TRUST_SPEC, POSTMESSAGE_TAXONOMY
from family_specs.knowledge_projection import family_knowledge_projection, taxonomy_projection, validate_knowledge_projection
from family_specs.registry import MIGRATED_FAMILIES, get_detection_spec, validate_family_spec_registry
from hypothesis_admission import assess_admission
from vulnerability_knowledge import BUILTIN_KNOWLEDGE, SPEC_KNOWLEDGE_ERRORS, taxonomy_for_family


class FinalAnalyzersAuthRedirectPostMessageGraphQLSpecTests(unittest.TestCase):
    families = ("authentication_session", "open_redirect", "postmessage_trust", "graphql_authorization")

    def test_registry_and_knowledge_are_drift_free(self):
        self.assertEqual(len(MIGRATED_FAMILIES), 13)
        self.assertEqual(validate_family_spec_registry(), [])
        self.assertFalse(SPEC_KNOWLEDGE_ERRORS)
        for family in self.families:
            spec = get_detection_spec(family)
            self.assertEqual(validate_knowledge_projection(spec), [])
            self.assertEqual(taxonomy_for_family(family), taxonomy_projection(spec))
            self.assertEqual(BUILTIN_KNOWLEDGE[family], family_knowledge_projection(spec))
            self.assertTrue(all(doc.get("counts_as_target_evidence") is False for doc in BUILTIN_KNOWLEDGE[family]))
            self.assertTrue(all("type" not in doc for doc in BUILTIN_KNOWLEDGE[family]))

    def test_analyzer_compatibility_exports_come_from_specs(self):
        rows = (
            (AUTH_SESSION_SPEC, AUTH_SESSION_TAXONOMY, AUTH_SESSION_METHOD),
            (OPEN_REDIRECT_SPEC, OPEN_REDIRECT_TAXONOMY, OPEN_REDIRECT_METHOD),
            (POSTMESSAGE_TRUST_SPEC, POSTMESSAGE_TAXONOMY, POSTMESSAGE_METHOD),
            (GRAPHQL_AUTHORIZATION_SPEC, GRAPHQL_AUTHORIZATION_TAXONOMY, GRAPHQL_AUTHORIZATION_METHOD),
        )
        for spec, taxonomy, methodology in rows:
            self.assertEqual(taxonomy, spec.taxonomy())
            self.assertEqual(methodology, tuple(step.as_dict() for step in spec.standard.methodology))

    def test_auth_surface_requires_actual_lifecycle_failure(self):
        surface = assess_admission("authentication_session", [
            {"type": "authentication_surface", "source_group": "surface"},
            {"type": "client_operation", "source_group": "operation"},
        ])
        self.assertFalse(surface["admitted"])
        direct = assess_admission("authentication_session", [
            {"type": "authentication_surface", "source_group": "surface"},
            {"type": "client_operation", "source_group": "operation"},
            {"type": "session_reuse_after_logout", "source_group": "controlled_lifecycle"},
        ])
        self.assertTrue(direct["admitted"])
        self.assertEqual(
            direct["confirmation_required"],
            [["authentication_state_violation", "recovery_bypass", "session_reuse_after_logout", "token_not_rotated"]],
        )

    def test_redirect_requires_external_user_controlled_navigation(self):
        surface = assess_admission("open_redirect", [
            {"type": "redirect_parameter", "source_group": "static_flow"},
            {"type": "navigation_context", "source_group": "static_flow"},
            {"type": "navigation_validation_absent", "source_group": "runtime_policy"},
        ])
        self.assertFalse(surface["admitted"])
        direct = assess_admission("open_redirect", [
            {"type": "redirect_parameter", "source_group": "static_flow"},
            {"type": "navigation_context", "source_group": "static_flow"},
            {"type": "external_destination_accepted", "source_group": "controlled_runtime"},
        ])
        self.assertTrue(direct["admitted"])

    def test_postmessage_requires_untrusted_sender_sensitive_effect(self):
        surface = assess_admission("postmessage_trust", [
            {"type": "postmessage_source", "source_group": "static_flow"},
            {"type": "message_handler", "source_group": "static_flow"},
            {"type": "origin_validation_absent", "source_group": "runtime_policy"},
        ])
        self.assertFalse(surface["admitted"])
        direct = assess_admission("postmessage_trust", [
            {"type": "postmessage_source", "source_group": "static_flow"},
            {"type": "message_handler", "source_group": "static_flow"},
            {"type": "untrusted_message_accepted", "source_group": "controlled_runtime"},
        ])
        self.assertTrue(direct["admitted"])

    def test_graphql_policy_context_is_not_vulnerability_evidence(self):
        context = assess_admission("graphql_authorization", [
            {"type": "graphql_identifier", "source_group": "graphql_static"},
            {"type": "graphql_operation", "source_group": "graphql_static"},
            {"type": "resolver_policy_context", "source_group": "policy"},
        ])
        self.assertFalse(context["admitted"])
        direct = assess_admission("graphql_authorization", [
            {"type": "graphql_identifier", "source_group": "graphql_static"},
            {"type": "graphql_operation", "source_group": "graphql_static"},
            {"type": "graphql_authorization_differential", "source_group": "controlled_graphql"},
        ])
        self.assertTrue(direct["admitted"])

    def test_curated_reference_compatibility_is_preserved(self):
        auth_ids = {doc["id"] for doc in BUILTIN_KNOWLEDGE["authentication_session"]}
        redirect_ids = {doc["id"] for doc in BUILTIN_KNOWLEDGE["open_redirect"]}
        post_ids = {doc["id"] for doc in BUILTIN_KNOWLEDGE["postmessage_trust"]}
        gql_ids = {doc["id"] for doc in BUILTIN_KNOWLEDGE["graphql_authorization"]}
        self.assertIn("capec-115", auth_ids)
        self.assertIn("ghsl-ruby-saml-2024-329-330", auth_ids)
        self.assertIn("ghsl-2025-122-nocodb-open-redirect", redirect_ids)
        self.assertIn("owasp-wstg-clnt-11-web-messaging", post_ids)
        self.assertIn("owasp-graphql-access-control-global", gql_ids)

    def test_external_knowledge_is_zero_target_evidence(self):
        for family in self.families:
            result = assess_admission(family, [
                {"source": "OWASP", "ref": "standard", "source_group": "knowledge"},
                {"source": "WSTG", "ref": "test", "source_group": "knowledge"},
                {"source": "CWE", "ref": "weakness", "source_group": "knowledge"},
                {"source": "GHSL", "ref": "writeup", "source_group": "knowledge"},
            ])
            self.assertFalse(result["admitted"])
            self.assertEqual(result["independent_sources"], 0)


if __name__ == "__main__":
    unittest.main()
