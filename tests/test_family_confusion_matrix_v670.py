from __future__ import annotations

import unittest

from analysis_ranking import rank_families
from family_reasoners import FAMILY_REASONER_PROFILES, reason_family


def evidence(*signals: str) -> list[dict[str, str]]:
    return [
        {
            "type": signal,
            "source": f"source_{index}",
            "source_group": f"group_{index}",
            "text": signal,
        }
        for index, signal in enumerate(signals, start=1)
    ]


CANONICAL_SIGNATURES: dict[str, tuple[str, ...]] = {
    "broken_object_authorization": ("object_identifier", "object_operation", "unauthorized_object_response"),
    "broken_function_authorization": ("privileged_function", "role_property", "lower_privilege_success"),
    "mass_assignment": ("write_method", "privileged_property", "privileged_property_accepted"),
    "authentication_session": ("authentication_surface", "session_validation_failure"),
    "account_enumeration": ("identity_lookup", "response_difference"),
    "dom_xss": ("source_sink", "dangerous_sink", "runtime_reachable_flow"),
    "postmessage_trust": ("postmessage_handler", "message_sink", "missing_origin_check"),
    "open_redirect": ("redirect_parameter", "navigation_sink", "external_destination"),
    "ssrf": ("url_parameter", "backend_fetch"),
    "file_upload": ("file_input", "upload_operation", "dangerous_type_accepted"),
    "path_traversal": ("filename_field", "file_operation", "base_directory_escape"),
    "information_disclosure": ("sensitive_fields", "public_observation"),
    "graphql_authorization": ("graphql_operation", "graphql_identifier", "resolver_authorization_failure"),
    "graphql_data_exposure": ("graphql_operation", "sensitive_fields", "field_expansion"),
    "websocket_authorization": ("websocket_channel", "room_identifier", "unauthorized_subscription"),
    "cors_misconfiguration": ("cors_policy_surface", "reflected_origin", "credentials_allowed"),
    "sensitive_caching": ("cache_header", "sensitive_fields", "missing_vary"),
    "business_logic": ("business_operation", "workflow_invariant_violation"),
    "race_condition": ("state_change", "single_use_operation", "duplicate_effect_observed"),
    "sql_injection": ("input_parameter", "sql_query_surface", "query_structure_influence"),
    "nosql_injection": ("body_parameter", "nosql_query_surface", "nosql_operator_accepted"),
    "command_injection": ("input_parameter", "command_execution_surface", "command_output_observed"),
    "server_side_template_injection": ("template_input", "template_engine_semantic", "template_expression_evaluated"),
    "ldap_injection": ("input_parameter", "ldap_filter_surface", "ldap_filter_influence"),
    "unrestricted_resource_consumption": ("expensive_operation", "resource_exhaustion_differential"),
    "sensitive_business_flow_abuse": ("purchase_flow", "per_user_limit_absent"),
    "security_misconfiguration": ("debug_surface", "debug_mode_exposed"),
    "improper_inventory_management": ("legacy_endpoint_surface", "deprecated_version_still_reachable"),
    "unsafe_api_consumption": ("third_party_integration", "third_party_data_unsanitized"),
    "source_map_exposure": ("source_map", "internal_sources", "public_observation"),
    "secret_exposure": ("secret_pattern", "production_javascript", "credential_context"),
    "software_supply_chain_failure": ("component_inventory", "known_vulnerable_component_observed"),
    "cryptographic_failure": ("cryptographic_surface", "weak_crypto_algorithm_observed"),
    "software_data_integrity_failure": ("integrity_boundary", "unsafe_deserialization_observed"),
    "security_logging_alerting_failure": ("logging_surface", "sensitive_data_logged"),
    "exceptional_condition_mishandling": ("exception_surface", "unhandled_exception_observed"),
}


class FamilyConfusionMatrix670Tests(unittest.TestCase):
    def test_canonical_signature_exists_for_every_family(self) -> None:
        self.assertEqual(set(CANONICAL_SIGNATURES), set(FAMILY_REASONER_PROFILES))
        self.assertGreaterEqual(len(CANONICAL_SIGNATURES), 31)

    def test_every_family_canonical_signature_ranks_itself_top1(self) -> None:
        failures: list[str] = []
        for family, signals in CANONICAL_SIGNATURES.items():
            ranked = rank_families(evidence(*signals), [])
            if not ranked or ranked[0]["family"] != family:
                predicted = ranked[0]["family"] if ranked else "<none>"
                failures.append(f"{family}->{predicted}")
                continue
            self.assertTrue(ranked[0]["assessment"]["admitted"], family)
            self.assertEqual(ranked[0]["family_fit_score"], 1.0, family)
        self.assertEqual(failures, [])

    def test_generic_input_alone_cannot_select_an_injection_family(self) -> None:
        support = evidence("input_parameter")
        for family in (
            "sql_injection",
            "nosql_injection",
            "command_injection",
            "server_side_template_injection",
            "ldap_injection",
        ):
            row = reason_family(family, support, [])
            self.assertFalse(row["identity_gate_satisfied"], family)
            self.assertEqual(row["family_fit_score"], 0.0, family)

    def test_redirect_condition_does_not_become_ssrf(self) -> None:
        support = evidence("redirect_parameter", "navigation_sink", "external_destination")
        redirect = reason_family("open_redirect", support, [])
        ssrf = reason_family("ssrf", support, [])
        self.assertEqual(redirect["family_fit_score"], 1.0)
        self.assertEqual(ssrf["family_fit_score"], 0.0)

    def test_backend_fetch_does_not_become_open_redirect(self) -> None:
        support = evidence("url_parameter", "backend_fetch")
        ssrf = reason_family("ssrf", support, [])
        redirect = reason_family("open_redirect", support, [])
        self.assertEqual(ssrf["family_fit_score"], 1.0)
        self.assertEqual(redirect["family_fit_score"], 0.0)

    def test_concurrency_failure_suppresses_generic_business_logic_when_its_condition_is_missing(self) -> None:
        support = evidence("state_change", "single_use_operation", "duplicate_effect_observed")
        race = reason_family("race_condition", support, [])
        business = reason_family("business_logic", support, [])
        self.assertEqual(race["family_fit_score"], 1.0)
        self.assertTrue(business["confounder_evidence"])
        self.assertGreater(business["confounder_penalty"], 0.0)
        self.assertLess(business["family_fit_score"], race["family_fit_score"])


if __name__ == "__main__":
    unittest.main()