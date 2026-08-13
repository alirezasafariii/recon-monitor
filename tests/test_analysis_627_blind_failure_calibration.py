from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS, STANDARDS_ENGINE_VERSION
from family_detectors import evaluate_family_detector, execute_detector_intelligence
from family_detectors.base import DETECTOR_ENGINE_VERSION, DETECTOR_RULE_VERSION
from family_detectors.execution import EXECUTION_ENGINE_VERSION, EXECUTION_RULE_VERSION
from family_detectors.registry import DETECTOR_SPECS
from hypothesis_admission import (
    ADMISSION_ENGINE_VERSION,
    ADMISSION_RULE_VERSION,
    FAMILY_ADMISSION_POLICIES,
    assess_admission,
)


def schema(*, query=(), body=(), path=(), object_ids=(), auth=()):
    return {
        "query_parameters": list(query),
        "body_fields": list(body),
        "path_parameters": list(path),
        "object_identifiers": list(object_ids),
        "authentication_hints": list(auth),
    }


def assessment(
    family: str,
    *,
    endpoint: str,
    method: str = "GET",
    endpoint_schema=None,
    details=None,
    category: str = "",
    business_context: str = "general",
):
    execution = execute_detector_intelligence(
        target="fixture.invalid",
        endpoint=endpoint,
        method=method,
        endpoint_schema=endpoint_schema or schema(),
        details=details or {},
        category=category,
        business_context=business_context,
    )
    raw = execution.get(family, {"support": [], "contradict": []})
    scoped = evaluate_family_detector(
        family,
        raw.get("support") or [],
        raw.get("contradict") or [],
        channel="analysis_627_test",
    )
    decision = assess_admission(family, scoped.get("support") or [], scoped.get("contradict") or [])
    support_types = {str(row.get("type") or "") for row in scoped.get("support") or []}
    contradict_types = {str(row.get("type") or "") for row in scoped.get("contradict") or []}
    return decision, support_types, contradict_types


class Analysis627BlindFailureCalibrationTests(unittest.TestCase):
    def test_sensitive_cache_requires_observed_cacheability_and_actual_auth_context(self) -> None:
        positive, support, _ = assessment(
            "sensitive_caching",
            endpoint="/api/account",
            endpoint_schema=schema(auth=("session",)),
            details={
                "status_code": 200,
                "request_headers": {"Cookie": "session=fixture"},
                "response_headers": {"Cache-Control": "public, max-age=300"},
                "response_json": {"email": "user@fixture.invalid", "balance": "100.00"},
                "cache_observation": {"shared_cache_store": True},
            },
            category="authenticated sensitive response caching",
            business_context="customer_data",
        )
        self.assertTrue(positive["admitted"])
        self.assertIn("shared_cache_risk", support)

        for details, endpoint_schema in (
            ({"status_code": 200}, schema(auth=("session",))),
            ({"status_code": 200, "response_json": {"email": "user@fixture.invalid"}}, schema(auth=("session",))),
            ({"status_code": 200, "response_headers": {"Cache-Control": "max-age=60"}}, schema()),
        ):
            decision, support, _ = assessment(
                "sensitive_caching",
                endpoint="/api/graphql",
                endpoint_schema=endpoint_schema,
                details=details,
                category="general api response",
            )
            self.assertFalse(decision["admitted"])
            self.assertNotIn("shared_cache_risk", support)

    def test_dom_and_postmessage_conditions_require_behavioral_observation(self) -> None:
        decision, support, _ = assessment(
            "dom_xss",
            endpoint="/app",
            details={
                "status_code": 200,
                "javascript": "const value = location.hash.slice(1); document.querySelector('#result').innerHTML = value;",
                "browser_observation": {"input_channel": "location.hash", "rendered_as_html": True},
            },
            category="client javascript rendering",
        )
        self.assertTrue(decision["admitted"])
        self.assertIn("runtime_reachable_flow", support)

        decision, support, contradict = assessment(
            "postmessage_trust",
            endpoint="/embed",
            details={
                "status_code": 200,
                "javascript": "window.addEventListener('message', (event) => { document.querySelector('#panel').innerHTML = event.data; });",
                "message_observation": {"accepted": True, "origin_checked": False, "sender_origin": "https://untrusted.fixture.invalid"},
            },
            category="cross-window message handling",
        )
        self.assertTrue(decision["admitted"])
        self.assertIn("missing_origin_check", support)
        self.assertNotIn("strict_origin_check", contradict)

        decision, _, contradict = assessment(
            "postmessage_trust",
            endpoint="/embed",
            details={
                "status_code": 200,
                "javascript": "window.addEventListener('message', (event) => { if (event.origin !== 'https://trusted.fixture.invalid') return; document.querySelector('#panel').textContent = event.data; });",
                "message_observation": {"accepted": False, "origin_checked": True},
            },
            category="cross-window message handling",
        )
        self.assertFalse(decision["admitted"])
        self.assertIn("strict_origin_check", contradict)

    def test_graphql_authorization_and_data_exposure_use_stored_response_behavior(self) -> None:
        decision, support, _ = assessment(
            "graphql_authorization",
            endpoint="/graphql",
            method="POST",
            endpoint_schema=schema(body=("query",), object_ids=("accountId",), auth=("session",)),
            details={
                "status_code": 200,
                "graphql_query": "query Account($id: ID!){ account(id:$id){ id privateNotes } }",
                "context_observations": [{
                    "context": "low_privilege_other_account",
                    "expected_access": "denied",
                    "status_code": 200,
                    "response_json": {"data": {"account": {"id": "acct-200", "privateNotes": "fixture-private"}}},
                }],
            },
            category="graphql resolver object authorization",
        )
        self.assertTrue(decision["admitted"])
        self.assertIn("resolver_authorization_failure", support)

        decision, _, contradict = assessment(
            "graphql_authorization",
            endpoint="/graphql",
            method="POST",
            endpoint_schema=schema(body=("query",), object_ids=("accountId",), auth=("session",)),
            details={
                "status_code": 200,
                "graphql_query": "query Account($id: ID!){ account(id:$id){ id privateNotes } }",
                "context_observations": [{
                    "context": "low_privilege_other_account",
                    "expected_access": "denied",
                    "status_code": 200,
                    "response_json": {"errors": [{"message": "forbidden"}], "data": {"account": None}},
                }],
            },
            category="graphql resolver object authorization",
        )
        self.assertFalse(decision["admitted"])
        self.assertIn("cross_context_denied", contradict)

        decision, support, _ = assessment(
            "graphql_data_exposure",
            endpoint="/graphql",
            method="POST",
            endpoint_schema=schema(body=("query",), auth=("session",)),
            details={
                "status_code": 200,
                "graphql_query": "query { viewer { id email apiToken } }",
                "response_json": {"data": {"viewer": {"id": "u-1", "email": "user@fixture.invalid", "apiToken": "fixture-sensitive-token-value"}}},
            },
            category="graphql sensitive field response",
        )
        self.assertTrue(decision["admitted"])
        self.assertIn("sensitive_expansion", support)

    def test_websocket_expected_denial_must_actually_subscribe(self) -> None:
        decision, support, _ = assessment(
            "websocket_authorization",
            endpoint="/ws",
            endpoint_schema=schema(query=("channel",), auth=("session",)),
            details={
                "status_code": 101,
                "websocket_url": "wss://fixture.invalid/ws",
                "context_observations": [{
                    "context": "low_privilege_user",
                    "expected_access": "denied",
                    "channel": "tenant-200-private",
                    "subscription_accepted": True,
                    "message_received": True,
                }],
            },
            category="websocket subscription authorization",
        )
        self.assertTrue(decision["admitted"])
        self.assertIn("unauthorized_subscription", support)

        decision, _, contradict = assessment(
            "websocket_authorization",
            endpoint="/ws",
            endpoint_schema=schema(query=("channel",), auth=("session",)),
            details={
                "status_code": 101,
                "context_observations": [{
                    "context": "low_privilege_user",
                    "expected_access": "denied",
                    "channel": "tenant-200-private",
                    "subscription_accepted": False,
                    "message_received": False,
                }],
            },
            category="websocket subscription authorization",
        )
        self.assertFalse(decision["admitted"])
        self.assertIn("cross_context_denied", contradict)

    def test_business_logic_and_business_flow_conditions_are_observation_bound(self) -> None:
        decision, support, _ = assessment(
            "business_logic",
            endpoint="/api/checkout",
            method="POST",
            endpoint_schema=schema(body=("order_id", "amount"), auth=("session",)),
            details={
                "status_code": 200,
                "workflow_observation": {
                    "order_state_before": "unpaid",
                    "requested_transition": "download",
                    "order_state_after": "download_enabled",
                    "payment_confirmed": False,
                },
            },
            category="checkout workflow invariant",
            business_context="payments",
        )
        self.assertTrue(decision["admitted"])
        self.assertIn("workflow_invariant_violation", support)

        decision, support, _ = assessment(
            "sensitive_business_flow_abuse",
            endpoint="/api/password-reset",
            method="POST",
            endpoint_schema=schema(body=("email",)),
            details={
                "status_code": 200,
                "automation_observation": {
                    "same_identity_attempts": 50,
                    "accepted_attempts": 50,
                    "rate_limit_response_seen": False,
                    "challenge_present": False,
                },
            },
            category="sensitive workflow automation control",
            business_context="identity",
        )
        self.assertTrue(decision["admitted"])
        self.assertIn("automation_limit_absent", support)

        decision, _, contradict = assessment(
            "sensitive_business_flow_abuse",
            endpoint="/api/password-reset",
            method="POST",
            endpoint_schema=schema(body=("email",)),
            details={
                "status_code": 429,
                "automation_observation": {
                    "same_identity_attempts": 50,
                    "accepted_attempts": 5,
                    "rate_limit_response_seen": True,
                    "challenge_present": True,
                },
            },
            category="sensitive workflow automation control",
            business_context="identity",
        )
        self.assertFalse(decision["admitted"])
        self.assertIn("anti_bot_control_enforced", contradict)

    def test_2025_completion_families_reconstruct_only_explicit_stored_conditions(self) -> None:
        cases = (
            (
                "software_supply_chain_failure",
                "/build-metadata",
                "dependency component inventory",
                {"status_code": 200, "dependency_manifest": {"package": "fixture-component", "version": "1.2.3", "deployed": True}, "component_observation": {"security_advisory_present": True, "affected_version": True, "fixed_version_available": "1.2.4"}},
                "known_vulnerable_component_observed",
            ),
            (
                "cryptographic_failure",
                "https://crypto.fixture.invalid/session",
                "tls cryptographic transport",
                {"status_code": 200, "tls_observation": {"protocol": "TLSv1.0", "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "certificate_valid": True}},
                "weak_tls_observed",
            ),
            (
                "software_data_integrity_failure",
                "/api/update",
                "software update integrity verification",
                {"status_code": 200, "update_observation": {"artifact": "fixture-update.pkg", "signature_present": False, "signature_verified": False, "installation_accepted": True}},
                "unsigned_update_accepted",
            ),
            (
                "security_logging_alerting_failure",
                "/admin/login",
                "security event audit logging",
                {"status_code": 401, "security_event": {"event_type": "repeated_failed_login", "attempts": 12}, "audit_observation": {"matching_log_entries": 0, "alert_emitted": False, "log_store_checked": True}},
                "security_event_not_logged",
            ),
        )
        for family, endpoint, category, details, condition in cases:
            with self.subTest(family=family):
                decision, support, _ = assessment(
                    family,
                    endpoint=endpoint,
                    method="POST" if endpoint.startswith("/api/") or endpoint == "/admin/login" else "GET",
                    endpoint_schema=schema(body=("username", "password")) if family == "security_logging_alerting_failure" else schema(),
                    details=details,
                    category=category,
                    business_context="identity" if family == "security_logging_alerting_failure" else "general",
                )
                self.assertTrue(decision["admitted"], (family, decision, support))
                self.assertIn(condition, support)

    def test_source_map_requires_content_and_public_fetch(self) -> None:
        decision, support, _ = assessment(
            "source_map_exposure",
            endpoint="/pkg/module.mjs.map",
            details={
                "status_code": 200,
                "source_map": {"version": 3, "sources": ["../../server/config.ts"], "sourcesContent": ["export const internalSetting = 'fixture';"]},
                "public_fetch": True,
            },
            category="public javascript source map",
        )
        self.assertTrue(decision["admitted"])
        self.assertIn("public_observation", support)
        self.assertIn("source_contents", support)

        decision, support, _ = assessment(
            "source_map_exposure",
            endpoint="/pkg/module.mjs.map",
            details={"status_code": 200, "source_map": {"version": 3, "sources": ["webpack:///src/public.ts"], "sourcesContent": []}, "public_fetch": True},
            category="public javascript source map",
        )
        self.assertFalse(decision["admitted"])
        self.assertNotIn("source_contents", support)

    def test_unsafe_api_certificate_validation_is_grounded_in_cwe_295(self) -> None:
        self.assertIn("upstream_certificate_validation_failure", DETECTOR_SPECS["unsafe_api_consumption"].condition_signals)
        self.assertIn("CWE-295", {row["id"] for row in FAMILY_STANDARDS["unsafe_api_consumption"]["cwe"]})
        decision, support, _ = assessment(
            "unsafe_api_consumption",
            endpoint="/api/vendor-sync",
            method="POST",
            endpoint_schema=schema(body=("vendor_id",)),
            details={
                "status_code": 200,
                "upstream_observation": {
                    "url": "https://vendor.fixture.invalid/data",
                    "tls_certificate_present": True,
                    "hostname_matches_certificate": False,
                    "response_accepted": True,
                    "trusted_upstream": True,
                },
            },
            category="third-party upstream api integration",
            business_context="integration",
        )
        self.assertTrue(decision["admitted"])
        self.assertIn("upstream_certificate_validation_failure", support)

    def test_inventory_does_not_treat_test_named_business_endpoint_as_nonproduction(self) -> None:
        decision, support, _ = assessment(
            "improper_inventory_management",
            endpoint="/api/v1/users/test_race",
            method="PUT",
            endpoint_schema=schema(body=("coupon",)),
            details={"status_code": 200, "response_text": "single fixture request returned success"},
            category="redeem single-use concurrent business flow",
            business_context="payment",
        )
        self.assertFalse(decision["admitted"])
        self.assertFalse(set(DETECTOR_SPECS["improper_inventory_management"].condition_signals) & support)

    def test_admin_login_is_not_routed_as_privileged_function_authorization(self) -> None:
        execution = execute_detector_intelligence(
            target="fixture.invalid",
            endpoint="/admin/login",
            method="POST",
            endpoint_schema=schema(body=("username", "password")),
            details={"status_code": 401, "security_event": {"event_type": "repeated_failed_login"}, "audit_observation": {"matching_log_entries": 0, "log_store_checked": True}},
            category="security event audit logging",
            business_context="identity",
        )
        bfa = execution.get("broken_function_authorization", {"support": []})
        self.assertNotIn("privileged_function", {row.get("type") for row in bfa.get("support") or []})

    def test_component_lineage_is_627(self) -> None:
        self.assertGreaterEqual(tuple(int(x) for x in EXECUTION_ENGINE_VERSION.split(".")), (1, 3, 0))
        self.assertGreaterEqual(tuple(int(x) for x in EXECUTION_RULE_VERSION.split(".")), (2026, 8, 13, 6, 27))
        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.5.0")
        self.assertEqual(ADMISSION_RULE_VERSION, "2026.08.13.6.27")
        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.2.0")
        self.assertEqual(DETECTOR_RULE_VERSION, "2026.08.13.6.27")
        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.4.0")
        self.assertEqual(set(FAMILY_ADMISSION_POLICIES), set(DETECTOR_SPECS))
        self.assertEqual(len(DETECTOR_SPECS), 36)


if __name__ == "__main__":
    unittest.main()
