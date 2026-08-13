from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_ranking import rank_families
from family_detectors import evaluate_family_detector, execute_detector_intelligence
from hypothesis_admission import assess_admission
from raw_condition_reconstruction import RECONSTRUCTION_ENGINE_VERSION, RECONSTRUCTION_RULE_VERSION


def schema(*, query=(), body=(), path=(), object_ids=(), auth=()):
    return {
        "query_parameters": list(query),
        "body_fields": list(body),
        "path_parameters": list(path),
        "object_identifiers": list(object_ids),
        "authentication_hints": list(auth),
    }


def packets(*, endpoint: str, method: str = "GET", endpoint_schema=None, details=None, category="", business_context="general"):
    execution = execute_detector_intelligence(
        target="fixture.invalid",
        endpoint=endpoint,
        method=method,
        endpoint_schema=endpoint_schema or schema(),
        details=details or {},
        category=category,
        business_context=business_context,
    )
    prepared = {}
    support = []
    contradict = []
    for family, packet in execution.items():
        scoped = evaluate_family_detector(family, packet.get("support") or [], packet.get("contradict") or [], channel="analysis_627_precision")
        prepared[family] = scoped
        support.extend(scoped.get("support") or [])
        contradict.extend(scoped.get("contradict") or [])
    return prepared, support, contradict, rank_families(support, contradict)


def types(prepared, family, side="support"):
    return {str(row.get("type") or "") for row in prepared.get(family, {}).get(side, [])}


def is_admitted(prepared, family):
    packet = prepared.get(family, {"support": [], "contradict": []})
    return assess_admission(family, packet.get("support") or [], packet.get("contradict") or [])["admitted"]


class Analysis627PrecisionRoutingTests(unittest.TestCase):
    def test_graphql_object_context_is_not_reinterpreted_as_auth_session_or_generic_bola(self):
        prepared, _, _, ranked = packets(
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
        self.assertTrue(is_admitted(prepared, "graphql_authorization"))
        self.assertFalse(is_admitted(prepared, "authentication_session"))
        self.assertFalse(is_admitted(prepared, "broken_object_authorization"))
        self.assertNotIn("authentication_boundary_regression", types(prepared, "authentication_session"))
        self.assertNotIn("unauthorized_object_response", types(prepared, "broken_object_authorization"))
        self.assertEqual(ranked[0]["family"], "graphql_authorization")

    def test_invalid_session_context_still_reconstructs_authentication_boundary_failure(self):
        prepared, _, _, _ = packets(
            endpoint="/api/session/refresh",
            method="POST",
            endpoint_schema=schema(auth=("session",)),
            details={"context_observations": [{"context": "invalid_session", "expected_access": "denied", "status_code": 200}]},
            business_context="identity",
        )
        self.assertIn("authentication_boundary_regression", types(prepared, "authentication_session"))
        self.assertTrue(is_admitted(prepared, "authentication_session"))

    def test_unhandled_exception_text_alone_is_not_stack_trace_misconfiguration(self):
        prepared, _, _, ranked = packets(
            endpoint="/api/process",
            method="POST",
            endpoint_schema=schema(body=("operation",)),
            details={
                "status_code": 500,
                "response_text": "Unhandled exception while processing request",
                "exception_observation": {"exception_type": "UnhandledRuntimeError", "handled": False, "process_crashed": True},
            },
            category="exception handling state transition",
            business_context="workflow",
        )
        self.assertTrue(is_admitted(prepared, "exceptional_condition_mishandling"))
        self.assertIn("crash_on_exception", types(prepared, "exceptional_condition_mishandling"))
        self.assertNotIn("stack_trace_exposed", types(prepared, "security_misconfiguration"))
        self.assertFalse(is_admitted(prepared, "security_misconfiguration"))
        self.assertEqual(ranked[0]["family"], "exceptional_condition_mishandling")

    def test_source_map_reachability_condition_requires_meaningful_internal_material(self):
        positive, _, _, _ = packets(
            endpoint="/app.js.map",
            details={"status_code": 200, "response_body": '{"sources":["../src/app.ts"],"sourcesContent":["const x=1"]}'},
        )
        self.assertIn("direct_reachability", types(positive, "source_map_exposure"))

        empty, _, _, _ = packets(
            endpoint="/app.js.map",
            details={"status_code": 200, "source_map": {"version": 3, "sources": ["webpack:///src/public.ts"], "sourcesContent": []}, "public_fetch": True},
        )
        self.assertNotIn("direct_reachability", types(empty, "source_map_exposure"))
        self.assertIn("empty_map", types(empty, "source_map_exposure", "contradict"))
        self.assertFalse(is_admitted(empty, "source_map_exposure"))

    def test_body_business_identifier_does_not_create_generic_bola_surface(self):
        prepared, _, _, ranked = packets(
            endpoint="/api/checkout",
            method="POST",
            endpoint_schema=schema(body=("order_id", "amount"), auth=("session",)),
            details={
                "status_code": 200,
                "workflow_observation": {"order_state_before": "paid", "requested_transition": "download", "order_state_after": "download_enabled", "payment_confirmed": True},
            },
            category="checkout workflow invariant",
            business_context="payments",
        )
        self.assertNotIn("object_identifier", types(prepared, "broken_object_authorization"))
        self.assertEqual(ranked[0]["family"], "business_logic")
        self.assertFalse(is_admitted(prepared, "business_logic"))

    def test_safe_cors_policy_routes_to_cors_but_remains_blocked(self):
        prepared, _, _, ranked = packets(
            endpoint="/api/data",
            endpoint_schema=schema(auth=("session",)),
            details={
                "status_code": 200,
                "request_headers": {"Origin": "https://untrusted.fixture.invalid"},
                "response_headers": {"Access-Control-Allow-Origin": "https://trusted.fixture.invalid"},
            },
            category="cors cross-origin authenticated response",
            business_context="customer_data",
        )
        self.assertIn("cors_policy_surface", types(prepared, "cors_misconfiguration"))
        self.assertIn("strict_origin_allowlist", types(prepared, "cors_misconfiguration", "contradict"))
        self.assertFalse(is_admitted(prepared, "cors_misconfiguration"))
        self.assertEqual(ranked[0]["family"], "cors_misconfiguration")

    def test_safe_dom_render_path_routes_to_dom_without_promotion(self):
        prepared, _, _, ranked = packets(
            endpoint="/app",
            details={
                "status_code": 200,
                "javascript": "const value = location.hash.slice(1); document.querySelector('#result').textContent = value;",
                "browser_observation": {"input_channel": "location.hash", "render_target": "#result", "rendered_as_html": False},
            },
            category="client javascript rendering",
        )
        self.assertIn("source_sink", types(prepared, "dom_xss"))
        self.assertIn("text_only_sink", types(prepared, "dom_xss", "contradict"))
        self.assertFalse(is_admitted(prepared, "dom_xss"))
        self.assertEqual(ranked[0]["family"], "dom_xss")

    def test_handled_exception_routes_to_exception_family_without_promotion(self):
        prepared, _, _, ranked = packets(
            endpoint="/api/process",
            method="POST",
            endpoint_schema=schema(body=("operation",)),
            details={
                "status_code": 409,
                "exception_observation": {"exception_type": "RuntimeError", "handled": True, "process_crashed": False, "rollback_completed": True},
            },
            category="exception handling state transition",
            business_context="workflow",
        )
        self.assertIn("exception_surface", types(prepared, "exceptional_condition_mishandling"))
        self.assertIn("transaction_rollback_observed", types(prepared, "exceptional_condition_mishandling", "contradict"))
        self.assertFalse(is_admitted(prepared, "exceptional_condition_mishandling"))
        self.assertEqual(ranked[0]["family"], "exceptional_condition_mishandling")

    def test_reconstruction_lineage_is_627(self):
        self.assertEqual(RECONSTRUCTION_ENGINE_VERSION, "1.2.0")
        self.assertEqual(RECONSTRUCTION_RULE_VERSION, "2026.08.13.6.27")


if __name__ == "__main__":
    unittest.main()
