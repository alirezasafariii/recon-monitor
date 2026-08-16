from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import family_signal_bridge
from family_analyzers.base import FamilyAnalyzerContext
from family_analyzers.router import analyzer_for_family
from owasp_phase2_catalog import PHASE2_FAMILY_SPECS
from family_signal_bridge import (
    FAMILY_SIGNAL_BRIDGE_VERSION,
    augment_family_details,
    clear_family_signal_bridge_cache,
)


class _BridgeDb:
    def __init__(self):
        self.calls = 0

    def all(self, sql, params=()):
        self.calls += 1
        if "endpoint_contracts" in sql:
            return [{
                "input_fields_json": '{"query":["filter"]}',
                "output_fields_json": '["account.id"]',
                "auth_boundary": "session_required",
                "content_type": "text/html",
                "confidence": 90,
            }]
        if "authentication_boundaries" in sql:
            return [{"boundary": "session_required", "confidence": 90}]
        if "response_shape_fingerprints" in sql:
            return [{"sensitive_keys_json": '["account.id"]', "confidence": 82}]
        if "protocol_findings" in sql:
            return [{
                "protocol": "oauth_oidc",
                "kind": "flow_markers",
                "entity": "https://example.test/admin/settings",
                "confidence": 81,
                "severity": "low",
                "summary": "Stored OAuth/OIDC flow markers were observed.",
                "evidence_json": "{}",
            }]
        if "semantic_js_units" in sql:
            return [
                {
                    "js_url": "https://example.test/app.js",
                    "unit_type": "storage_key",
                    "unit_key": "auth-token",
                    "value_json": '{"value":"/admin/settings"}',
                    "confidence": 84,
                },
                {
                    "js_url": "https://example.test/app.js",
                    "unit_type": "oauth_parameter",
                    "unit_key": "redirect-uri",
                    "value_json": '{"value":"redirect_uri /admin/settings pkce"}',
                    "confidence": 86,
                },
            ]
        if "technology_observations" in sql:
            return [{
                "url": "https://example.test/admin/settings",
                "technology": "nginx 1.25.4",
                "confidence": 78,
                "evidence_json": "{}",
            }]
        return []


class _MissingTablesDb:
    def all(self, sql, params=()):
        raise RuntimeError("table missing")


class FamilySignalBridgeV950Tests(unittest.TestCase):
    def setUp(self):
        clear_family_signal_bridge_cache()

    def test_context_is_enriched_from_existing_analysis_tables(self):
        context = FamilyAnalyzerContext(
            db=_BridgeDb(),
            analysis_id="analysis-1",
            target="example.test",
            endpoint="https://example.test/admin/settings",
            method="POST",
            details={"status_code": 200, "content_type": "text/html"},
        )
        self.assertTrue(context.details["administrative_interface_surface"])
        self.assertTrue(context.details["oauth_oidc_flow_surface"])
        self.assertTrue(context.details["browser_storage_surface"])
        self.assertTrue(context.details["cookie_authenticated_state_change_surface"])
        bridge = context.details["_family_signal_bridge"]
        self.assertEqual(bridge["version"], FAMILY_SIGNAL_BRIDGE_VERSION)
        self.assertTrue(bridge["context_only"])
        self.assertFalse(bridge["network_requests"])
        self.assertFalse(bridge["decisive_signals_synthesized"])

    def test_phase2_context_contracts_have_explicit_bridge_mapping(self):
        source = inspect.getsource(family_signal_bridge)
        for family, spec in PHASE2_FAMILY_SPECS.items():
            with self.subTest(family=family):
                for signal in spec["context"]:
                    self.assertIn(signal, source)

    def test_bridge_never_manufactures_decisive_family_evidence(self):
        details = augment_family_details(
            _BridgeDb(),
            analysis_id="analysis-1",
            target="example.test",
            endpoint="https://example.test/admin/settings",
            method="POST",
            details={"status_code": 200, "content_type": "text/html"},
        )
        forbidden = {
            "controlled_oauth_flow_security_bypass_observed",
            "sensitive_token_persisted_in_web_storage_observed",
            "unauthenticated_admin_function_exposed_observed",
            "http_parser_framing_disagreement_observed",
            "controlled_request_desynchronization_observed",
            "provider_resource_claimability_confirmed_authorized",
        }
        self.assertFalse(forbidden & set(details))

    def test_phase2_analyzer_receives_bridge_context_but_does_not_promote_without_unsafe_evidence(self):
        context = FamilyAnalyzerContext(
            db=_BridgeDb(),
            analysis_id="analysis-1",
            target="example.test",
            endpoint="https://example.test/admin/settings",
            method="POST",
            details={"status_code": 200, "content_type": "text/html"},
        )
        analyzer = analyzer_for_family("oauth_oidc_weakness")
        self.assertIsNotNone(analyzer)
        result = analyzer.analyze(context)
        self.assertIsNotNone(result)
        self.assertIn(
            "oauth_oidc_flow_surface",
            {str(item.get("type") or "") for item in result.get("support", [])},
        )
        self.assertFalse(result["direct"])
        self.assertFalse(
            result["family_analyzer"]["promotion_ready_from_stored_target_evidence"]
        )

    def test_repeated_family_contexts_reuse_bounded_db_snapshot(self):
        db = _BridgeDb()
        first = FamilyAnalyzerContext(
            db=db,
            analysis_id="analysis-cache",
            target="example.test",
            endpoint="https://example.test/admin/settings",
            method="POST",
            details={"status_code": 200, "content_type": "text/html"},
        )
        first_calls = db.calls
        second = FamilyAnalyzerContext(
            db=db,
            analysis_id="analysis-cache",
            target="example.test",
            endpoint="https://example.test/admin/settings",
            method="POST",
            details={"status_code": 200, "content_type": "text/html"},
        )
        self.assertGreater(first_calls, 0)
        self.assertEqual(db.calls, first_calls)
        self.assertTrue(first.details["oauth_oidc_flow_surface"])
        self.assertTrue(second.details["oauth_oidc_flow_surface"])

    def test_missing_optional_tables_are_fail_soft(self):
        original = {"status_code": 200}
        details = augment_family_details(
            _MissingTablesDb(),
            analysis_id="analysis-legacy",
            target="example.test",
            endpoint="https://example.test/",
            method="GET",
            details=original,
        )
        self.assertEqual(details["status_code"], 200)
        self.assertIn("_family_signal_bridge", details)

    def test_no_analysis_identity_preserves_original_details(self):
        details = augment_family_details(
            None,
            analysis_id="",
            target="",
            endpoint="",
            method="GET",
            details={"custom": "value"},
        )
        self.assertEqual(details, {"custom": "value"})


if __name__ == "__main__":
    unittest.main()
