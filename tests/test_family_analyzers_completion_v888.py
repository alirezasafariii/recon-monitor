from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import bug_candidates
from core import APP_VERSION, Database, utc_now
from family_analyzers.business_logic import analyze_business_logic_signal
from family_analyzers.cors_misconfiguration import analyze_cors_misconfiguration_signal
from family_analyzers.graphql_authorization import analyze_graphql_authorization_signal
from family_analyzers.graphql_data_exposure import analyze_graphql_data_exposure_signal
from family_analyzers.race_condition import analyze_race_condition_signal
from family_analyzers.router import analyzer_for_family, router_status
from family_analyzers.sensitive_caching import analyze_sensitive_caching_signal
from family_analyzers.websocket_authorization import analyze_websocket_authorization_signal
from family_reasoning import FAMILY_ORDER


class RemainingFamilyCompletionV888Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-FINAL-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES('AN-FINAL-FAMILY','RUN-FINAL-FAMILY','example.com','8.6','family-final','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def test_router_is_21_of_21_without_fallback(self) -> None:
        status = router_status()
        self.assertEqual(status["registered_count"], 21)
        self.assertEqual(status["pending_count"], 0)
        self.assertEqual(status["registered"], list(FAMILY_ORDER))
        self.assertEqual(status["pending"], [])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        for family in FAMILY_ORDER:
            self.assertIsNotNone(analyzer_for_family(family), family)

    def test_graphql_authorization_static_surface_is_one_root_and_hidden(self) -> None:
        result = analyze_graphql_authorization_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            js_url="https://example.com/app.js",
            operation_name="GetOrder",
            operation_type="query",
            identifiers=["orderId"],
            details={},
        )
        self.assertIsNotNone(result)
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertEqual(result["family_analyzer"]["independent_evidence_roots"], 1)

    def test_graphql_authorization_controlled_test_object_can_confirm(self) -> None:
        result = analyze_graphql_authorization_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            operation_name="GetOrder",
            identifiers=["orderId"],
            details={
                "graphql_authorization_observations": [
                    {
                        "controlled_test_context": True,
                        "test_owned_object": True,
                        "graphql_authorization_differential": True,
                    }
                ]
            },
        )
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_graphql_data_static_fields_are_not_response_evidence(self) -> None:
        result = analyze_graphql_data_exposure_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            operation_name="Profile",
            sensitive_fields=["email", "balance"],
            details={},
        )
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertEqual(result["family_analyzer"]["independent_evidence_roots"], 1)

    def test_graphql_data_controlled_policy_response_can_confirm(self) -> None:
        result = analyze_graphql_data_exposure_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            operation_name="Profile",
            sensitive_fields=["email"],
            details={
                "graphql_data_exposure_observations": [
                    {
                        "controlled_test_context": True,
                        "field_policy_expected_restricted": True,
                        "sensitive_graphql_response_observed": True,
                    }
                ]
            },
        )
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_business_keywords_alone_are_not_direct(self) -> None:
        result = analyze_business_logic_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            endpoint="/checkout/order/confirm",
            method="POST",
            details={},
            semantic_text="checkout order confirm price quantity",
        )
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["state_changing_request_performed"])

    def test_business_controlled_reversible_invariant_can_confirm(self) -> None:
        result = analyze_business_logic_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            endpoint="/checkout/order/confirm",
            method="POST",
            details={
                "workflow_observations": [
                    {
                        "controlled_test_context": True,
                        "reversible_test_data": True,
                        "expected_invariant_documented": True,
                        "invalid_transition_accepted": True,
                    }
                ]
            },
            semantic_text="checkout order confirm price quantity",
        )
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_race_uses_only_authorized_stored_concurrency_evidence(self) -> None:
        result = analyze_race_condition_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            endpoint="/coupon/redeem",
            method="POST",
            details={
                "race_condition_observations": [
                    {
                        "concurrency_test_authorized": True,
                        "test_owned_resource": True,
                        "duplicate_operation_observed": True,
                    }
                ]
            },
            semantic_text="coupon redeem claim",
        )
        self.assertTrue(result["direct"])
        self.assertFalse(result["family_analyzer"]["concurrent_requests_performed"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_websocket_static_surface_hidden_and_controlled_channel_direct(self) -> None:
        static = analyze_websocket_authorization_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            js_url="https://example.com/app.js",
            sink_kind="websocket",
            operation="subscribe channel",
            channel_identifiers=["roomId"],
            details={},
        )
        self.assertFalse(static["direct"])
        self.assertFalse(static["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        direct = analyze_websocket_authorization_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            sink_kind="websocket",
            operation="subscribe channel",
            channel_identifiers=["roomId"],
            details={
                "websocket_authorization_observations": [
                    {
                        "controlled_test_context": True,
                        "test_owned_channel": True,
                        "unauthorized_subscription_observed": True,
                    }
                ]
            },
        )
        self.assertTrue(direct["direct"])
        self.assertFalse(direct["family_analyzer"]["socket_connection_performed"])

    def test_cors_wildcard_not_direct_but_controlled_sensitive_read_is(self) -> None:
        surface = analyze_cors_misconfiguration_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            endpoint="/api/me",
            details={
                "headers": {"Access-Control-Allow-Origin": "*"},
                "authenticated_response": True,
            },
            business_context="identity",
        )
        self.assertFalse(surface["direct"])
        direct = analyze_cors_misconfiguration_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            endpoint="/api/me",
            details={
                "headers": {"Access-Control-Allow-Origin": "https://controlled.invalid"},
                "authenticated_response": True,
                "cors_observations": [
                    {
                        "controlled_origin": True,
                        "origin_untrusted_by_policy": True,
                        "credentials_included": True,
                        "cross_origin_response_readable": True,
                        "sensitive_response": True,
                    }
                ],
            },
            business_context="identity",
        )
        self.assertTrue(direct["direct"])
        self.assertFalse(direct["family_analyzer"]["credentialed_request_performed"])

    def test_sensitive_cache_private_control_and_redacted_cross_identity_direct(self) -> None:
        private = analyze_sensitive_caching_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            endpoint="/api/me",
            details={
                "headers": {"Cache-Control": "private, no-store"},
                "authenticated_response": True,
            },
            business_context="identity",
        )
        self.assertIn("private_cache_control_observed", {x["type"] for x in private["contradict"]})
        direct = analyze_sensitive_caching_signal(
            self.db,
            analysis_id="AN-FINAL-FAMILY",
            target="example.com",
            endpoint="/api/me",
            details={
                "headers": {"Cache-Control": "public, max-age=60"},
                "authenticated_response": True,
                "shared_cache_observations": [
                    {
                        "controlled_test_context": True,
                        "response_body_redacted": True,
                        "sensitive_response": True,
                        "shared_cache_hit": True,
                        "cross_user_cache_observed": True,
                        "two_controlled_test_identities": True,
                    }
                ],
            },
            business_context="identity",
        )
        self.assertTrue(direct["direct"])
        self.assertFalse(direct["family_analyzer"]["response_body_stored"])

    def _insert_graphql(self) -> None:
        columns = {row["name"] for row in self.db.all("PRAGMA table_info(graphql_intelligence)")}
        values = {
            "analysis_id": "AN-FINAL-FAMILY",
            "target": "example.com",
            "run_id": "RUN-FINAL-FAMILY",
            "js_url": "https://example.com/app.js",
            "operation_type": "query",
            "operation_name": "GetOrder",
            "identifiers_json": json.dumps(["orderId"]),
            "sensitive_fields_json": json.dumps(["email"]),
            "variables_json": "{}",
            "confidence": 80,
            "created_at": utc_now(),
        }
        keys = [key for key in values if key in columns]
        self.db.execute(
            f"INSERT INTO graphql_intelligence({','.join(keys)}) VALUES({','.join('?' for _ in keys)})",
            tuple(values[key] for key in keys),
        )

    def test_legacy_graphql_static_direct_insert_is_closed(self) -> None:
        self._insert_graphql()
        bug_candidates._static_candidates(
            self.db, "AN-FINAL-FAMILY", "RUN-FINAL-FAMILY", "example.com"
        )
        auth_h = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='graphql_authorization'",
            ("AN-FINAL-FAMILY",),
        )
        data_h = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='graphql_data_exposure'",
            ("AN-FINAL-FAMILY",),
        )
        self.assertIsNotNone(auth_h)
        self.assertIsNotNone(data_h)
        self.assertFalse(json.loads(auth_h["admission_json"])["admitted"])
        self.assertFalse(json.loads(data_h["admission_json"])["admitted"])
        self.assertIsNone(
            self.db.one(
                "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family IN ('graphql_authorization','graphql_data_exposure')",
                ("AN-FINAL-FAMILY",),
            )
        )

    def test_legacy_websocket_static_direct_insert_is_closed(self) -> None:
        columns = {row["name"] for row in self.db.all("PRAGMA table_info(js_dataflows)")}
        values = {
            "analysis_id": "AN-FINAL-FAMILY",
            "target": "example.com",
            "run_id": "RUN-FINAL-FAMILY",
            "js_url": "https://example.com/socket.js",
            "source_kind": "location.search",
            "sink_kind": "websocket",
            "snippet": "new WebSocket(url)",
            "confidence": 80,
            "created_at": utc_now(),
        }
        keys = [key for key in values if key in columns]
        self.db.execute(
            f"INSERT INTO js_dataflows({','.join(keys)}) VALUES({','.join('?' for _ in keys)})",
            tuple(values[key] for key in keys),
        )
        bug_candidates._static_candidates(
            self.db, "AN-FINAL-FAMILY", "RUN-FINAL-FAMILY", "example.com"
        )
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='websocket_authorization'",
            ("AN-FINAL-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        self.assertFalse(json.loads(hypothesis["admission_json"])["admitted"])
        self.assertIsNone(
            self.db.one(
                "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='websocket_authorization'",
                ("AN-FINAL-FAMILY",),
            )
        )


if __name__ == "__main__":
    unittest.main()
