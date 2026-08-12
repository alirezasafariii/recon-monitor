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
from family_analyzers.authentication_session import (
    AUTH_SESSION_FAMILY_ANALYZER_VERSION,
    AUTH_SESSION_METHOD,
    analyze_authentication_session_signal,
)
from family_analyzers.router import analyzer_for_family, router_status


class AuthenticationSessionFamilyAnalyzerV871Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-AUTH-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-AUTH-FAMILY','RUN-AUTH-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(
        self,
        details,
        *,
        endpoint="https://example.com/api/session",
        method="POST",
        body_fields=None,
        query_fields=None,
        auth_hints=None,
        semantic_text="",
    ):
        return analyze_authentication_session_signal(
            self.db,
            analysis_id="AN-AUTH-FAMILY",
            target="example.com",
            endpoint=endpoint,
            method=method,
            body_fields=list(["refresh_token"] if body_fields is None else body_fields),
            query_fields=list([] if query_fields is None else query_fields),
            auth_hints=list(["bearer"] if auth_hints is None else auth_hints),
            details=details,
            business_context="identity",
            semantic_text=semantic_text,
        )

    def test_router_registers_eleven_dedicated_families_without_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered_count"], 11)
        self.assertEqual(status["pending_count"], 10)
        self.assertEqual(status["registered"], [
            "broken_object_authorization",
            "broken_function_authorization",
            "mass_assignment",
            "authentication_session",
            "account_enumeration",
            "dom_xss",
            "postmessage_trust",
            "open_redirect",
            "ssrf",
            "file_upload",
            "path_traversal",
        ])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("authentication_session"))
        self.assertIsNotNone(analyzer_for_family("account_enumeration"))
        self.assertIsNotNone(analyzer_for_family("dom_xss"))
        self.assertIsNotNone(analyzer_for_family("postmessage_trust"))
        self.assertIsNotNone(analyzer_for_family("open_redirect"))
        self.assertIsNotNone(analyzer_for_family("ssrf"))
        self.assertIsNotNone(analyzer_for_family("file_upload"))
        self.assertIsNotNone(analyzer_for_family("path_traversal"))
        self.assertIsNone(analyzer_for_family("information_disclosure"))

    def test_methodology_grounding_is_non_evidentiary(self):
        result = self.analyze({})
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(AUTH_SESSION_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("CWE-287", meta["taxonomy"]["cwe"])
        self.assertIn("WSTG-ATHN-04", meta["taxonomy"]["wstg"])
        self.assertIn("WSTG-SESS-01", meta["taxonomy"]["wstg"])
        basis = {item for step in AUTH_SESSION_METHOD for item in step["basis"]}
        self.assertIn("CWE-287", basis)
        self.assertIn("CWE-613", basis)
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])
        self.assertFalse(meta["confirmation_ready_from_stored_target_evidence"])

    def test_auth_surface_alone_is_not_confirmation(self):
        result = self.analyze({}, endpoint="https://example.com/api/login", body_fields=["password"])
        observed = {row["type"] for row in result["support"]}
        self.assertIn("authentication_surface", observed)
        self.assertIn("client_operation", observed)
        self.assertFalse(result["direct"])
        self.assertEqual(result["variant"], "auth_lifecycle")
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])

    def test_session_reuse_after_logout_is_direct_confirmation_evidence(self):
        result = self.analyze({
            "session_observations": [
                {
                    "context": "post_logout",
                    "expected_access": False,
                    "access_granted": True,
                    "status_code": 200,
                }
            ]
        }, endpoint="https://example.com/api/logout")
        observed = {row["type"] for row in result["support"]}
        self.assertIn("session_reuse_after_logout", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "session_reuse_after_logout")
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_expected_rotation_failure_and_rotation_control_are_separated(self):
        failed = self.analyze({
            "lifecycle_observations": [
                {
                    "context": "post_login",
                    "rotation_expected": True,
                    "token_before": "session-A",
                    "token_after": "session-A",
                }
            ]
        }, endpoint="https://example.com/api/login")
        failed_types = {row["type"] for row in failed["support"]}
        self.assertIn("token_not_rotated", failed_types)
        self.assertTrue(failed["direct"])
        self.assertEqual(failed["variant"], "token_rotation_failure")

        enforced = self.analyze({
            "lifecycle_observations": [
                {
                    "context": "post_login",
                    "rotation_expected": True,
                    "token_before": "session-A",
                    "token_after": "session-B",
                }
            ]
        }, endpoint="https://example.com/api/login")
        contradiction_types = {row["type"] for row in enforced["contradict"]}
        self.assertIn("session_rotation_observed", contradiction_types)
        self.assertFalse(enforced["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_recovery_requires_explicit_verification_bypass_evidence(self):
        result = self.analyze({
            "authentication_observations": [
                {
                    "context": "password_reset",
                    "recovery_verification_required": True,
                    "verification_passed": False,
                    "recovery_completed": True,
                    "status_code": 200,
                }
            ]
        }, endpoint="https://example.com/api/password/reset", body_fields=["password", "code"])
        observed = {row["type"] for row in result["support"]}
        self.assertIn("recovery_bypass", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "recovery_verification_bypass")
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])

    def test_rotation_recovery_and_expiration_enforcement_trigger_false_positive_controls(self):
        result = self.analyze({
            "session_rotation_observed": True,
            "recovery_verification_enforced": True,
            "expired_session_rejected": True,
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertEqual(
            contradictions,
            {"session_rotation_observed", "recovery_verification_enforced", "expired_session_rejected"},
        )
        triggered = {row["signal"] for row in result["family_analyzer"]["triggered_false_positive_checks"]}
        self.assertEqual(contradictions, triggered)
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_non_authentication_surface_does_not_emit(self):
        result = self.analyze(
            {},
            endpoint="https://example.com/api/catalog",
            method="GET",
            body_fields=[],
            query_fields=["page"],
            auth_hints=[],
            semantic_text="ordinary public catalog listing",
        )
        self.assertIsNone(result)

    def test_writeup_similarity_never_becomes_target_evidence(self):
        result = self.analyze({
            "authentication_state_violation": True,
        }, endpoint="https://example.com/api/sso/callback")
        observed = {row["type"] for row in result["support"]}
        refs = {row["id"] for row in result["family_analyzer"]["writeup_patterns"]}
        self.assertIn("authentication_state_violation", observed)
        self.assertIn("ghsl-ruby-saml-2024-329-330", refs)
        self.assertNotIn("ghsl-ruby-saml-2024-329-330", observed)
        self.assertTrue(all(row["non_evidentiary"] for row in result["family_analyzer"]["writeup_patterns"]))

    def test_candidate_engine_routes_authentication_session_before_admission(self):
        endpoint = "https://example.com/api/logout"
        details = {
            "session_observations": [
                {
                    "context": "post_logout",
                    "expected_access": False,
                    "access_granted": True,
                    "status_code": 200,
                }
            ]
        }
        schema = {
            "endpoint": endpoint,
            "method": "POST",
            "path_parameters": [],
            "query_parameters": [],
            "body_fields": ["session"],
            "object_identifiers": [],
            "authentication_hints": ["bearer"],
            "is_endpoint": True,
        }
        now = utc_now()
        cursor = self.db.execute(
            """INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "example.com", "auth-prod-1", "new_url", "info", 10, "test",
                endpoint, json.dumps(details), "new", 1, now, now, "RUN-AUTH-FAMILY",
            ),
        )
        alert_id = int(cursor.lastrowid)
        self.db.execute(
            """INSERT INTO analysis_results(
            analysis_id,alert_id,target,source_run_id,category,original_score,adjusted_score,confidence,
            hypothesis,next_action,playbook_id,business_context,evidence_for_json,evidence_against_json,
            anomaly_score,baseline_json,feedback_json,duplicate_cluster,rule_ids_json,temporal_json,endpoint_schema_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "AN-AUTH-FAMILY", alert_id, "example.com", "RUN-AUTH-FAMILY", "new_url",
                50, 50, 80, "test", "review", "test", "identity", "[]", "[]",
                0.0, "{}", "{}", "", "[]", "{}", json.dumps(schema), now,
            ),
        )
        row = {
            "alert_id": alert_id,
            "target": "example.com",
            "endpoint_schema_json": json.dumps(schema),
            "details_json": json.dumps(details),
            "evidence_for_json": "[]",
            "evidence_against_json": "[]",
            "confidence": 80,
            "business_context": "identity",
            "category": "new_url",
            "item": endpoint,
        }

        count = bug_candidates._alert_candidates(
            self.db,
            "AN-AUTH-FAMILY",
            "RUN-AUTH-FAMILY",
            row,
        )
        self.assertGreaterEqual(count, 1)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='authentication_session'",
            ("AN-AUTH-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("session_reuse_after_logout", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "authentication_session")
        self.assertTrue(admission["family_analyzer"]["knowledge_does_not_change_target_evidence"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='authentication_session'",
            ("AN-AUTH-FAMILY",),
        )
        self.assertIsNotNone(candidate)
        candidate_support = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("session_reuse_after_logout", candidate_support)


if __name__ == "__main__":
    unittest.main()
