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
from family_analyzers.account_enumeration import (
    ACCOUNT_ENUMERATION_FAMILY_ANALYZER_VERSION,
    ACCOUNT_ENUMERATION_METHOD,
    analyze_account_enumeration_signal,
)
from family_analyzers.router import analyzer_for_family, router_status


class AccountEnumerationFamilyAnalyzerV872Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-ENUM-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-ENUM-FAMILY','RUN-ENUM-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(
        self,
        details,
        *,
        endpoint="https://example.com/api/password/reset",
        method="POST",
        body_fields=None,
        query_fields=None,
        semantic_text="",
    ):
        return analyze_account_enumeration_signal(
            self.db,
            analysis_id="AN-ENUM-FAMILY",
            target="example.com",
            endpoint=endpoint,
            method=method,
            body_fields=list(["email"] if body_fields is None else body_fields),
            query_fields=list([] if query_fields is None else query_fields),
            details=details,
            business_context="identity",
            semantic_text=semantic_text,
        )

    def test_router_registers_five_dedicated_families_without_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered_count"], 5)
        self.assertEqual(status["pending_count"], 16)
        self.assertEqual(status["registered"], [
            "broken_object_authorization",
            "broken_function_authorization",
            "mass_assignment",
            "authentication_session",
            "account_enumeration",
        ])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("account_enumeration"))
        self.assertIsNone(analyzer_for_family("ssrf"))

    def test_methodology_grounding_is_non_evidentiary(self):
        result = self.analyze({})
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(ACCOUNT_ENUMERATION_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("WSTG-IDNT-04", meta["taxonomy"]["wstg"])
        self.assertIn("CWE-204", meta["taxonomy"]["cwe"])
        self.assertIn("CWE-208", meta["taxonomy"]["cwe"])
        basis = {item for step in ACCOUNT_ENUMERATION_METHOD for item in step["basis"]}
        self.assertIn("WSTG-IDNT-04", basis)
        self.assertIn("CWE-204", basis)
        self.assertIn("CWE-208", basis)
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])
        self.assertTrue(meta["controlled_test_identity_requirement"])
        self.assertFalse(meta["confirmation_ready_from_stored_target_evidence"])

    def test_identity_lookup_surface_alone_is_not_confirmation(self):
        result = self.analyze({})
        observed = {row["type"] for row in result["support"]}
        self.assertIn("identity_lookup", observed)
        self.assertIn("client_operation", observed)
        self.assertFalse(result["direct"])
        self.assertEqual(result["variant"], "identity_lookup_surface")
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])

    def test_controlled_response_differential_is_direct_confirmation_evidence(self):
        result = self.analyze({
            "identity_observations": [
                {
                    "identity_class": "existing",
                    "controlled_identity": True,
                    "status_code": 200,
                    "message_class": "reset_link_sent",
                    "response_shape": ["message"],
                },
                {
                    "identity_class": "nonexisting",
                    "controlled_identity": True,
                    "status_code": 404,
                    "message_class": "account_not_found",
                    "response_shape": ["message"],
                },
            ]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("identity_response_differential", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "identity_response_differential")
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        refs = {row["id"] for row in result["family_analyzer"]["writeup_patterns"]}
        self.assertIn("owasp-wstg-idnt-04-response-pattern", refs)
        self.assertTrue(all(row["non_evidentiary"] for row in result["family_analyzer"]["writeup_patterns"]))

    def test_uniform_generic_response_is_false_positive_control(self):
        result = self.analyze({
            "identity_observations": [
                {
                    "identity_class": "existing",
                    "controlled_identity": True,
                    "status_code": 200,
                    "message": "If an account exists, check your email",
                    "response_shape": ["message"],
                },
                {
                    "identity_class": "nonexisting",
                    "controlled_identity": True,
                    "status_code": 200,
                    "message": "If an account exists, check your email",
                    "response_shape": ["message"],
                },
            ]
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("uniform_identity_response", contradictions)
        triggered = {row["signal"] for row in result["family_analyzer"]["triggered_false_positive_checks"]}
        self.assertIn("uniform_identity_response", triggered)
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_stable_repeated_timing_difference_can_be_direct_but_single_sample_cannot(self):
        stable = self.analyze({
            "identity_observations": [
                {
                    "identity_class": "existing",
                    "controlled_identity": True,
                    "status_code": 200,
                    "message": "If an account exists, check your email",
                    "median_ms": 420,
                    "sample_count": 5,
                },
                {
                    "identity_class": "nonexisting",
                    "controlled_identity": True,
                    "status_code": 200,
                    "message": "If an account exists, check your email",
                    "median_ms": 180,
                    "sample_count": 5,
                },
            ]
        })
        stable_types = {row["type"] for row in stable["support"]}
        self.assertIn("identity_timing_differential", stable_types)
        self.assertTrue(stable["direct"])
        self.assertTrue(stable["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        refs = {row["id"] for row in stable["family_analyzer"]["writeup_patterns"]}
        self.assertIn("cwe-208-account-timing-pattern", refs)

        single = self.analyze({
            "identity_observations": [
                {
                    "identity_class": "existing",
                    "controlled_identity": True,
                    "status_code": 200,
                    "median_ms": 600,
                    "sample_count": 1,
                },
                {
                    "identity_class": "nonexisting",
                    "controlled_identity": True,
                    "status_code": 200,
                    "median_ms": 100,
                    "sample_count": 1,
                },
            ]
        })
        single_types = {row["type"] for row in single["support"]}
        self.assertNotIn("identity_timing_differential", single_types)
        self.assertFalse(single["direct"])

    def test_rate_limit_confounded_difference_never_becomes_direct_evidence(self):
        result = self.analyze({
            "identity_observations": [
                {
                    "identity_class": "existing",
                    "controlled_identity": True,
                    "status_code": 200,
                    "message_class": "reset_link_sent",
                    "median_ms": 500,
                    "sample_count": 5,
                },
                {
                    "identity_class": "nonexisting",
                    "controlled_identity": True,
                    "status_code": 429,
                    "message_class": "rate_limited",
                    "median_ms": 100,
                    "sample_count": 5,
                    "rate_limited": True,
                },
            ]
        })
        observed = {row["type"] for row in result["support"]}
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertNotIn("identity_response_differential", observed)
        self.assertNotIn("identity_timing_differential", observed)
        self.assertIn("rate_limit_confounded", contradictions)
        self.assertFalse(result["direct"])

    def test_uncontrolled_identity_observations_do_not_create_direct_evidence(self):
        result = self.analyze({
            "identity_observations": [
                {"identity_class": "existing", "status_code": 200, "message_class": "known"},
                {"identity_class": "nonexisting", "status_code": 404, "message_class": "missing"},
            ]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertNotIn("identity_response_differential", observed)
        self.assertNotIn("identity_timing_differential", observed)
        self.assertFalse(result["direct"])

    def test_non_identity_surface_does_not_emit(self):
        result = self.analyze(
            {},
            endpoint="https://example.com/api/catalog",
            method="GET",
            body_fields=[],
            query_fields=["page"],
            semantic_text="ordinary public catalog listing",
        )
        self.assertIsNone(result)

    def test_candidate_engine_routes_account_enumeration_before_admission(self):
        endpoint = "https://example.com/api/password/reset"
        details = {
            "identity_observations": [
                {
                    "identity_class": "existing",
                    "controlled_identity": True,
                    "status_code": 200,
                    "message_class": "reset_link_sent",
                    "response_shape": ["message"],
                },
                {
                    "identity_class": "nonexisting",
                    "controlled_identity": True,
                    "status_code": 404,
                    "message_class": "account_not_found",
                    "response_shape": ["message"],
                },
            ]
        }
        schema = {
            "endpoint": endpoint,
            "method": "POST",
            "path_parameters": [],
            "query_parameters": [],
            "body_fields": ["email"],
            "object_identifiers": [],
            "authentication_hints": [],
            "is_endpoint": True,
        }
        now = utc_now()
        cursor = self.db.execute(
            """INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "example.com", "enum-prod-1", "new_url", "info", 10, "test",
                endpoint, json.dumps(details), "new", 1, now, now, "RUN-ENUM-FAMILY",
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
                "AN-ENUM-FAMILY", alert_id, "example.com", "RUN-ENUM-FAMILY", "new_url",
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
            "AN-ENUM-FAMILY",
            "RUN-ENUM-FAMILY",
            row,
        )
        self.assertGreaterEqual(count, 1)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='account_enumeration'",
            ("AN-ENUM-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("identity_response_differential", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "account_enumeration")
        self.assertTrue(admission["family_analyzer"]["knowledge_does_not_change_target_evidence"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='account_enumeration'",
            ("AN-ENUM-FAMILY",),
        )
        self.assertIsNotNone(candidate)
        candidate_support = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("identity_response_differential", candidate_support)


if __name__ == "__main__":
    unittest.main()
