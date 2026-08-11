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
from family_analyzers.bfla import BFLA_FAMILY_ANALYZER_VERSION, BFLA_METHOD, analyze_bfla_signal
from family_analyzers.router import analyzer_for_family, router_status


class BflaFamilyAnalyzerV869Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-BFLA-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-BFLA-FAMILY','RUN-BFLA-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details, *, endpoint="https://example.com/api/admin/users", method="POST", body_fields=None, auth_hints=None, semantic_text=""):
        return analyze_bfla_signal(
            self.db,
            analysis_id="AN-BFLA-FAMILY",
            target="example.com",
            endpoint=endpoint,
            method=method,
            body_fields=list(body_fields or []),
            auth_hints=list(auth_hints or []),
            details=details,
            business_context="administration",
            semantic_text=semantic_text,
        )

    def test_router_registers_bola_bfla_mass_assignment_authentication_enumeration_and_dom_xss_without_generic_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered"], [
            "broken_object_authorization",
            "broken_function_authorization",
            "mass_assignment",
            "authentication_session",
            "account_enumeration",
            "dom_xss",
        ])
        self.assertEqual(status["registered_count"], 6)
        self.assertEqual(status["pending_count"], 15)
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("broken_function_authorization"))
        self.assertIsNotNone(analyzer_for_family("mass_assignment"))
        self.assertIsNotNone(analyzer_for_family("authentication_session"))
        self.assertIsNotNone(analyzer_for_family("account_enumeration"))
        self.assertIsNotNone(analyzer_for_family("dom_xss"))
        self.assertIsNone(analyzer_for_family("ssrf"))

    def test_methodology_is_grounded_in_api5_wstg_and_cwe(self):
        result = self.analyze({}, body_fields=["role"])
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(BFLA_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("CWE-862", meta["taxonomy"]["cwe"])
        self.assertIn("WSTG-APIT-04", meta["taxonomy"]["wstg"])
        self.assertIn("WSTG-ATHZ-02", meta["taxonomy"]["wstg"])
        basis = {item for step in BFLA_METHOD for item in step["basis"]}
        self.assertIn("OWASP API5:2023", basis)
        self.assertIn("CWE-862", basis)
        self.assertIn("WSTG-ATHZ-02", basis)

    def test_privileged_route_alone_is_not_confirmation(self):
        result = self.analyze({}, endpoint="https://example.com/api/admin/audit", method="GET")
        observed = {row["type"] for row in result["support"]}
        self.assertIn("privileged_function", observed)
        self.assertIn("privileged_read_operation", observed)
        self.assertEqual(result["variant"], "privileged_read")
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])

    def test_lower_privilege_success_is_direct_role_boundary_evidence(self):
        result = self.analyze({"context_observations": [{
            "context": "member", "role": "member", "required_role": "admin",
            "expected_access": False, "status_code": 200, "privileged_effect": True,
        }]})
        observed = {row["type"] for row in result["support"]}
        self.assertIn("unauthorized_function_success", observed)
        self.assertIn("role_authorization_differential", observed)
        self.assertIn("privileged_effect_observed", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "vertical_role_bypass")
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])

    def test_permission_scope_mismatch_matches_real_world_patterns_but_stays_non_evidentiary(self):
        result = self.analyze({"context_observations": [{
            "context": "writer", "permission": "event:write", "required_permission": "event:admin",
            "expected_access": False, "status_code": 200,
        }]}, endpoint="https://example.com/api/admin/events/reprocess", method="POST")
        observed = {row["type"] for row in result["support"]}
        self.assertIn("permission_scope_mismatch", observed)
        self.assertIn("role_authorization_differential", observed)
        refs = {row["id"] for row in result["family_analyzer"]["writeup_patterns"]}
        self.assertIn("ghsl-sentry-2025-120", refs)
        self.assertTrue(all(row["non_evidentiary"] for row in result["family_analyzer"]["writeup_patterns"]))
        self.assertNotIn("ghsl-sentry-2025-120", observed)
        self.assertTrue(result["family_analyzer"]["knowledge_does_not_change_target_evidence"])

    def test_enforced_lower_privilege_denial_triggers_false_positive_review(self):
        result = self.analyze({"context_observations": [{
            "context": "member", "role": "member", "required_role": "admin",
            "expected_access": False, "status_code": 403, "role_enforcement": True,
            "permission_enforced": True,
        }]})
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("lower_privilege_denied", contradictions)
        self.assertIn("role_enforcement_observed", contradictions)
        self.assertIn("permission_check_enforced", contradictions)
        triggered = {row["signal"] for row in result["family_analyzer"]["triggered_false_positive_checks"]}
        self.assertIn("lower_privilege_denied", triggered)
        self.assertIn("role_enforcement_observed", triggered)
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_non_privileged_surface_does_not_emit_bfla(self):
        self.assertIsNone(self.analyze({}, endpoint="https://example.com/api/profile", method="GET", semantic_text="ordinary user profile read"))

    def test_candidate_engine_routes_bfla_through_dedicated_analyzer_before_admission(self):
        endpoint = "https://example.com/api/admin/users/disable"
        details = {"context_observations": [{
            "context": "member", "role": "member", "required_role": "admin",
            "expected_access": False, "status_code": 200, "privileged_effect": True,
        }]}
        schema = {
            "endpoint": endpoint, "method": "POST", "path_parameters": [], "query_parameters": [],
            "body_fields": [], "object_identifiers": [], "authentication_hints": ["bearer"], "is_endpoint": True,
        }
        now = utc_now()
        cursor = self.db.execute(
            """INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("example.com", "bfla-prod-1", "new_url", "info", 10, "test", endpoint, json.dumps(details), "new", 1, now, now, "RUN-BFLA-FAMILY"),
        )
        alert_id = int(cursor.lastrowid)
        self.db.execute(
            """INSERT INTO analysis_results(
            analysis_id,alert_id,target,source_run_id,category,original_score,adjusted_score,confidence,
            hypothesis,next_action,playbook_id,business_context,evidence_for_json,evidence_against_json,
            anomaly_score,baseline_json,feedback_json,duplicate_cluster,rule_ids_json,temporal_json,endpoint_schema_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("AN-BFLA-FAMILY", alert_id, "example.com", "RUN-BFLA-FAMILY", "new_url", 50, 50, 80,
             "test", "review", "test", "administration", "[]", "[]", 0.0, "{}", "{}", "", "[]", "{}", json.dumps(schema), now),
        )
        row = {
            "alert_id": alert_id, "target": "example.com", "endpoint_schema_json": json.dumps(schema),
            "details_json": json.dumps(details), "evidence_for_json": "[]", "evidence_against_json": "[]",
            "confidence": 80, "business_context": "administration", "category": "new_url", "item": endpoint,
        }
        count = bug_candidates._alert_candidates(self.db, "AN-BFLA-FAMILY", "RUN-BFLA-FAMILY", row)
        self.assertGreaterEqual(count, 1)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='broken_function_authorization'",
            ("AN-BFLA-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("unauthorized_function_success", support)
        self.assertIn("role_authorization_differential", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "broken_function_authorization")
        self.assertTrue(admission["family_analyzer"]["knowledge_does_not_change_target_evidence"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='broken_function_authorization'",
            ("AN-BFLA-FAMILY",),
        )
        self.assertIsNotNone(candidate)
        candidate_support = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("unauthorized_function_success", candidate_support)


if __name__ == "__main__":
    unittest.main()
