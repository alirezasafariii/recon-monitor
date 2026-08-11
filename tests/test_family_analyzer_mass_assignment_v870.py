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
from family_analyzers.mass_assignment import (
    MASS_ASSIGNMENT_FAMILY_ANALYZER_VERSION,
    MASS_ASSIGNMENT_METHOD,
    analyze_mass_assignment_signal,
)
from family_analyzers.router import analyzer_for_family, router_status


class MassAssignmentFamilyAnalyzerV870Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-MA-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-MA-FAMILY','RUN-MA-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details, *, body_fields=None, method="PATCH", endpoint="https://example.com/api/profile"):
        return analyze_mass_assignment_signal(
            self.db,
            analysis_id="AN-MA-FAMILY",
            target="example.com",
            endpoint=endpoint,
            method=method,
            body_fields=list(body_fields or ["displayName", "is_admin"]),
            details=details,
            business_context="identity",
        )

    def test_router_registers_eight_dedicated_families_without_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered_count"], 8)
        self.assertEqual(status["pending_count"], 13)
        self.assertEqual(status["registered"], [
            "broken_object_authorization",
            "broken_function_authorization",
            "mass_assignment",
            "authentication_session",
            "account_enumeration",
            "dom_xss",
            "postmessage_trust",
            "open_redirect",
        ])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("mass_assignment"))
        self.assertIsNotNone(analyzer_for_family("authentication_session"))
        self.assertIsNotNone(analyzer_for_family("account_enumeration"))
        self.assertIsNotNone(analyzer_for_family("dom_xss"))
        self.assertIsNotNone(analyzer_for_family("postmessage_trust"))
        self.assertIsNotNone(analyzer_for_family("open_redirect"))
        self.assertIsNone(analyzer_for_family("ssrf"))

    def test_methodology_grounding_is_non_evidentiary(self):
        result = self.analyze({})
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(MASS_ASSIGNMENT_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("CWE-915", meta["taxonomy"]["cwe"])
        self.assertIn("WSTG-INPV-20", meta["taxonomy"]["wstg"])
        basis = {item for step in MASS_ASSIGNMENT_METHOD for item in step["basis"]}
        self.assertIn("CWE-915", basis)
        self.assertIn("OWASP API3:2023", basis)
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])
        self.assertFalse(meta["confirmation_ready_from_stored_target_evidence"])

    def test_sensitive_write_surface_alone_is_not_confirmation(self):
        result = self.analyze({})
        observed = {row["type"] for row in result["support"]}
        self.assertIn("privileged_property", observed)
        self.assertIn("write_method", observed)
        self.assertFalse(result["direct"])
        self.assertEqual(result["variant"], "privileged_properties")
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])

    def test_persisted_protected_property_is_direct_confirmation_evidence(self):
        result = self.analyze({
            "property_observations": [
                {
                    "field": "is_admin",
                    "expected_writable": False,
                    "accepted": True,
                    "before": False,
                    "after": True,
                    "status_code": 200,
                }
            ]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("protected_property_accepted", observed)
        self.assertIn("protected_property_mutated", observed)
        self.assertIn("property_authorization_differential", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "protected_property_mutation")
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        refs = {row["id"] for row in result["family_analyzer"]["writeup_patterns"]}
        self.assertIn("ghsl-wekan-2026-044", refs)
        self.assertTrue(all(row["non_evidentiary"] for row in result["family_analyzer"]["writeup_patterns"]))

    def test_rejected_ignored_and_allowlisted_properties_are_false_positive_controls(self):
        result = self.analyze({
            "rejected_fields": ["is_admin"],
            "ignored_fields": ["is_admin"],
            "writable_fields": ["displayName"],
            "server_allowlist_enforced": True,
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("protected_property_rejected", contradictions)
        self.assertIn("sensitive_property_ignored", contradictions)
        self.assertIn("server_allowlist_observed", contradictions)
        triggered = {row["signal"] for row in result["family_analyzer"]["triggered_false_positive_checks"]}
        self.assertTrue({"protected_property_rejected", "sensitive_property_ignored", "server_allowlist_observed"} <= triggered)
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_read_only_sensitive_field_does_not_emit_mass_assignment(self):
        self.assertIsNone(self.analyze({}, method="GET"))

    def test_candidate_engine_routes_mass_assignment_before_admission(self):
        endpoint = "https://example.com/api/profile"
        details = {
            "property_observations": [
                {
                    "field": "is_admin",
                    "expected_writable": False,
                    "accepted": True,
                    "persisted": True,
                    "status_code": 200,
                }
            ]
        }
        schema = {
            "endpoint": endpoint,
            "method": "PATCH",
            "path_parameters": [],
            "query_parameters": [],
            "body_fields": ["displayName", "is_admin"],
            "object_identifiers": ["userId"],
            "authentication_hints": ["bearer"],
            "is_endpoint": True,
        }
        now = utc_now()
        cursor = self.db.execute(
            """INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("example.com", "ma-prod-1", "new_url", "info", 10, "test", endpoint, json.dumps(details), "new", 1, now, now, "RUN-MA-FAMILY"),
        )
        alert_id = int(cursor.lastrowid)
        self.db.execute(
            """INSERT INTO analysis_results(
            analysis_id,alert_id,target,source_run_id,category,original_score,adjusted_score,confidence,
            hypothesis,next_action,playbook_id,business_context,evidence_for_json,evidence_against_json,
            anomaly_score,baseline_json,feedback_json,duplicate_cluster,rule_ids_json,temporal_json,endpoint_schema_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "AN-MA-FAMILY", alert_id, "example.com", "RUN-MA-FAMILY", "new_url", 50, 50, 80,
                "test", "review", "test", "identity", "[]", "[]", 0.0, "{}", "{}", "", "[]", "{}", json.dumps(schema), now,
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
        count = bug_candidates._alert_candidates(self.db, "AN-MA-FAMILY", "RUN-MA-FAMILY", row)
        self.assertGreaterEqual(count, 1)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='mass_assignment'",
            ("AN-MA-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("protected_property_mutated", support)
        self.assertIn("property_authorization_differential", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "mass_assignment")
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='mass_assignment'",
            ("AN-MA-FAMILY",),
        )
        self.assertIsNotNone(candidate)


if __name__ == "__main__":
    unittest.main()
