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
from family_analyzers.information_disclosure import (
    INFORMATION_DISCLOSURE_FAMILY_ANALYZER_VERSION,
    INFORMATION_DISCLOSURE_METHOD,
    analyze_information_disclosure_signal,
)
from family_analyzers.router import analyzer_for_family, router_status
from family_reasoning import confirmation_gaps


class InformationDisclosureFamilyAnalyzerV879Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-INFO-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-INFO-FAMILY','RUN-INFO-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details=None, *, endpoint="https://example.com/api/profile", semantic_text="debug response metadata"):
        return analyze_information_disclosure_signal(
            self.db,
            analysis_id="AN-INFO-FAMILY",
            target="example.com",
            endpoint=endpoint,
            method="GET",
            body_fields=[],
            query_fields=[],
            path_fields=[],
            details=dict(details or {}),
            business_context="general",
            semantic_text=semantic_text,
        )

    def _insert_alert_context(self, details: dict, *, endpoint="https://example.com/api/profile") -> int:
        schema = {
            "endpoint": endpoint,
            "method": "GET",
            "path_parameters": [],
            "query_parameters": [],
            "body_fields": [],
            "object_identifiers": [],
            "authentication_hints": [],
            "is_endpoint": True,
        }
        now = utc_now()
        cursor = self.db.execute(
            """INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "example.com", f"info-prod-{now}", "response_change", "info", 10, "debug response",
                endpoint, json.dumps(details), "new", 1, now, now, "RUN-INFO-FAMILY",
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
                "AN-INFO-FAMILY", alert_id, "example.com", "RUN-INFO-FAMILY", "response_change",
                50, 50, 88, "test", "review", "test", "general", "[]", "[]",
                0.0, "{}", "{}", "", "[]", "{}", json.dumps(schema), now,
            ),
        )
        return alert_id

    def _candidate_row_input(self, alert_id: int, details: dict, *, endpoint="https://example.com/api/profile") -> dict:
        schema = {
            "endpoint": endpoint,
            "method": "GET",
            "path_parameters": [],
            "query_parameters": [],
            "body_fields": [],
            "object_identifiers": [],
            "authentication_hints": [],
            "is_endpoint": True,
        }
        return {
            "alert_id": alert_id,
            "target": "example.com",
            "endpoint_schema_json": json.dumps(schema),
            "details_json": json.dumps(details),
            "evidence_for_json": "[]",
            "evidence_against_json": "[]",
            "confidence": 88,
            "business_context": "general",
            "category": "response_change",
            "item": endpoint,
        }

    def test_router_registers_twelve_dedicated_families_without_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered_count"], 12)
        self.assertEqual(status["pending_count"], 9)
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
            "information_disclosure",
        ])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("information_disclosure"))
        self.assertIsNone(analyzer_for_family("source_map_exposure"))

    def test_taxonomy_and_methodology_are_non_evidentiary(self):
        result = self.analyze({"debug": True})
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(INFORMATION_DISCLOSURE_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("CWE-200", meta["taxonomy"]["cwe"])
        self.assertIn("CWE-209", meta["taxonomy"]["related_cwe"])
        self.assertIn("CWE-497", meta["taxonomy"]["related_cwe"])
        self.assertIn("CWE-1295", meta["taxonomy"]["related_cwe"])
        self.assertIn("WSTG-ERRH-01", meta["taxonomy"]["wstg"])
        self.assertIn("WSTG-ERRH-02", meta["taxonomy"]["wstg"])
        self.assertIn("WSTG-INFO-05", meta["taxonomy"]["wstg"])
        basis = {item for step in INFORMATION_DISCLOSURE_METHOD for item in step["basis"]}
        self.assertIn("CWE-200", basis)
        self.assertIn("WSTG-INFO-05", basis)
        self.assertTrue(all(row["non_evidentiary"] for row in meta["knowledge_patterns"]))
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])
        self.assertFalse(meta["active_request_performed"])
        self.assertFalse(meta["private_data_retrieval_performed_by_analyzer"])
        self.assertFalse(meta["secret_validation_performed"])

    def test_structural_marker_and_storage_provenance_are_one_evidence_root(self):
        result = self.analyze({"debug": True})
        observed = {row["type"] for row in result["support"]}
        roots = {row.get("source_group") for row in result["support"]}
        self.assertIn("sensitive_marker", observed)
        self.assertIn("stored_evidence", observed)
        self.assertEqual(roots, {"information_disclosure_structural_surface"})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_version_or_banner_surface_is_not_direct_disclosure(self):
        result = self.analyze({"server_version": "example"}, semantic_text="server version framework build")
        self.assertIsNotNone(result)
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertNotIn("sensitive_response_observed", {row["type"] for row in result["support"]})

    def test_private_field_public_observation_is_direct_and_confirmation_ready(self):
        result = self.analyze({
            "debug": True,
            "information_disclosure_observations": [{
                "response_observed": True,
                "publicly_reachable": True,
                "intended_public": False,
                "private_field_observed": True,
                "private_fields": ["billing_email"],
                "sensitive_categories": ["customer_data"],
            }],
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("sensitive_response_observed", observed)
        self.assertIn("private_field_publicly_observed", observed)
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertEqual(confirmation_gaps("information_disclosure", observed), [])
        self.assertEqual(result["variant"], "private_field_public_exposure")

    def test_sensitive_error_detail_requires_real_visibility_boundary(self):
        result = self.analyze({
            "debug": True,
            "information_disclosure_observations": [{
                "response_observed": True,
                "anonymous_context": True,
                "expected_public": False,
                "sensitive_data_observed": True,
                "sensitive_categories": ["internal_path", "sql_fragment"],
            }],
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("sensitive_response_observed", observed)
        self.assertIn("error_detail_exposure_observed", observed)
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertEqual(result["variant"], "sensitive_error_detail_exposure")

    def test_intended_public_metadata_is_contradiction_not_vulnerability(self):
        result = self.analyze({
            "debug": True,
            "information_disclosure_observations": [{
                "response_observed": True,
                "publicly_reachable": True,
                "intended_public": True,
                "sensitive_categories": ["framework"],
            }],
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("intended_public_metadata", contradictions)
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_redaction_enforcement_blocks_direct_exposure(self):
        result = self.analyze({
            "debug": True,
            "information_disclosure_observations": [{
                "response_observed": True,
                "publicly_reachable": True,
                "intended_public": False,
                "private_field_observed": True,
                "private_fields": ["customer_email"],
                "redaction_enforced": True,
            }],
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("redaction_enforced", contradictions)
        self.assertFalse(result["direct"])
        self.assertNotIn("private_field_publicly_observed", {row["type"] for row in result["support"]})

    def test_authorized_owner_context_does_not_become_public_disclosure(self):
        result = self.analyze({
            "debug": True,
            "information_disclosure_observations": [{
                "response_observed": True,
                "current_actor_authorized": True,
                "intended_private": True,
                "private_field_observed": True,
                "private_fields": ["profile_email"],
            }],
        })
        self.assertFalse(result["direct"])
        self.assertIn("authorized_visibility_observed", {row["type"] for row in result["contradict"]})

    def test_secret_only_observation_prefers_specialized_family(self):
        result = self.analyze({
            "token": "marker-only",
            "information_disclosure_observations": [{
                "response_observed": True,
                "publicly_reachable": True,
                "intended_public": False,
                "sensitive_data_observed": True,
                "sensitive_categories": ["token"],
            }],
        })
        self.assertFalse(result["direct"])
        self.assertIn("secret_exposure", result["family_analyzer"]["neighbor_family_hints"])
        self.assertNotIn("sensitive_response_observed", {row["type"] for row in result["support"]})

    def test_source_map_only_observation_prefers_specialized_family(self):
        result = self.analyze({
            "sourceMappingURL": "app.js.map",
            "information_disclosure_observations": [{
                "response_observed": True,
                "publicly_reachable": True,
                "intended_public": False,
                "sensitive_data_observed": True,
                "sensitive_categories": ["source_map"],
            }],
        })
        self.assertFalse(result["direct"])
        self.assertIn("source_map_exposure", result["family_analyzer"]["neighbor_family_hints"])

    def test_raw_sensitive_value_is_never_echoed_by_analyzer(self):
        secret_value = "DO-NOT-ECHO-RAW-CUSTOMER-VALUE-879"
        result = self.analyze({
            "debug": True,
            "information_disclosure_observations": [{
                "response_observed": True,
                "publicly_reachable": True,
                "intended_public": False,
                "sensitive_data_observed": True,
                "sensitive_categories": ["internal_path"],
                "raw_value": secret_value,
            }],
        })
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret_value, serialized)
        self.assertFalse(result["family_analyzer"]["raw_sensitive_values_persisted_by_analyzer"])
        self.assertTrue(result["family_analyzer"]["minimal_evidence_only"])

    def test_candidate_engine_keeps_marker_only_disclosure_hidden(self):
        details = {"debug": True}
        alert_id = self._insert_alert_context(details)
        row = self._candidate_row_input(alert_id, details)
        bug_candidates._alert_candidates(self.db, "AN-INFO-FAMILY", "RUN-INFO-FAMILY", row)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='information_disclosure'",
            ("AN-INFO-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertFalse(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "information_disclosure")
        self.assertTrue(admission["family_analyzer"]["structural_marker_and_storage_are_one_evidence_root"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='information_disclosure'",
            ("AN-INFO-FAMILY",),
        )
        self.assertIsNone(candidate)

    def test_candidate_engine_promotes_stored_private_public_exposure(self):
        details = {
            "debug": True,
            "information_disclosure_observations": [{
                "response_observed": True,
                "publicly_reachable": True,
                "intended_public": False,
                "private_field_observed": True,
                "private_fields": ["billing_email"],
                "sensitive_categories": ["customer_data"],
            }],
        }
        alert_id = self._insert_alert_context(details)
        row = self._candidate_row_input(alert_id, details)
        bug_candidates._alert_candidates(self.db, "AN-INFO-FAMILY", "RUN-INFO-FAMILY", row)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='information_disclosure'",
            ("AN-INFO-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("sensitive_response_observed", support)
        self.assertIn("private_field_publicly_observed", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertTrue(admission["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='information_disclosure'",
            ("AN-INFO-FAMILY",),
        )
        self.assertIsNotNone(candidate)


if __name__ == "__main__":
    unittest.main()
