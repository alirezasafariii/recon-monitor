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
from family_analyzers.path_traversal import (
    PATH_TRAVERSAL_FAMILY_ANALYZER_VERSION,
    PATH_TRAVERSAL_METHOD,
    analyze_path_traversal_signal,
)
from family_analyzers.router import analyzer_for_family, router_status
from family_reasoning import confirmation_gaps


class PathTraversalFamilyAnalyzerV878Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-PATH-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-PATH-FAMILY','RUN-PATH-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details=None, *, endpoint="https://example.com/api/download", method="GET", body_fields=None, query_fields=None, path_fields=None, semantic_text="download file"):
        return analyze_path_traversal_signal(
            self.db,
            analysis_id="AN-PATH-FAMILY",
            target="example.com",
            endpoint=endpoint,
            method=method,
            body_fields=list([] if body_fields is None else body_fields),
            query_fields=list(["path"] if query_fields is None else query_fields),
            path_fields=list([] if path_fields is None else path_fields),
            details=dict(details or {}),
            business_context="general",
            semantic_text=semantic_text,
        )

    def _insert_alert_context(self, details: dict, *, endpoint="https://example.com/api/download") -> int:
        schema = {
            "endpoint": endpoint,
            "method": "GET",
            "path_parameters": [],
            "query_parameters": ["path"],
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
                "example.com", f"path-prod-{now}", "new_url", "info", 10, "download endpoint",
                endpoint, json.dumps(details), "new", 1, now, now, "RUN-PATH-FAMILY",
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
                "AN-PATH-FAMILY", alert_id, "example.com", "RUN-PATH-FAMILY", "new_url",
                50, 50, 88, "test", "review", "test", "general", "[]", "[]",
                0.0, "{}", "{}", "", "[]", "{}", json.dumps(schema), now,
            ),
        )
        return alert_id

    def _candidate_row_input(self, alert_id: int, details: dict, *, endpoint="https://example.com/api/download") -> dict:
        schema = {
            "endpoint": endpoint,
            "method": "GET",
            "path_parameters": [],
            "query_parameters": ["path"],
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
            "category": "new_url",
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
        self.assertIsNotNone(analyzer_for_family("path_traversal"))
        self.assertIsNotNone(analyzer_for_family("information_disclosure"))
        self.assertIsNone(analyzer_for_family("source_map_exposure"))

    def test_methodology_grounding_is_non_evidentiary(self):
        result = self.analyze()
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(PATH_TRAVERSAL_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("CWE-22", meta["taxonomy"]["cwe"])
        self.assertIn("CWE-23", meta["taxonomy"]["related_cwe"])
        self.assertIn("CWE-36", meta["taxonomy"]["related_cwe"])
        self.assertIn("WSTG-ATHZ-01", meta["taxonomy"]["wstg"])
        basis = {item for step in PATH_TRAVERSAL_METHOD for item in step["basis"]}
        self.assertIn("CWE-22", basis)
        self.assertIn("WSTG-ATHZ-01", basis)
        self.assertTrue(all(row["non_evidentiary"] for row in meta["writeup_patterns"]))
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])
        self.assertFalse(meta["active_request_performed"])
        self.assertFalse(meta["filesystem_read_performed_by_analyzer"])
        self.assertFalse(meta["filesystem_write_performed_by_analyzer"])
        self.assertFalse(meta["traversal_payload_generated"])

    def test_structural_path_and_file_operation_are_one_evidence_root(self):
        result = self.analyze()
        observed = {row["type"] for row in result["support"]}
        roots = {row.get("source_group") for row in result["support"]}
        self.assertIn("path_parameter", observed)
        self.assertIn("download_operation", observed)
        self.assertIn("file_operation", observed)
        self.assertEqual(roots, {"path_traversal_structural_surface"})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_controlled_non_sensitive_path_escape_promotes_but_does_not_confirm(self):
        result = self.analyze({
            "path_traversal_observations": [{
                "controlled_test_path": True,
                "non_sensitive_test_resource": True,
                "expected_reject": True,
                "filesystem_operation_observed": True,
                "resolved_outside_base": True,
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("path_escape_observed", observed)
        self.assertIn("path_boundary_differential", observed)
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])
        self.assertTrue(confirmation_gaps("path_traversal", {"path_escape_observed"}))
        self.assertEqual(result["variant"], "controlled_path_escape")

    def test_uncontrolled_or_sensitive_resource_never_becomes_direct(self):
        uncontrolled = self.analyze({
            "path_traversal_observations": [{
                "controlled_test_path": False,
                "non_sensitive_test_resource": True,
                "expected_reject": True,
                "filesystem_operation_observed": True,
                "resolved_outside_base": True,
            }]
        })
        self.assertNotIn("path_escape_observed", {row["type"] for row in uncontrolled["support"]})
        self.assertFalse(uncontrolled["direct"])

        sensitive = self.analyze({
            "path_traversal_observations": [{
                "controlled_test_path": True,
                "non_sensitive_test_resource": False,
                "expected_reject": True,
                "filesystem_operation_observed": True,
                "resolved_outside_base": True,
            }]
        })
        self.assertNotIn("path_escape_observed", {row["type"] for row in sensitive["support"]})
        self.assertFalse(sensitive["direct"])

    def test_canonicalization_and_base_enforcement_are_contradictions(self):
        result = self.analyze({
            "path_traversal_observations": [{
                "controlled_test_path": True,
                "non_sensitive_test_resource": True,
                "expected_reject": True,
                "path_rejected": True,
                "canonicalization_enforced": True,
                "base_directory_enforced": True,
            }]
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("canonicalization_enforced", contradictions)
        self.assertIn("base_directory_enforced", contradictions)
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])

    def test_canonicalization_bypass_is_stricter_confirmation_condition(self):
        result = self.analyze({
            "path_traversal_observations": [{
                "controlled_test_path": True,
                "non_sensitive_test_resource": True,
                "expected_reject": True,
                "filesystem_operation_observed": True,
                "resolved_outside_base": True,
                "canonicalization_bypass_observed": True,
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("path_escape_observed", observed)
        self.assertIn("canonicalization_bypass_observed", observed)
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertEqual(result["variant"], "canonicalization_boundary_bypass")

    def test_test_owned_out_of_root_access_is_confirmation_ready(self):
        result = self.analyze({
            "path_traversal_observations": [{
                "controlled_test_path": True,
                "non_sensitive_test_resource": True,
                "expected_reject": True,
                "filesystem_operation_observed": True,
                "resolved_outside_base": True,
                "out_of_root_file_access_observed": True,
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("out_of_root_file_access_observed", observed)
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertEqual(result["variant"], "out_of_root_access")
        self.assertEqual(confirmation_gaps("path_traversal", observed), [])

    def test_confirmation_signal_cannot_hitchhike_from_uncontrolled_second_observation(self):
        result = self.analyze({
            "path_traversal_observations": [
                {
                    "controlled_test_path": True,
                    "non_sensitive_test_resource": True,
                    "expected_reject": True,
                    "filesystem_operation_observed": True,
                    "resolved_outside_base": True,
                },
                {
                    "controlled_test_path": False,
                    "non_sensitive_test_resource": True,
                    "expected_reject": True,
                    "filesystem_operation_observed": True,
                    "resolved_outside_base": True,
                    "out_of_root_file_access_observed": True,
                },
            ]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("path_escape_observed", observed)
        self.assertNotIn("out_of_root_file_access_observed", observed)
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_candidate_engine_keeps_structural_path_surface_hidden(self):
        details: dict = {}
        alert_id = self._insert_alert_context(details)
        row = self._candidate_row_input(alert_id, details)
        bug_candidates._alert_candidates(self.db, "AN-PATH-FAMILY", "RUN-PATH-FAMILY", row)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='path_traversal'",
            ("AN-PATH-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertFalse(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "path_traversal")
        self.assertTrue(admission["family_analyzer"]["structural_path_and_operation_are_one_evidence_root"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='path_traversal'",
            ("AN-PATH-FAMILY",),
        )
        self.assertIsNone(candidate)

    def test_candidate_engine_promotes_after_stored_controlled_path_escape(self):
        details = {
            "path_traversal_observations": [{
                "controlled_test_path": True,
                "non_sensitive_test_resource": True,
                "expected_reject": True,
                "filesystem_operation_observed": True,
                "resolved_outside_base": True,
            }]
        }
        alert_id = self._insert_alert_context(details)
        row = self._candidate_row_input(alert_id, details)
        bug_candidates._alert_candidates(self.db, "AN-PATH-FAMILY", "RUN-PATH-FAMILY", row)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='path_traversal'",
            ("AN-PATH-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("path_escape_observed", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertTrue(admission["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(admission["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='path_traversal'",
            ("AN-PATH-FAMILY",),
        )
        self.assertIsNotNone(candidate)
        candidate_support = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("path_escape_observed", candidate_support)

    def test_upload_filename_surface_does_not_claim_path_escape(self):
        result = self.analyze(
            {}, endpoint="https://example.com/api/upload", method="POST",
            body_fields=["filename"], query_fields=[], semantic_text="upload file",
        )
        observed = {row["type"] for row in result["support"]}
        self.assertIn("filename_field", observed)
        self.assertIn("upload_operation", observed)
        self.assertNotIn("path_escape_observed", observed)
        self.assertFalse(result["direct"])


if __name__ == "__main__":
    unittest.main()
