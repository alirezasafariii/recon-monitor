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
from family_analyzers.file_upload import (
    FILE_UPLOAD_FAMILY_ANALYZER_VERSION,
    FILE_UPLOAD_METHOD,
    analyze_file_upload_signal,
)
from family_analyzers.router import analyzer_for_family, router_status


class FileUploadFamilyAnalyzerV877Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-FILE-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-FILE-FAMILY','RUN-FILE-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details=None, *, endpoint="https://example.com/api/upload", method="POST", body_fields=None, query_fields=None, semantic_text="file upload"):
        return analyze_file_upload_signal(
            self.db,
            analysis_id="AN-FILE-FAMILY",
            target="example.com",
            endpoint=endpoint,
            method=method,
            body_fields=list(["file"] if body_fields is None else body_fields),
            query_fields=list([] if query_fields is None else query_fields),
            details=dict(details or {}),
            business_context="general",
            semantic_text=semantic_text,
        )

    def _insert_alert_context(self, details: dict, *, endpoint="https://example.com/api/upload") -> int:
        schema = {
            "endpoint": endpoint,
            "method": "POST",
            "path_parameters": [],
            "query_parameters": [],
            "body_fields": ["file"],
            "object_identifiers": [],
            "authentication_hints": [],
            "is_endpoint": True,
        }
        now = utc_now()
        cursor = self.db.execute(
            """INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "example.com", f"file-prod-{now}", "new_url", "info", 10, "upload endpoint",
                endpoint, json.dumps(details), "new", 1, now, now, "RUN-FILE-FAMILY",
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
                "AN-FILE-FAMILY", alert_id, "example.com", "RUN-FILE-FAMILY", "new_url",
                50, 50, 88, "test", "review", "test", "general", "[]", "[]",
                0.0, "{}", "{}", "", "[]", "{}", json.dumps(schema), now,
            ),
        )
        return alert_id

    def _candidate_row_input(self, alert_id: int, details: dict, *, endpoint="https://example.com/api/upload") -> dict:
        schema = {
            "endpoint": endpoint,
            "method": "POST",
            "path_parameters": [],
            "query_parameters": [],
            "body_fields": ["file"],
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
        self.assertIsNotNone(analyzer_for_family("file_upload"))
        self.assertIsNotNone(analyzer_for_family("path_traversal"))
        self.assertIsNone(analyzer_for_family("information_disclosure"))

    def test_methodology_grounding_is_non_evidentiary(self):
        result = self.analyze()
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(FILE_UPLOAD_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("CWE-434", meta["taxonomy"]["cwe"])
        self.assertIn("WSTG-BUSL-08", meta["taxonomy"]["wstg"])
        self.assertIn("WSTG-BUSL-09", meta["taxonomy"]["wstg"])
        basis = {item for step in FILE_UPLOAD_METHOD for item in step["basis"]}
        self.assertIn("CWE-434", basis)
        self.assertIn("WSTG-BUSL-08", basis)
        self.assertIn("WSTG-BUSL-09", basis)
        self.assertTrue(all(row["non_evidentiary"] for row in meta["writeup_patterns"]))
        observed = {row["type"] for row in result["support"]}
        self.assertNotIn("cwe-434-dangerous-file-type", observed)
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])
        self.assertFalse(meta["active_upload_performed"])
        self.assertFalse(meta["payload_execution_performed"])
        self.assertFalse(meta["malware_or_weaponized_file_used"])

    def test_structural_file_input_and_operation_are_one_evidence_root(self):
        result = self.analyze()
        observed = {row["type"] for row in result["support"]}
        roots = {row.get("source_group") for row in result["support"]}
        self.assertIn("file_input", observed)
        self.assertIn("upload_operation", observed)
        self.assertEqual(roots, {"file_upload_structural_surface"})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_expected_allowed_file_acceptance_is_not_direct_evidence(self):
        result = self.analyze({
            "file_upload_observations": [{
                "controlled_test_file": True,
                "inert_test_file": True,
                "expected_reject": False,
                "upload_accepted": True,
                "file_persisted": True,
                "filename": "avatar.png",
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertNotIn("unsafe_file_accepted", observed)
        self.assertNotIn("file_policy_differential", observed)
        self.assertFalse(result["direct"])

    def test_controlled_inert_policy_disallowed_file_acceptance_promotes_but_does_not_confirm(self):
        result = self.analyze({
            "file_upload_observations": [{
                "controlled_test_file": True,
                "inert_test_file": True,
                "expected_reject": True,
                "upload_accepted": True,
                "file_persisted": True,
                "filename": "marker.unexpected",
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("unsafe_file_accepted", observed)
        self.assertIn("file_policy_differential", observed)
        self.assertIn("unsafe_file_persisted", observed)
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])
        self.assertEqual(result["variant"], "policy_disallowed_file_persisted")

    def test_uncontrolled_or_non_inert_file_never_becomes_direct_evidence(self):
        uncontrolled = self.analyze({
            "file_upload_observations": [{
                "controlled_test_file": False,
                "inert_test_file": True,
                "expected_reject": True,
                "upload_accepted": True,
            }]
        })
        self.assertNotIn("unsafe_file_accepted", {row["type"] for row in uncontrolled["support"]})
        self.assertFalse(uncontrolled["direct"])

        non_inert = self.analyze({
            "file_upload_observations": [{
                "controlled_test_file": True,
                "inert_test_file": False,
                "expected_reject": True,
                "upload_accepted": True,
            }]
        })
        self.assertNotIn("unsafe_file_accepted", {row["type"] for row in non_inert["support"]})
        self.assertFalse(non_inert["direct"])

    def test_file_type_enforcement_and_safe_storage_are_false_positive_controls(self):
        result = self.analyze({
            "file_upload_observations": [{
                "controlled_test_file": True,
                "inert_test_file": True,
                "expected_reject": True,
                "upload_rejected": True,
                "extension_allowlist_enforced": True,
                "signature_validation_enforced": True,
                "safe_storage_observed": True,
                "server_generated_filename": True,
            }]
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("file_type_enforcement_observed", contradictions)
        self.assertIn("safe_storage_observed", contradictions)
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])

    def test_content_type_policy_bypass_is_stricter_confirmation_condition(self):
        result = self.analyze({
            "file_upload_observations": [{
                "controlled_test_file": True,
                "inert_test_file": True,
                "expected_reject": True,
                "upload_accepted": True,
                "file_persisted": True,
                "content_type_bypass_observed": True,
                "declared_content_type": "image/png",
                "detected_content_type": "text/plain",
                "filename": "marker.png",
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("unsafe_file_accepted", observed)
        self.assertIn("content_type_bypass_observed", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "file_type_validation_bypass")
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_execution_capable_observation_is_read_only_confirmation_context(self):
        result = self.analyze({
            "file_upload_observations": [{
                "controlled_test_file": True,
                "inert_test_file": True,
                "expected_reject": True,
                "upload_accepted": True,
                "executable_upload_observed": True,
                "filename": "marker.safe",
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("executable_upload_observed", observed)
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertEqual(result["variant"], "execution_capable_upload_boundary")
        self.assertFalse(result["family_analyzer"]["active_upload_performed"])
        self.assertFalse(result["family_analyzer"]["payload_execution_performed"])

    def test_candidate_engine_keeps_structural_file_upload_as_hidden_hypothesis(self):
        details: dict = {}
        alert_id = self._insert_alert_context(details)
        row = self._candidate_row_input(alert_id, details)
        bug_candidates._alert_candidates(self.db, "AN-FILE-FAMILY", "RUN-FILE-FAMILY", row)

        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='file_upload'",
            ("AN-FILE-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertFalse(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "file_upload")
        self.assertTrue(admission["family_analyzer"]["structural_file_input_and_operation_are_one_evidence_root"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='file_upload'",
            ("AN-FILE-FAMILY",),
        )
        self.assertIsNone(candidate)

    def test_candidate_engine_promotes_after_controlled_inert_policy_differential(self):
        details = {
            "file_upload_observations": [{
                "controlled_test_file": True,
                "inert_test_file": True,
                "expected_reject": True,
                "upload_accepted": True,
                "file_persisted": True,
                "filename": "marker.unexpected",
            }]
        }
        alert_id = self._insert_alert_context(details)
        row = self._candidate_row_input(alert_id, details)
        bug_candidates._alert_candidates(self.db, "AN-FILE-FAMILY", "RUN-FILE-FAMILY", row)

        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='file_upload'",
            ("AN-FILE-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("unsafe_file_accepted", support)
        self.assertIn("file_policy_differential", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "file_upload")
        self.assertTrue(admission["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(admission["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='file_upload'",
            ("AN-FILE-FAMILY",),
        )
        self.assertIsNotNone(candidate)
        candidate_support = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("unsafe_file_accepted", candidate_support)

    def test_import_operation_uses_same_family_without_claiming_path_traversal(self):
        result = self.analyze(
            {},
            endpoint="https://example.com/api/import",
            method="POST",
            body_fields=["file"],
            semantic_text="bulk import file",
        )
        observed = {row["type"] for row in result["support"]}
        self.assertIn("file_input", observed)
        self.assertIn("import_operation", observed)
        self.assertNotIn("path_escape_observed", observed)
        self.assertFalse(result["direct"])


if __name__ == "__main__":
    unittest.main()
