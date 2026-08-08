from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from bug_candidates import _alert_candidates
from core import Database, utc_now
from hypothesis_admission import assess_admission, hypothesis_summary, record_hypothesis


class RecallPreservingAdmissionV843Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        self.analysis_id = "analysis-admission-test"
        self.run_id = "run-admission-test"
        self.alert_seq = 0
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_count) VALUES(?,?,?,?,?,?)",
            (self.run_id, "8.4.3", "success", now, now, 1),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.analysis_id, self.run_id, "x.test", "test", "test", "analysis", "success", now, now, "{}"),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def row(self, endpoint: str, *, method: str = "GET", body=None, query=None, path=None, details=None, category="new_url"):
        self.alert_seq += 1
        schema = {
            "endpoint": endpoint,
            "method": method,
            "path": "/",
            "path_parameters": path or [],
            "query_parameters": query or [],
            "body_fields": body or [],
            "object_identifiers": [],
            "content_type": "",
            "authentication_hints": [],
            "is_endpoint": True,
            "observation_kind": "endpoint",
        }
        now = utc_now()
        cursor = self.db.execute(
            """INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("x.test", f"test-alert-{self.alert_seq}", category, "info", 10, "test", endpoint, json.dumps(details or {}), "new", 1, now, now, self.run_id),
        )
        return {
            "alert_id": int(cursor.lastrowid),
            "target": "x.test",
            "endpoint_schema_json": json.dumps(schema),
            "details_json": json.dumps(details or {}),
            "evidence_for_json": "[]",
            "evidence_against_json": "[]",
            "confidence": 65,
            "business_context": "general",
            "category": category,
            "item": endpoint,
        }

    def test_generic_content_type_is_hidden_not_candidate(self):
        row = self.row("https://x.test/api/profile", details={"content_type": "application/json"})
        created = _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        self.assertEqual(created, 0)
        self.assertEqual(self.db.one("SELECT COUNT(*) c FROM bug_candidates")["c"], 0)
        hidden = self.db.one("SELECT * FROM analysis_hypotheses WHERE bug_family='file_upload'")
        self.assertIsNotNone(hidden)
        self.assertIn(hidden["state"], {"shadow_signal", "shadow_partial"})
        admission = json.loads(hidden["admission_json"])
        self.assertFalse(admission["admitted"])

    def test_real_structured_upload_is_promoted(self):
        row = self.row("https://x.test/api/upload", method="POST", body=["file"])
        created = _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        self.assertGreaterEqual(created, 1)
        candidate = self.db.one("SELECT * FROM bug_candidates WHERE bug_family='file_upload'")
        self.assertIsNotNone(candidate)
        hypothesis = self.db.one("SELECT * FROM analysis_hypotheses WHERE bug_family='file_upload'")
        self.assertEqual(hypothesis["state"], "promoted")
        self.assertEqual(hypothesis["promoted_candidate_id"], candidate["candidate_id"])
        types = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("file_input", types)
        self.assertIn("upload_operation", types)

    def test_generic_path_word_is_retained_but_not_promoted(self):
        row = self.row("https://x.test/api/profile", details={"metadata": {"path": "client-side label"}})
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        self.assertIsNone(self.db.one("SELECT * FROM bug_candidates WHERE bug_family='path_traversal'"))
        hypothesis = self.db.one("SELECT * FROM analysis_hypotheses WHERE bug_family='path_traversal'")
        self.assertIsNotNone(hypothesis)
        self.assertNotEqual(hypothesis["state"], "promoted")
        self.assertGreaterEqual(hypothesis["seen_count"], 1)

    def test_structured_filename_and_download_operation_promotes_traversal(self):
        row = self.row("https://x.test/api/download", method="GET", query=["filename"])
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        candidate = self.db.one("SELECT * FROM bug_candidates WHERE bug_family='path_traversal'")
        self.assertIsNotNone(candidate)
        types = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("filename_field", types)
        self.assertIn("download_operation", types)

    def test_complementary_evidence_merges_before_promotion(self):
        first = record_hypothesis(
            self.db, analysis_id=self.analysis_id, source_run_id=self.run_id, target="x.test", alert_id=None,
            asset="x.test", endpoint="https://x.test/api/import", source_ref="first", family="file_upload",
            variant="file_validation", support=[{"type": "file_input", "source": "schema", "text": "file field"}],
            contradict=[], missing=[], rule_ids=["first"], summary="test",
        )
        self.assertFalse(first["assessment"]["admitted"])
        second = record_hypothesis(
            self.db, analysis_id=self.analysis_id, source_run_id=self.run_id, target="x.test", alert_id=None,
            asset="x.test", endpoint="https://x.test/api/import", source_ref="second", family="file_upload",
            variant="file_validation", support=[{"type": "import_operation", "source": "endpoint", "text": "import operation"}],
            contradict=[], missing=[], rule_ids=["second"], summary="test",
        )
        self.assertTrue(second["assessment"]["admitted"])
        self.assertEqual(second["seen_count"], 2)
        self.assertEqual({item["type"] for item in second["support"]}, {"file_input", "import_operation"})

    def test_knowledge_is_context_not_target_evidence(self):
        row = self.row("https://x.test/api/upload", method="POST", body=["file"])
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        hypothesis = self.db.one("SELECT * FROM analysis_hypotheses WHERE bug_family='file_upload'")
        refs = json.loads(hypothesis["knowledge_references_json"])
        self.assertGreaterEqual(len(refs), 2)
        support_text = json.dumps(json.loads(hypothesis["supporting_evidence_json"]))
        self.assertNotIn("OWASP", support_text)
        self.assertNotIn("MITRE", support_text)
        self.assertNotIn("PortSwigger", support_text)

    def test_hypothesis_summary_preserves_hidden_recall(self):
        record_hypothesis(
            self.db, analysis_id=self.analysis_id, source_run_id=self.run_id, target="x.test", alert_id=None,
            asset="x.test", endpoint="https://x.test/weak", source_ref="weak", family="path_traversal",
            variant="path_construction", support=[{"type": "path_surface", "source": "semantic", "text": "path clue"}],
            contradict=[], missing=[], rule_ids=["weak"], summary="weak clue",
        )
        summary = hypothesis_summary(self.db, self.analysis_id)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["hidden"], 1)
        self.assertEqual(summary["promoted"], 0)

    def test_admission_requires_decisive_signals_not_generic_metadata(self):
        result = assess_admission("file_upload", [
            {"type": "file_surface", "source": "semantic"},
            {"type": "content_type_field", "source": "http_contract"},
        ])
        self.assertFalse(result["admitted"])
        self.assertEqual(result["decisive_signals"], [])


if __name__ == "__main__":
    unittest.main()
