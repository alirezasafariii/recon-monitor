from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis, replay_analysis
from candidate_intelligence import candidate_calibration, candidate_evaluation, independent_evidence, set_gold_label
from bug_candidates import set_bug_candidate_decision
from core import AppPaths, Database, utc_now


class CandidateReliabilityV43Tests(unittest.TestCase):
    def fixture(self, td: str):
        paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('run43','4.3.0','success',?,?,?,1)",
            (now, now, "example.com"),
        )
        details = {
            "status_code": 200,
            "method": "PATCH",
            "body_fields": ["displayName", "role", "isAdmin", "tenantId", "userId"],
            "authentication": "bearer",
            "endpoint_classification": {"primary_category": "admin", "confidence": 96},
            "response_json": {"user": {"email": "redacted", "role": "admin"}, "tenantId": "t1"},
            # Candidate-reliability tests need a real admitted candidate. The
            # stored property behavior supplies target evidence rather than
            # relying on the sensitive field names alone.
            "accepted_fields": ["isAdmin"],
            "persisted_fields": ["isAdmin"],
        }
        alert_id, _, _ = db.upsert_alert(
            "example.com", "v43-alert", "new_endpoint", "HIGH", 88,
            "Tenant user administration endpoint", "/api/tenants/{tenantId}/users/{userId}", details, "run43",
        )
        blob = paths.state / "fixture.js"
        blob.write_text(
            "const enableTenantAdmin=true; fetch('/api/tenants/'+tenantId+'/users/'+userId); "
            "if (permissions.includes('admin')) { localStorage.getItem('accessToken'); }",
            encoding="utf-8",
        )
        db.execute(
            "INSERT INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,first_seen,last_seen,last_changed,last_run_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("example.com", "https://example.com/app.js", "r", "s", str(blob), blob.stat().st_size, now, now, now, "run43"),
        )
        return paths, db, alert_id

    def test_independent_evidence_suppresses_correlated_signals(self):
        selected, meta = independent_evidence([
            {"type": "admin", "source": "semantic", "weight": 10},
            {"type": "classification", "source_group": "semantic", "weight": 14},
            {"type": "http", "source": "http", "weight": 8},
        ])
        self.assertEqual(len(selected), 2)
        self.assertEqual(meta["double_counted_signals_suppressed"], 1)

    def test_schema_and_reliability_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, alert_id = self.fixture(td)
            try:
                result = run_analysis(paths, db, "run43", "example.com", profile="balanced")
                self.assertEqual(db.meta_get("schema_version"), "18")
                row = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND alert_id=? ORDER BY investigation_value DESC LIMIT 1", (result["analysis_id"], alert_id))
                self.assertIsNotNone(row)
                self.assertGreater(int(row["observation_quality"]), 0)
                self.assertGreater(int(row["investigation_value"]), 0)
                self.assertEqual(row["analysis_profile"], "balanced")
                self.assertTrue(json.loads(row["evidence_groups_json"]))
                self.assertTrue(json.loads(row["quality_explanation_json"]))
            finally:
                db.close()

    def test_semantic_contracts_flags_relationships_and_shapes(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _ = self.fixture(td)
            try:
                result = run_analysis(paths, db, "run43", "example.com")
                aid = result["analysis_id"]
                self.assertGreater(db.one("SELECT COUNT(*) count FROM endpoint_contracts WHERE analysis_id=?", (aid,))["count"], 0)
                self.assertGreater(db.one("SELECT COUNT(*) count FROM authentication_boundaries WHERE analysis_id=?", (aid,))["count"], 0)
                self.assertGreater(db.one("SELECT COUNT(*) count FROM response_shape_fingerprints WHERE analysis_id=?", (aid,))["count"], 0)
                self.assertGreater(db.one("SELECT COUNT(*) count FROM parameter_relationships WHERE analysis_id=?", (aid,))["count"], 0)
                self.assertGreater(db.one("SELECT COUNT(*) count FROM semantic_js_units WHERE analysis_id=?", (aid,))["count"], 0)
                self.assertGreater(db.one("SELECT COUNT(*) count FROM feature_flags WHERE analysis_id=?", (aid,))["count"], 0)
            finally:
                db.close()

    def test_lifecycle_feedback_and_calibration(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _ = self.fixture(td)
            try:
                first = run_analysis(paths, db, "run43", "example.com")
                candidate = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? ORDER BY investigation_value DESC LIMIT 1", (first["analysis_id"],))
                set_bug_candidate_decision(db, candidate["candidate_id"], "confirmed_by_analyst", "Authorized confirmation", actor="test", reason_code="authorization_difference")
                second = replay_analysis(paths, db, "run43", "example.com")
                replayed = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND candidate_fingerprint=?", (second["analysis_id"], candidate["candidate_fingerprint"]))
                self.assertEqual(replayed["analyst_decision"], "confirmed_by_analyst")
                self.assertGreaterEqual(int(replayed["seen_count"]), 2)
                self.assertIn(replayed["lifecycle_state"], {"tracked", "persistent", "recurring"})
                feedback = db.one("SELECT * FROM candidate_feedback WHERE candidate_id=?", (candidate["candidate_id"],))
                self.assertEqual(feedback["reason_code"], "authorization_difference")
                report = candidate_calibration(db, "example.com")
                self.assertIn(str(candidate["bug_family"]), report["families"])
            finally:
                db.close()

    def test_evaluation_and_gold_label(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _ = self.fixture(td)
            try:
                result = run_analysis(paths, db, "run43", "example.com", profile="quiet")
                evaluation = candidate_evaluation(db, result["analysis_id"], profile="quiet")
                self.assertEqual(evaluation["profile"], "quiet")
                candidate = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? LIMIT 1", (result["analysis_id"],))
                label = set_gold_label(db, candidate["candidate_id"], "useful_candidate", candidate["bug_family"], "gold fixture")
                self.assertEqual(label["label"], "useful_candidate")
                self.assertEqual(db.one("SELECT COUNT(*) count FROM candidate_gold_labels")["count"], 1)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
