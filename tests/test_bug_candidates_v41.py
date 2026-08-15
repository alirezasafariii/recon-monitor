from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import replay_analysis, run_analysis
from bug_candidates import generate_bug_candidates, set_bug_candidate_decision
from core import AppPaths, Database, utc_now


class BugCandidateV41Tests(unittest.TestCase):
    def make_db(self, td: str):
        paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('run-candidate','4.1.0','success',?,?,?,1)",
            (now, now, 'example.com'),
        )
        details = {
            "status_code": 200,
            "identity_id": "fixture-user-a",
            "object_owner_id": "fixture-user-b",
            "method": "PATCH",
            "body_fields": ["displayName", "role", "isAdmin", "accountId"],
            "endpoint_classification": {"primary_category": "admin", "confidence": 95},
            "authentication": "bearer",
        }
        alert_id, _, _ = db.upsert_alert(
            'example.com', 'candidate-alert', 'new_endpoint', 'HIGH', 82,
            'Admin account update endpoint', '/api/admin/accounts/{accountId}', details, 'run-candidate'
        )
        return paths, db, alert_id

    def test_schema_and_alert_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, alert_id = self.make_db(td)
            try:
                result = run_analysis(paths, db, 'run-candidate', 'example.com')
                self.assertEqual(db.meta_get('schema_version'), '18')
                rows = db.all("SELECT * FROM bug_candidates WHERE analysis_id=? AND alert_id=?", (result['analysis_id'], alert_id))
                families = {str(row['bug_family']) for row in rows}
                self.assertIn('broken_object_authorization', families)
                self.assertNotIn('broken_function_authorization', families)
                self.assertIn('mass_assignment', families)

                # An administrative route plus state-changing method is only a
                # BFLA surface. Without stored role/permission-boundary evidence
                # it must remain a hidden hypothesis rather than Potential Finding.
                bfla_hypothesis = db.one(
                    "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='broken_function_authorization'",
                    (result['analysis_id'],),
                )
                self.assertIsNotNone(bfla_hypothesis)
                bfla_admission = json.loads(bfla_hypothesis['admission_json'])
                self.assertFalse(bfla_admission['admitted'])
                self.assertTrue(bfla_admission['required_missing'])

                bola = next(row for row in rows if row['bug_family'] == 'broken_object_authorization')
                self.assertLessEqual(int(bola['likelihood_score']), 100)
                self.assertIn(str(bola['candidate_state']), {'possible', 'plausible', 'strong_candidate'})
                self.assertNotEqual(str(bola['candidate_state']), 'confirmed_by_analyst')
                self.assertTrue(json.loads(bola['missing_evidence_json']))
            finally:
                db.close()

    def test_static_dom_dataflow_is_retained_as_hypothesis_not_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _ = self.make_db(td)
            try:
                result = run_analysis(paths, db, 'run-candidate', 'example.com')
                db.execute(
                    "INSERT INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (result['analysis_id'], 'example.com', 'run-candidate', 'https://example.com/app.js', 'location.search', 'innerHTML', 78, 'value -> innerHTML', utc_now()),
                )
                summary = generate_bug_candidates(db, result['analysis_id'], 'run-candidate', 'example.com')
                self.assertEqual(summary['from_static_intelligence'], 0)
                candidate = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='dom_xss'", (result['analysis_id'],))
                self.assertIsNone(candidate)
                hypothesis = db.one("SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='dom_xss'", (result['analysis_id'],))
                self.assertIsNotNone(hypothesis)
                self.assertIn('runtime', str(hypothesis['missing_evidence_json']).lower())
                admission = json.loads(hypothesis['admission_json'])
                self.assertFalse(admission['admitted'])
                self.assertEqual(admission['family_analyzer']['family'], 'dom_xss')
            finally:
                db.close()

    def test_analyst_decision_is_carried_to_replay(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _ = self.make_db(td)
            try:
                first = run_analysis(paths, db, 'run-candidate', 'example.com')
                row = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='broken_object_authorization'", (first['analysis_id'],))
                self.assertIsNotNone(row)
                set_bug_candidate_decision(db, str(row['candidate_id']), 'confirmed_by_analyst', 'Verified with authorized test accounts.', actor='test')
                second = replay_analysis(paths, db, 'run-candidate', 'example.com')
                replayed = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='broken_object_authorization'", (second['analysis_id'],))
                self.assertEqual(replayed['analyst_decision'], 'confirmed_by_analyst')
                self.assertEqual(replayed['candidate_state'], 'confirmed_by_analyst')
                self.assertIn('authorized test accounts', replayed['analyst_note'])
            finally:
                db.close()

    def test_candidate_requires_multiple_signals(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now()
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('run-weak','4.1.0','success',?,?,?,1)", (now, now, 'example.com'))
                db.upsert_alert('example.com', 'weak', 'new_url', 'LOW', 20, 'Keyword only', '/about/admin-history', {}, 'run-weak')
                result = run_analysis(paths, db, 'run-weak', 'example.com')
                count = int(db.one("SELECT COUNT(*) FROM bug_candidates WHERE analysis_id=?", (result['analysis_id'],))[0])
                self.assertEqual(count, 0)
            finally:
                db.close()


if __name__ == '__main__':
    unittest.main()
