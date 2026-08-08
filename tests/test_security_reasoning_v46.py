from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from candidate_intelligence import set_gold_label
from core import AppPaths, Database, utc_now
from dashboard import DashboardHandler
from evidence import build_evidence_export
from security_reasoning import evidence_trace, evaluate_reasoning, family_calibration_report, reasoning_regression_gate, reasoning_summary, shadow_rule_report
from analysis_audit import build_evidence_dossier


class SecurityReasoningV46Tests(unittest.TestCase):
    def fixture(self, td: str):
        paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('run46','4.6.0','success',?,?,?,1)",
            (now, now, "example.com"),
        )
        details = {
            "status_code": 200,
            "method": "PATCH",
            "authentication": "bearer",
            "body_fields": ["displayName", "role", "isAdmin", "tenantId", "userId"],
            "path_parameters": ["tenantId", "userId"],
            "endpoint_classification": {"primary_category": "admin", "confidence": 96},
            "response_json": {"user": {"email": "redacted", "role": "admin"}, "tenantId": "t1", "accountBalance": 1},
            "context_observations": {
                "anonymous": {"status_code": 200, "auth_state": "anonymous", "confidence": 82},
                "authenticated": {"status_code": 200, "auth_state": "authenticated", "confidence": 88},
            },
        }
        alert_id, _, _ = db.upsert_alert(
            "example.com", "security-reasoning-alert", "new_endpoint", "HIGH", 91,
            "Tenant administration endpoint", "/api/tenants/{tenantId}/users/{userId}", details, "run46",
        )
        js = paths.state / "reasoning.js"
        js.write_text(
            "const enableTenantAdmin=true; fetch('/api/tenants/'+tenantId+'/users/'+userId); "
            "if (permissions.includes('admin')) { localStorage.getItem('accessToken'); }",
            encoding="utf-8",
        )
        db.execute(
            "INSERT INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,first_seen,last_seen,last_changed,last_run_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("example.com", "https://example.com/app.js", "raw", "sem", str(js), js.stat().st_size, now, now, now, "run46"),
        )
        result = run_analysis(paths, db, "run46", "example.com")
        return paths, db, alert_id, result

    def test_schema_12_and_reasoning_tables(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                self.assertEqual(db.meta_get("schema_version"), "17")
                names = {row[0] for row in db.all("SELECT name FROM sqlite_master WHERE type='table'")}
                for name in ("evidence_records", "candidate_evidence_links", "candidate_evidence_snapshots", "candidate_evidence_exclusions", "candidate_analysis_versions", "family_rankings", "candidate_reasoning_traces", "shadow_rule_results", "family_calibration", "reasoning_evaluations", "reasoning_regression_gates"):
                    self.assertIn(name, names)
                columns = {row[1] for row in db.all("PRAGMA table_info(bug_candidates)")}
                for name in ("calibrated_likelihood", "exploitability_confidence", "evidence_coverage", "precondition_state", "reachability_state", "unknowns_json", "alternative_families_json", "reasoning_trace_json"):
                    self.assertIn(name, columns)
            finally:
                db.close()

    def test_schema_16_database_upgrades_additively_to_17(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            now = utc_now()
            db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('legacy-run','8.3.0','success',?,?,?,0)", (now, now, 'legacy'))
            for table in ('candidate_analysis_versions','candidate_evidence_exclusions','candidate_evidence_snapshots'):
                db.execute(f"DROP TABLE {table}")
            db.meta_set('schema_version','16')
            db.close()
            upgraded = Database(paths.db)
            try:
                self.assertEqual(upgraded.meta_get('schema_version'),'17')
                self.assertIsNotNone(upgraded.one("SELECT id FROM runs WHERE id='legacy-run'"))
                names={row[0] for row in upgraded.all("SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertIn('candidate_evidence_snapshots',names)
                self.assertIn('candidate_evidence_exclusions',names)
                self.assertIn('candidate_analysis_versions',names)
            finally:
                upgraded.close()

    def test_reasoning_scores_provenance_and_top3(self):
        with tempfile.TemporaryDirectory() as td:
            _, db, alert_id, result = self.fixture(td)
            try:
                row = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND alert_id=? AND bug_family='broken_object_authorization'", (result["analysis_id"], alert_id))
                self.assertIsNotNone(row)
                self.assertGreater(int(row["calibrated_likelihood"]), 0)
                self.assertGreater(int(row["evidence_coverage"]), 0)
                self.assertGreater(int(row["exploitability_confidence"]), 0)
                self.assertLessEqual(int(row["exploitability_confidence"]), 85)
                self.assertIn(row["precondition_state"], {"complete", "partial", "insufficient", "not_modeled"})
                trace = evidence_trace(db, row["candidate_id"])
                self.assertGreaterEqual(len(trace["evidence"]), 2)
                self.assertGreaterEqual(len(trace["family_rankings"]), 1)
                self.assertLessEqual(len(trace["family_rankings"]), 3)
                self.assertIn("falsification", trace["reasoning"])
                self.assertIn("unknown_model", trace["reasoning"])
                self.assertIn("calibration", trace["reasoning"])
                self.assertTrue(all(item.get("integrity_hash") for item in trace["evidence"]))
            finally:
                db.close()

    def test_rankings_require_protocol_evidence_and_unknowns_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as td:
            _, db, _, result = self.fixture(td)
            try:
                candidate = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='broken_object_authorization'", (result["analysis_id"],))
                rankings = [str(row[0]) for row in db.all("SELECT bug_family FROM family_rankings WHERE candidate_id=? ORDER BY rank", (candidate["candidate_id"],))]
                self.assertNotIn("websocket_authorization", rankings)
                unknowns = json.loads(candidate["unknowns_json"] or "[]")
                facts = [str(item["fact"]).lower() for item in unknowns]
                self.assertEqual(len(facts), len(set(facts)))
                self.assertLessEqual(sum("ownership" in fact and "boundary" in fact for fact in facts), 1)
            finally:
                db.close()

    def test_unknown_is_not_negative_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            _, db, _, result = self.fixture(td)
            try:
                row = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='broken_object_authorization' LIMIT 1", (result["analysis_id"],))
                unknowns = json.loads(row["unknowns_json"])
                contradict = json.loads(row["contradicting_evidence_json"])
                self.assertTrue(unknowns)
                self.assertTrue(all(item["state"] == "unknown" for item in unknowns))
                self.assertFalse(any(item.get("type") == "server_side_ownership_unknown" for item in contradict))
            finally:
                db.close()

    def test_gold_evaluation_and_family_calibration(self):
        with tempfile.TemporaryDirectory() as td:
            _, db, _, result = self.fixture(td)
            try:
                row = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='broken_object_authorization' LIMIT 1", (result["analysis_id"],))
                set_gold_label(db, row["candidate_id"], "correct_family", "broken_object_authorization", "v46 fixture")
                metrics = evaluate_reasoning(db, result["analysis_id"], persist=True)
                self.assertEqual(metrics["gold_evaluated"], 1)
                self.assertEqual(metrics["top3_family_accuracy"], 1.0)
                report = family_calibration_report(db, "example.com")
                self.assertTrue(any(item["family"] == "broken_object_authorization" for item in report["families"]))
            finally:
                db.close()

    def test_shadow_rules_are_separate_from_candidate_state(self):
        with tempfile.TemporaryDirectory() as td:
            _, db, _, result = self.fixture(td)
            try:
                report = shadow_rule_report(db, result["analysis_id"])
                self.assertEqual(report["analysis_id"], result["analysis_id"])
                self.assertGreaterEqual(len(report["rules"]), 3)
                row = db.one("SELECT analyst_decision FROM bug_candidates WHERE analysis_id=? LIMIT 1", (result["analysis_id"],))
                self.assertEqual(row["analyst_decision"], "unreviewed")
            finally:
                db.close()

    def test_dashboard_and_summary(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _, result = self.fixture(td)
            try:
                summary = reasoning_summary(db, result["analysis_id"])
                self.assertGreater(summary["counts"]["total"], 0)
                self.assertIn("evaluation", summary)
            finally:
                db.close()
            handler = object.__new__(DashboardHandler)
            handler.db_path = paths.db
            handler.path = "/security-reasoning"
            handler.query = lambda: {}
            captured = {}
            handler.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
            handler.security_reasoning_page()
            self.assertEqual(captured["title"], "Security reasoning")
            self.assertIn("Exploitability", captured["body"])
            self.assertIn("Shadow rules", captured["body"])


    def test_evidence_dossier_is_traceable_versioned_and_integrity_checked(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, alert_id, result = self.fixture(td)
            try:
                row = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND alert_id=? AND bug_family='broken_object_authorization'", (result["analysis_id"], alert_id))
                dossier = build_evidence_dossier(db, row["candidate_id"])
                self.assertGreaterEqual(len(dossier["supporting"]), 1)
                self.assertEqual(dossier["integrity"]["status"], "verified")
                self.assertEqual(dossier["integrity"]["verified"], dossier["integrity"]["snapshots"])
                self.assertGreaterEqual(len(dossier["versions"]), 1)
                self.assertTrue(all(item.get("snapshot") for item in dossier["supporting"] + dossier["contradicting"]))
                self.assertTrue(any("alert" in item["snapshot"].get("documents", {}) for item in dossier["supporting"] + dossier["contradicting"]))
                trace = evidence_trace(db, row["candidate_id"])
                self.assertIn("audit", trace)
                self.assertEqual(trace["audit"]["integrity"]["status"], "verified")
                _, package = build_evidence_export(db, alert_id=alert_id)
                with zipfile.ZipFile(io.BytesIO(package)) as zf:
                    payload = json.loads(zf.read("evidence.json"))
                self.assertTrue(payload["candidate_evidence_snapshots"])
                self.assertTrue(payload["candidate_analysis_versions"])
            finally:
                db.close()

    def test_candidate_detail_surfaces_audit_dossier_without_internal_dashboard_noise(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, alert_id, result = self.fixture(td)
            try:
                row = db.one("SELECT candidate_id FROM bug_candidates WHERE analysis_id=? AND alert_id=? AND bug_family='broken_object_authorization'", (result["analysis_id"], alert_id))
                candidate_id = str(row["candidate_id"])
            finally:
                db.close()
            handler = object.__new__(DashboardHandler)
            handler.db_path = paths.db
            handler.path = f"/bug-candidate?id={candidate_id}"
            handler.query = lambda: {"id": [candidate_id]}
            captured = {}
            handler.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
            handler.bug_candidate_detail()
            self.assertEqual(captured["title"], "Potential Finding · Evidence Dossier")
            self.assertIn("Evidence Dossier", captured["body"])
            self.assertIn("Source, lineage & raw snapshot", captured["body"])
            self.assertIn("Snapshot integrity", captured["body"] )
            self.assertIn("No conclusion without traceable evidence", captured["body"])
            self.assertIn("Timeline & analysis history", captured["body"])

    def test_regression_gate_is_persisted_and_safe_without_history(self):
        with tempfile.TemporaryDirectory() as td:
            _, db, _, result = self.fixture(td)
            try:
                gate = reasoning_regression_gate(db, result["analysis_id"], persist=True)
                self.assertTrue(gate["passed"])
                self.assertIn(gate["status"], {"passed", "insufficient_history"})
                self.assertGreater(db.one("SELECT COUNT(*) count FROM reasoning_regression_gates WHERE analysis_id=?", (result["analysis_id"],))["count"], 0)
            finally:
                db.close()

    def test_evidence_export_contains_reasoning_records(self):
        with tempfile.TemporaryDirectory() as td:
            _, db, alert_id, _ = self.fixture(td)
            try:
                _, data = build_evidence_export(db, alert_id=alert_id)
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    payload = json.loads(archive.read("evidence.json"))
                for key in ("evidence_records", "candidate_evidence_links", "family_rankings", "candidate_reasoning_traces", "shadow_rule_results", "reasoning_evaluations", "reasoning_regression_gates"):
                    self.assertIn(key, payload)
                self.assertGreater(len(payload["evidence_records"]), 0)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
