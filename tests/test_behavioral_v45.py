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
from behavioral_intelligence import behavioral_summary
from core import AppPaths, Database, utc_now
from dashboard import DashboardHandler
from evidence import build_evidence_export


class BehavioralV45Tests(unittest.TestCase):
    def fixture(self, td: str):
        paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
        now = utc_now()
        for run_id in ("run45a", "run45b"):
            db.execute(
                "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)",
                (run_id, "4.5.0", "success", now, now, "example.com"),
            )
        js = paths.state / "behavioral.js"
        js.write_text(
            "const redirect_uri='/oauth/callback'; const state='random'; const nonce='n'; "
            "const code_verifier='v'; const ws=new WebSocket('wss://example.com/socket'); "
            "subscribe('tenantId'); fetch('/api/accounts/'+accountId);",
            encoding="utf-8",
        )
        db.execute(
            "INSERT INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,first_seen,last_seen,last_changed,last_run_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("example.com", "https://example.com/app.js", "r1", "s1", str(js), js.stat().st_size, now, now, now, "run45a"),
        )
        alert_id, _, _ = db.upsert_alert(
            "example.com", "behavioral-endpoint", "endpoint", "HIGH", 82,
            "Account endpoint", "/api/v2/accounts/{accountId}",
            {
                "status_code": 401,
                "method": "GET",
                "authentication": "bearer",
                "path_parameters": ["accountId"],
                "response_json": {"error": "authentication required"},
                "response_headers": {"Cache-Control": "no-store"},
            },
            "run45a",
        )
        first = run_analysis(paths, db, "run45a", "example.com")
        db.upsert_alert(
            "example.com", "behavioral-endpoint", "endpoint", "HIGH", 92,
            "Account endpoint", "/api/v2/accounts/{accountId}",
            {
                "status_code": 200,
                "method": "GET",
                "path_parameters": ["accountId"],
                "response_json": {"account": {"email": "redacted"}, "balance": 100},
                "response_headers": {"Cache-Control": "public, max-age=120"},
                "context_observations": {
                    "anonymous": {"status_code": 200, "auth_state": "anonymous", "confidence": 80},
                    "authenticated": {"status_code": 200, "auth_state": "authenticated", "confidence": 85},
                },
            },
            "run45b",
        )
        db.execute("UPDATE js_files SET last_run_id=?,last_seen=?,last_changed=? WHERE target=?", ("run45b", now, now, "example.com"))
        db.execute(
            "INSERT INTO js_indicators(target,js_url,kind,value,redacted,first_seen,last_seen,last_run_id) VALUES(?,?,?,?,0,?,?,?)",
            ("example.com", "https://example.com/app.js", "graphql_operation", "query Account($accountId: ID!){ account(id:$accountId){ email role } }", now, now, "run45b"),
        )
        second = run_analysis(paths, db, "run45b", "example.com")
        return paths, db, alert_id, first, second

    def test_schema_11_and_behavioral_tables(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                self.assertEqual(db.meta_get("schema_version"), "18")
                names = {row[0] for row in db.all("SELECT name FROM sqlite_master WHERE type='table'")}
                for name in (
                    "behavioral_observations", "authentication_boundary_diffs", "response_shape_diffs",
                    "protocol_findings", "identity_entities", "identity_relations",
                ):
                    self.assertIn(name, names)
            finally:
                db.close()

    def test_boundary_and_structural_response_diffs(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _, _, second = self.fixture(td)
            try:
                boundary = db.one("SELECT * FROM authentication_boundary_diffs WHERE analysis_id=?", (second["analysis_id"],))
                self.assertIsNotNone(boundary)
                self.assertEqual(boundary["transition"], "boundary_regression")
                shape = db.one("SELECT * FROM response_shape_diffs WHERE analysis_id=?", (second["analysis_id"],))
                self.assertIsNotNone(shape)
                self.assertIn(shape["transition"], {"error_to_data", "protected_to_data", "sensitive_expansion"})
                self.assertIn("account.email", json.loads(shape["sensitive_added_json"]))
            finally:
                db.close()

    def test_protocol_engines_and_identity_graph(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _, _, second = self.fixture(td)
            try:
                protocols = {row["protocol"] for row in db.all("SELECT protocol FROM protocol_findings WHERE analysis_id=?", (second["analysis_id"],))}
                self.assertTrue({"rest", "graphql", "websocket", "oauth_oidc", "cache"}.issubset(protocols))
                relation = db.one("SELECT * FROM identity_relations WHERE analysis_id=? AND source_type='endpoint' AND relation='reads'", (second["analysis_id"],))
                self.assertIsNotNone(relation)
                self.assertEqual(relation["destination_type"], "account")
                context_count = db.one("SELECT COUNT(*) count FROM behavioral_observations WHERE analysis_id=?", (second["analysis_id"],))["count"]
                self.assertEqual(context_count, 2)
            finally:
                db.close()

    def test_behavioral_diffs_are_hidden_until_family_admission(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _, _, second = self.fixture(td)
            try:
                candidates = [dict(row) for row in db.all(
                    "SELECT * FROM bug_candidates WHERE analysis_id=? AND (source_ref LIKE 'boundary-diff:%' OR source_ref LIKE 'shape-diff:%' OR source_ref LIKE 'protocol:%')",
                    (second["analysis_id"],),
                )]
                self.assertEqual(candidates, [])

                hypotheses = [dict(row) for row in db.all(
                    "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND (source_ref LIKE 'boundary-diff:%' OR source_ref LIKE 'shape-diff:%' OR source_ref LIKE 'protocol:%')",
                    (second["analysis_id"],),
                )]
                self.assertGreaterEqual(len(hypotheses), 2)
                families = {row["bug_family"] for row in hypotheses}
                self.assertIn("authentication_session", families)
                self.assertIn("information_disclosure", families)
                for row in hypotheses:
                    admission = json.loads(row["admission_json"])
                    self.assertFalse(admission["admitted"], row["bug_family"])
                    self.assertNotEqual(row["state"], "promoted")
            finally:
                db.close()

    def test_behavioral_candidate_paths_cannot_bypass_admission(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _, _, second = self.fixture(td)
            try:
                rows = [dict(row) for row in db.all(
                    "SELECT c.candidate_id,c.source_ref,h.admission_json,h.state "
                    "FROM bug_candidates c LEFT JOIN analysis_hypotheses h "
                    "ON h.analysis_id=c.analysis_id AND h.promoted_candidate_id=c.candidate_id "
                    "WHERE c.analysis_id=? AND (c.source_ref LIKE 'boundary-diff:%' OR c.source_ref LIKE 'shape-diff:%' OR c.source_ref LIKE 'protocol:%')",
                    (second["analysis_id"],),
                )]
                for row in rows:
                    self.assertTrue(row["admission_json"], row["candidate_id"])
                    admission = json.loads(row["admission_json"])
                    self.assertTrue(admission["admitted"], row["candidate_id"])
                    self.assertEqual(row["state"], "promoted")
            finally:
                db.close()

    def test_behavioral_summary_and_dashboard_route(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _, _, second = self.fixture(td)
            try:
                summary = behavioral_summary(db, second["analysis_id"])
                self.assertGreater(summary["counts"]["boundary_diffs"], 0)
                self.assertGreater(summary["counts"]["protocol_findings"], 0)
            finally:
                db.close()
            handler = object.__new__(DashboardHandler)
            handler.db_path = paths.db
            handler.path = "/behavioral-intelligence"
            handler.query = lambda: {}
            captured = {}
            handler.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
            handler.behavioral_intelligence_page()
            self.assertEqual(captured["title"], "Behavioral intelligence")
            self.assertIn("Authentication boundary changes", captured["body"])
            self.assertIn("Identity and authorization graph", captured["body"])

    def test_evidence_export_contains_behavioral_records(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, alert_id, _, second = self.fixture(td)
            try:
                _, data = build_evidence_export(db, alert_id=alert_id)
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    payload = json.loads(archive.read("evidence.json"))
                self.assertIn("authentication_boundary_diffs", payload)
                self.assertIn("response_shape_diffs", payload)
                self.assertIn("protocol_findings", payload)
                self.assertIn("identity_relations", payload)
                self.assertGreater(len(payload["authentication_boundary_diffs"]), 0)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
