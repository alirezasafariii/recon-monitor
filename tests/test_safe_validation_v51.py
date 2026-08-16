from __future__ import annotations

import base64
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, SCHEMA_VERSION, AppPaths, Config, Database, json_dumps, utc_now
from dashboard import DashboardHandler
from evidence import build_evidence_export
from safe_validation import (
    approve_validation_plan,
    create_validation_plan,
    execute_validation_plan,
    import_burp_xml,
    import_har,
    record_validation_feedback,
    _classify,
    _record_validation_evidence,
    validation_detail,
    validation_eligibility,
)


class SafeValidationV51Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name)); paths.ensure()
        paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nENABLE_ACTIVE_MODULES="yes"\nTELEGRAM_ENABLED="no"\n', encoding="utf-8")
        paths.policy.write_text(json.dumps({
            "schema": 3,
            "defaults": {"limits": {"max_http_requests": 1000, "max_runtime_minutes": 60}},
            "targets": [{
                "name": "example.com", "roots": ["example.com"],
                "include": [r"(^|\.)example\.com$"], "exclude": [r"^status\.example\.com$"],
                "active": {"confirmation": "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING"},
            }],
        }), encoding="utf-8")
        return temp, paths, Database(paths.db)

    def add_case(self, db: Database, *, case_id="CASE-1", family="Information Disclosure", endpoint="https://example.com/api/account"):
        now = utc_now(); candidate_id = "CAND-" + case_id
        db.execute(
            "INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at) VALUES(?,?,?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (candidate_id, "fp-"+case_id, "AN-1", "RUN-1", "example.com", "example.com", endpoint, endpoint, family, "candidate", family+" candidate", "Candidate summary", 75, 70, 80, 78, "plausible", "[]", "[]", "[]", "Review safely", "[]", "v1", "unreviewed", "", now, now),
        )
        db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'ready_for_validation','','in_scope',50,?,?)",
            (case_id, "key-"+case_id, "AN-1", "RUN-1", "example.com", family+" case", "Case summary", family, 80, now, now),
        )
        db.execute("INSERT INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES(?, 'candidate', ?, 'supports_case', '{}', ?)", (case_id, candidate_id, now))
        return candidate_id

    def add_direct_evidence(self, db: Database, candidate_id: str, suffix: str, polarity="supports"):
        now = utc_now(); evidence_id = "EVD-"+suffix; root = "root-"+suffix
        db.execute(
            "INSERT INTO evidence_records(evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,summary,raw_reference,integrity_hash,first_seen,last_seen,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (evidence_id, "AN-1", "RUN-1", "example.com", "http_observation", polarity, "http", "fixture", "fixture", "fixture", "1", "fixture", root, 80, 80, "direct", "fixture evidence", "fixture", root, now, now, now),
        )
        db.execute("INSERT INTO candidate_evidence_links(candidate_id,evidence_id,polarity,weight,relation,created_at) VALUES(?,?,?,?,?,?)", (candidate_id, evidence_id, polarity, 80, "fixture", now))

    def test_version_schema_and_validation_tables(self):
        temp, paths, db = self.project()
        try:
            self.assertEqual(APP_VERSION, "8.7.0"); self.assertEqual(SCHEMA_VERSION, 18); self.assertEqual(db.meta_get("schema_version"), "18")
            names = {row[0] for row in db.all("SELECT name FROM sqlite_master WHERE type='table'")}
            for name in ("validation_plans", "validation_approvals", "validation_runs", "validation_observations", "validation_feedback", "imported_http_evidence"):
                self.assertIn(name, names)
            columns = {row[1] for row in db.all("PRAGMA table_info(security_cases)")}
            self.assertTrue({"validation_state", "validation_summary", "last_validation_at"}.issubset(columns))
        finally: db.close(); temp.cleanup()

    def test_eligibility_keeps_risky_families_manual_or_controlled(self):
        temp, paths, db = self.project()
        try:
            self.add_case(db, case_id="CASE-SSRF", family="SSRF")
            self.add_case(db, case_id="CASE-BOLA", family="BOLA / IDOR")
            self.add_case(db, case_id="CASE-INFO", family="Information Disclosure")
            self.assertEqual(validation_eligibility(db, "CASE-SSRF")["recommended_level"], "manual_only")
            self.assertEqual(validation_eligibility(db, "CASE-BOLA")["recommended_level"], "controlled")
            self.assertEqual(validation_eligibility(db, "CASE-INFO")["recommended_level"], "passive_live")
        finally: db.close(); temp.cleanup()

    def test_plan_cannot_downgrade_controlled_candidate(self):
        temp, paths, db = self.project()
        try:
            self.add_case(db, family="BOLA / IDOR")
            with self.assertRaises(Exception):
                create_validation_plan(paths, db, "CASE-1", requested_level="passive_live")
            plan = create_validation_plan(paths, db, "CASE-1")
            self.assertEqual(plan["level"], "controlled"); self.assertEqual(plan["status"], "not_eligible")
        finally: db.close(); temp.cleanup()

    def test_offline_validation_records_evidence_without_network(self):
        temp, paths, db = self.project()
        try:
            candidate = self.add_case(db)
            self.add_direct_evidence(db, candidate, "A")
            self.add_direct_evidence(db, candidate, "B")
            plan = create_validation_plan(paths, db, "CASE-1", requested_level="offline")
            result = execute_validation_plan(paths, Config(paths), db, plan["plan_id"], actor="test")
            self.assertEqual(result["network_requests"], 0); self.assertEqual(result["result"], "strengthened")
            self.assertGreater(db.one("SELECT COUNT(*) count FROM validation_runs")["count"], 0)
            self.assertEqual(db.one("SELECT analyst_decision FROM bug_candidates WHERE candidate_id=?", (candidate,))["analyst_decision"], "unreviewed")
        finally: db.close(); temp.cleanup()

    def test_passive_live_requires_exact_approval_and_explicit_gate(self):
        temp, paths, db = self.project()
        try:
            candidate = self.add_case(db)
            plan = create_validation_plan(paths, db, "CASE-1")
            self.assertEqual(plan["status"], "awaiting_approval")
            with self.assertRaises(Exception): approve_validation_plan(db, plan["plan_id"], "wrong")
            approve_validation_plan(db, plan["plan_id"], plan["approval_phrase"], actor="test")
            with self.assertRaises(Exception): execute_validation_plan(paths, Config(paths), db, plan["plan_id"], allow_live=False)
            observation = {"method":"GET","url":"https://example.com/api/account","status_code":200,"headers":{"content-type":"application/json"},"content_type":"application/json","response_bytes":30,"body_sha256":"x","response_shape":{"email":"string"},"shape_hash":"s","sensitive_key_names":["email"],"sensitive_pattern_categories":[],"raw_body_stored":False,"error":"","observed_at":utc_now()}
            with mock.patch("safe_validation._perform_request", return_value=(observation, "ok")):
                result = execute_validation_plan(paths, Config(paths), db, plan["plan_id"], allow_live=True, actor="test")
            self.assertEqual(result["result"], "strengthened")
            self.assertFalse(result["raw_bodies_stored"])
            self.assertEqual(db.one("SELECT analyst_decision FROM bug_candidates WHERE candidate_id=?", (candidate,))["analyst_decision"], "unreviewed")
            stored = json.loads(db.one("SELECT observation_json FROM validation_observations LIMIT 1")["observation_json"])
            self.assertNotIn("body", stored); self.assertFalse(stored["raw_body_stored"])
        finally: db.close(); temp.cleanup()

    def test_candidate_specific_validation_evidence_does_not_cross_link_endpoints(self):
        temp, paths, db = self.project()
        try:
            first = self.add_case(db, case_id="CASE-MAP-1", endpoint="https://example.com/api/account")
            second = self.add_case(db, case_id="CASE-MAP-2", endpoint="https://example.com/api/profile")
            db.execute("DELETE FROM security_case_members WHERE case_id='CASE-MAP-2' AND member_id=?", (second,))
            db.execute(
                "INSERT INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES('CASE-MAP-1','candidate',?,'supports_case','{}',?)",
                (second, utc_now()),
            )
            plan = create_validation_plan(paths, db, "CASE-MAP-1")
            ownership = {}
            for request in plan["requests"]:
                ownership.setdefault(request["url"], set()).update(request.get("candidate_ids") or [])
            self.assertEqual(ownership["https://example.com/api/account"], {first})
            self.assertEqual(ownership["https://example.com/api/profile"], {second})

            observations = [
                {
                    "candidate_ids": [first], "method": "GET", "url": "https://example.com/api/account",
                    "status_code": 200, "headers": {}, "sensitive_key_names": ["email"],
                    "sensitive_pattern_categories": [],
                },
                {
                    "candidate_ids": [second], "method": "GET", "url": "https://example.com/api/profile",
                    "status_code": 403, "headers": {}, "sensitive_key_names": [],
                    "sensitive_pattern_categories": [],
                },
            ]
            linked = _record_validation_evidence(db, "CASE-MAP-1", "SVR-MAP", "strengthened", observations)
            self.assertEqual(linked, 2)
            rows = db.all(
                "SELECT l.candidate_id,e.polarity,e.raw_reference FROM candidate_evidence_links l "
                "JOIN evidence_records e ON e.evidence_id=l.evidence_id "
                "WHERE e.source_artifact='SVR-MAP' ORDER BY l.candidate_id"
            )
            by_candidate = {str(row["candidate_id"]): (str(row["polarity"]), str(row["raw_reference"])) for row in rows}
            self.assertEqual(by_candidate[first][0], "supports")
            self.assertEqual(by_candidate[second][0], "contradicts")
            self.assertIn(first, by_candidate[first][1])
            self.assertIn(second, by_candidate[second][1])
        finally:
            db.close(); temp.cleanup()

    def test_cors_headers_alone_never_strengthen_without_browser_readability(self):
        wildcard = [{
            "status_code": 200,
            "headers": {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
            "sensitive_key_names": ["email"],
            "sensitive_pattern_categories": [],
        }]
        reflected = [{
            "status_code": 200,
            "headers": {"access-control-allow-origin": "https://safe-validation.invalid", "access-control-allow-credentials": "true"},
            "sensitive_key_names": ["email"],
            "sensitive_pattern_categories": [],
        }]
        self.assertEqual(_classify("cors_misconfiguration", wildcard)[0], "inconclusive")
        self.assertEqual(_classify("cors_misconfiguration", reflected)[0], "inconclusive")

    def test_feedback_is_structured_and_audited(self):
        temp, paths, db = self.project()
        try:
            self.add_case(db); plan = create_validation_plan(paths, db, "CASE-1", requested_level="offline")
            run = execute_validation_plan(paths, Config(paths), db, plan["plan_id"])
            feedback = record_validation_feedback(db, run["run_id"], "needs_more_evidence", "insufficient_evidence", "Need second context", actor="test")
            self.assertTrue(feedback["ok"]); self.assertEqual(db.one("SELECT reason_code FROM validation_feedback")["reason_code"], "insufficient_evidence")
            self.assertGreater(db.one("SELECT COUNT(*) count FROM audit_log WHERE action='validation_feedback_recorded'")["count"], 0)
        finally: db.close(); temp.cleanup()

    def test_har_import_is_scope_bounded_and_redacted(self):
        temp, paths, db = self.project()
        try:
            self.add_case(db)
            har = {"log":{"entries":[
                {"request":{"method":"GET","url":"https://example.com/api/account","headers":[{"name":"Authorization","value":"Bearer secret"}]},"response":{"status":200,"headers":[{"name":"Content-Type","value":"application/json"},{"name":"Set-Cookie","value":"secret"}],"content":{"text":json.dumps({"email":"person@example.com","token":"abc"}),"mimeType":"application/json"}}},
                {"request":{"method":"GET","url":"https://evil.example.net/","headers":[]},"response":{"status":200,"headers":[],"content":{"text":"x"}}},
            ]}}
            path = paths.root / "sample.har"; path.write_text(json.dumps(har), encoding="utf-8")
            result = import_har(paths, db, "CASE-1", path, actor="test")
            self.assertEqual(result["imported"], 1); self.assertEqual(result["skipped"], 1); self.assertFalse(result["raw_bodies_stored"])
            payload = json.loads(db.one("SELECT observation_json FROM imported_http_evidence")["observation_json"])
            self.assertEqual(payload["request_headers"]["authorization"], "<redacted>")
            self.assertNotIn("person@example.com", json.dumps(payload)); self.assertNotIn("abc", json.dumps(payload))
        finally: db.close(); temp.cleanup()

    def test_burp_xml_import_rejects_entities_and_imports_metadata(self):
        temp, paths, db = self.project()
        try:
            self.add_case(db)
            request = base64.b64encode(b"GET /api/account HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer secret\r\n\r\n").decode()
            response = base64.b64encode(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: secret\r\n\r\n{\"email\":\"person@example.com\"}").decode()
            xml = f"<items><item><url>https://example.com/api/account</url><method>GET</method><status>200</status><request base64='true'>{request}</request><response base64='true'>{response}</response></item></items>"
            path = paths.root / "burp.xml"; path.write_text(xml, encoding="utf-8")
            result = import_burp_xml(paths, db, "CASE-1", path, actor="test")
            self.assertEqual(result["imported"], 1)
            payload = json.loads(db.one("SELECT observation_json FROM imported_http_evidence")["observation_json"])
            self.assertEqual(payload["request_headers"]["authorization"], "<redacted>")
            bad = paths.root / "bad.xml"; bad.write_text("<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///etc/passwd'>]><items/>", encoding="utf-8")
            with self.assertRaises(Exception): import_burp_xml(paths, db, "CASE-1", bad)
        finally: db.close(); temp.cleanup()

    def test_dashboard_safe_validation_route_renders(self):
        temp, paths, db = self.project()
        try:
            self.add_case(db); db.close()
            handler = object.__new__(DashboardHandler); handler.paths = paths; handler.db_path = paths.db; handler.path = "/safe-validation?case_id=CASE-1"; handler.query = lambda: {"case_id":["CASE-1"]}
            captured = {}; handler.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
            handler.safe_validation_page()
            self.assertEqual(captured["title"], "Safe validation"); self.assertIn("Eligibility", captured["body"]); self.assertIn("Create validation plan", captured["body"])
        finally: temp.cleanup()

    def test_evidence_export_contains_validation_records(self):
        temp, paths, db = self.project()
        try:
            candidate = self.add_case(db); self.add_direct_evidence(db, candidate, "A"); self.add_direct_evidence(db, candidate, "B")
            now=utc_now()
            db.execute("INSERT INTO alerts(id,target,dedup_key,category,severity,risk_score,title,item,details_json,status,first_seen,last_seen,last_notified,last_run_id,occurrences,priority,assignee,workflow_note,updated_at) VALUES(1,'example.com','d','test','HIGH',80,'Test','https://example.com/api/account','{}','new',?,?,NULL,'RUN-1',1,'normal','','',?)", (now,now,now))
            db.execute("UPDATE bug_candidates SET alert_id=1 WHERE candidate_id=?", (candidate,))
            plan=create_validation_plan(paths,db,"CASE-1",requested_level="offline"); execute_validation_plan(paths,Config(paths),db,plan["plan_id"])
            _, blob=build_evidence_export(db,alert_id=1)
            with zipfile.ZipFile(io.BytesIO(blob)) as z: payload=json.loads(z.read("evidence.json"))
            for key in ("validation_plans","validation_runs","validation_observations","validation_feedback","imported_http_evidence"):
                self.assertIn(key,payload)
            self.assertGreater(len(payload["validation_runs"]),0)
        finally: db.close(); temp.cleanup()


if __name__ == "__main__":
    unittest.main()
