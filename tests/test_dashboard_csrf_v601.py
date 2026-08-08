from __future__ import annotations

import json
import tempfile
import threading
import urllib.parse
import urllib.request
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Config, Database, Logger, utc_now
from dashboard import (
    DashboardHandler,
    _inject_csrf_inputs,
    _layout,
    _origin_matches_request,
    _origin_matches_loopback_server,
)
from session_auth import Session, create_session, session_cookie
from http.server import ThreadingHTTPServer


class DashboardCsrfV601Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text(
            'DASHBOARD_AUTH_ENABLED="yes"\n'
            'DASHBOARD_AUTH_MODE="session"\n'
            'DASHBOARD_TRUST_PROXY_HEADERS="no"\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def handler(self, headers: dict[str, str]) -> DashboardHandler:
        h = object.__new__(DashboardHandler)
        h.paths = self.paths
        h.config = Config(self.paths)
        h.headers = headers
        h.session = Session("analyst", "analyst", "csrf-token", 9999999999, "session-token")
        h.server = type("Server", (), {"server_address": ("127.0.0.1", 8787)})()
        h.client_address = ("127.0.0.1", 51337)
        h.path = "/validation/plan"
        return h

    def test_server_side_csrf_is_embedded_in_post_forms(self) -> None:
        body = "<form method='post' action='/validation/approve'><input name='plan_id'></form>"
        rendered = _layout("Safe validation", body, csrf="csrf-token", username="analyst", role="analyst", current_path="/safe-validation")
        self.assertIn("name='csrf' value='csrf-token'", rendered)
        self.assertEqual(rendered.count("name='csrf' value='csrf-token'"), 1)

    def test_existing_csrf_is_not_duplicated(self) -> None:
        body = "<form method='POST'><input type='hidden' name='csrf' value='existing'></form>"
        rendered = _inject_csrf_inputs(body, "new-token")
        self.assertEqual(rendered.count("name='csrf'"), 1)
        self.assertIn("value='existing'", rendered)

    def test_loopback_aliases_are_same_origin_on_same_port(self) -> None:
        self.assertTrue(_origin_matches_request("http://localhost:8787", "127.0.0.1:8787"))
        self.assertTrue(_origin_matches_request("http://127.0.0.1:8787", "localhost:8787"))
        self.assertTrue(_origin_matches_request("http://[::1]:8787", "localhost:8787"))
        self.assertFalse(_origin_matches_request("http://localhost:8788", "127.0.0.1:8787"))
        self.assertFalse(_origin_matches_request("https://localhost:8787", "127.0.0.1:8787"))


    def test_actual_loopback_socket_recovers_from_rewritten_host_header(self) -> None:
        self.assertTrue(_origin_matches_loopback_server("http://localhost:8787", ("127.0.0.1", 8787)))
        self.assertTrue(_origin_matches_loopback_server("http://127.0.0.1:8787", ("::1", 8787)))
        self.assertFalse(_origin_matches_loopback_server("http://localhost:8788", ("127.0.0.1", 8787)))
        self.assertFalse(_origin_matches_loopback_server("http://evil.example:8787", ("127.0.0.1", 8787)))
        self.assertFalse(_origin_matches_loopback_server("http://localhost:8787", ("0.0.0.0", 8787)))

    def test_handler_uses_actual_socket_when_host_header_is_rewritten(self) -> None:
        h = self.handler({
            "Origin": "http://localhost:8787",
            "Host": "0.0.0.0:8787",
            "Sec-Fetch-Site": "cross-site",
        })
        self.assertTrue(h._same_origin_post())
        h.server = type("Server", (), {"server_address": ("127.0.0.1", 8788)})()
        self.assertFalse(h._same_origin_post())



    def test_safari_literal_null_origin_same_origin_is_allowed_for_local_dashboard_forms(self) -> None:
        h = self.handler({
            "Origin": "null",
            "Host": "127.0.0.1:8787",
            "Sec-Fetch-Site": "same-origin",
        })
        self.assertTrue(h._same_origin_post())

        h.path = "/alerts/status"
        self.assertTrue(h._same_origin_post())

        h.path = "/validation/plan"
        h.headers["Sec-Fetch-Site"] = "same-site"
        self.assertFalse(h._same_origin_post())
        h.headers["Sec-Fetch-Site"] = "cross-site"
        self.assertFalse(h._same_origin_post())

        h.headers["Sec-Fetch-Site"] = "same-origin"
        h.client_address = ("192.0.2.10", 51337)
        self.assertFalse(h._same_origin_post())

    def test_safari_literal_null_origin_rejects_wrong_host_port_and_proxy_mode(self) -> None:
        h = self.handler({
            "Origin": "null",
            "Host": "127.0.0.1:8788",
            "Sec-Fetch-Site": "same-origin",
        })
        self.assertFalse(h._same_origin_post())

        h.headers["Host"] = "evil.example:8787"
        self.assertFalse(h._same_origin_post())

        self.paths.config.write_text(
            'DASHBOARD_AUTH_ENABLED="yes"\n'
            'DASHBOARD_AUTH_MODE="session"\n'
            'DASHBOARD_TRUST_PROXY_HEADERS="yes"\n',
            encoding="utf-8",
        )
        h.config = Config(self.paths)
        h.headers["Host"] = "127.0.0.1:8787"
        self.assertFalse(h._same_origin_post())

    def test_safari_missing_origin_same_site_is_allowed_only_on_loopback(self) -> None:
        h = self.handler({
            "Host": "127.0.0.1:8787",
            "Sec-Fetch-Site": "same-site",
        })
        self.assertTrue(h._same_origin_post())
        self.assertTrue(h._require_csrf({"csrf": ["csrf-token"]}))

        h.client_address = ("192.0.2.10", 51337)
        self.assertFalse(h._same_origin_post())

        h = self.handler({
            "Host": "127.0.0.1:8787",
            "Sec-Fetch-Site": "cross-site",
        })
        self.assertFalse(h._same_origin_post())

    def test_missing_origin_uses_loopback_referer_on_same_port(self) -> None:
        h = self.handler({
            "Host": "0.0.0.0:8787",
            "Sec-Fetch-Site": "same-site",
            "Referer": "http://localhost:8787/safe-validation?case_id=CASE-1",
        })
        self.assertTrue(h._same_origin_post())
        h.headers["Referer"] = "http://localhost:8788/safe-validation"
        self.assertFalse(h._same_origin_post())

    def test_external_null_and_malformed_origins_are_rejected(self) -> None:
        self.assertFalse(_origin_matches_request("http://evil.example:8787", "127.0.0.1:8787"))
        self.assertFalse(_origin_matches_request("http://localhost:8787/path", "127.0.0.1:8787"))
        self.assertFalse(_origin_matches_request("not-an-origin", "127.0.0.1:8787"))

    def test_handler_accepts_loopback_alias_and_valid_csrf(self) -> None:
        h = self.handler({
            "Origin": "http://localhost:8787",
            "Host": "127.0.0.1:8787",
            "Sec-Fetch-Site": "cross-site",
        })
        self.assertTrue(h._same_origin_post())
        self.assertTrue(h._require_csrf({"csrf": ["csrf-token"]}))

    def test_handler_rejects_cross_origin_even_with_valid_csrf(self) -> None:
        h = self.handler({"Origin": "http://evil.example:8787", "Host": "127.0.0.1:8787"})
        self.assertFalse(h._same_origin_post())
        self.assertTrue(h._require_csrf({"csrf": ["csrf-token"]}))

    def test_handler_rejects_missing_or_stale_csrf(self) -> None:
        h = self.handler({"Origin": "http://127.0.0.1:8787", "Host": "127.0.0.1:8787"})
        self.assertTrue(h._same_origin_post())
        self.assertFalse(h._require_csrf({}))
        self.assertFalse(h._require_csrf({"csrf": ["stale-token"]}))
        self.assertTrue(h._require_csrf({"csrf": ["csrf-token"]}))

    def test_explicit_allowed_origin_is_opt_in(self) -> None:
        self.paths.config.write_text(
            'DASHBOARD_AUTH_ENABLED="yes"\n'
            'DASHBOARD_AUTH_MODE="session"\n'
            'DASHBOARD_ALLOWED_ORIGINS="https://dashboard.example.test"\n',
            encoding="utf-8",
        )
        h = self.handler({"Origin": "https://dashboard.example.test", "Host": "127.0.0.1:8787"})
        self.assertTrue(h._same_origin_post())
        h = self.handler({"Origin": "https://other.example.test", "Host": "127.0.0.1:8787"})
        self.assertFalse(h._same_origin_post())

    def test_http_safe_validation_post_accepts_localhost_alias(self) -> None:
        self.paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\n'
            'ENABLE_ACTIVE_MODULES="yes"\n'
            'DASHBOARD_AUTH_ENABLED="yes"\n'
            'DASHBOARD_AUTH_MODE="session"\n',
            encoding="utf-8",
        )
        self.paths.policy.write_text(json.dumps({
            "schema": 3, "defaults": {},
            "targets": [{
                "name": "example.com", "roots": ["example.com"],
                "include": [r"(^|\\.)example\\.com$"], "exclude": [],
                "active": {"confirmation": "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING"},
            }],
        }), encoding="utf-8")
        db = Database(self.paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at) VALUES('C1','fp','A1','R1',NULL,'example.com','example.com','https://example.com/api/account','https://example.com/api/account','Information Disclosure','candidate','Candidate','Summary',75,70,80,78,'plausible','[]','[]','[]','Review','[]','v1','unreviewed','',?,?)",
            (now, now),
        )
        db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES('CASE-1','k','A1','R1','example.com','Case','Summary','Information Disclosure',80,'ready_for_validation','','in_scope',50,?,?)",
            (now, now),
        )
        db.execute("INSERT INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES('CASE-1','candidate','C1','supports_case','{}',?)", (now,))
        db.close()

        config = Config(self.paths)
        logger = Logger(self.paths, verbose=False)
        handler = type(
            "ConfiguredDashboardHandler",
            (DashboardHandler,),
            {"db_path": self.paths.db, "paths": self.paths, "logger": logger, "config": config},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            session = create_session(self.paths, "analyst", "analyst")
            cookie = session_cookie(session).split(";", 1)[0]
            get_request = urllib.request.Request(
                f"http://127.0.0.1:{port}/safe-validation?case_id=CASE-1",
                headers={"Cookie": cookie},
            )
            rendered = urllib.request.urlopen(get_request, timeout=5).read().decode("utf-8")
            self.assertIn(f"name='csrf' value='{session.csrf}'", rendered)

            payload = urllib.parse.urlencode({
                "case_id": "CASE-1", "level": "offline",
                "return": "/safe-validation?case_id=CASE-1", "csrf": session.csrf,
            }).encode("utf-8")
            post_request = urllib.request.Request(
                f"http://127.0.0.1:{port}/validation/plan", data=payload, method="POST",
                headers={
                    "Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"http://localhost:{port}", "Host": f"0.0.0.0:{port}",
                    "Sec-Fetch-Site": "cross-site",
                },
            )
            response = urllib.request.urlopen(post_request, timeout=5)
            self.assertEqual(response.status, 200)
            check = Database(self.paths.db)
            try:
                self.assertEqual(check.one("SELECT COUNT(*) count FROM validation_plans WHERE case_id='CASE-1'")["count"], 1)
            finally:
                check.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_http_safe_validation_post_accepts_safari_missing_origin(self) -> None:
        self.paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\n'
            'ENABLE_ACTIVE_MODULES="yes"\n'
            'DASHBOARD_AUTH_ENABLED="yes"\n'
            'DASHBOARD_AUTH_MODE="session"\n',
            encoding="utf-8",
        )
        self.paths.policy.write_text(json.dumps({
            "schema": 3, "defaults": {},
            "targets": [{
                "name": "example.com", "roots": ["example.com"],
                "include": [r"(^|\\.)example\\.com$"], "exclude": [],
                "active": {"confirmation": "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING"},
            }],
        }), encoding="utf-8")
        db = Database(self.paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at) VALUES('C2','fp2','A1','R1',NULL,'example.com','example.com','https://example.com/api/account','https://example.com/api/account','ssrf','candidate','Candidate','Summary',75,70,80,78,'plausible','[]','[]','[]','Review','[]','v1','unreviewed','',?,?)",
            (now, now),
        )
        db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES('CASE-2','k2','A1','R1','example.com','Case','Summary','ssrf',80,'ready_for_validation','','in_scope',50,?,?)",
            (now, now),
        )
        db.execute("INSERT INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES('CASE-2','candidate','C2','supports_case','{}',?)", (now,))
        db.close()

        config = Config(self.paths)
        logger = Logger(self.paths, verbose=False)
        handler = type(
            "ConfiguredDashboardHandler",
            (DashboardHandler,),
            {"db_path": self.paths.db, "paths": self.paths, "logger": logger, "config": config},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            session = create_session(self.paths, "analyst", "analyst")
            cookie = session_cookie(session).split(";", 1)[0]
            payload = urllib.parse.urlencode({
                "case_id": "CASE-2", "level": "manual_only",
                "return": "/safe-validation?case_id=CASE-2", "csrf": session.csrf,
            }).encode("utf-8")
            post_request = urllib.request.Request(
                f"http://127.0.0.1:{port}/validation/plan", data=payload, method="POST",
                headers={
                    "Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded",
                    "Host": f"127.0.0.1:{port}", "Sec-Fetch-Site": "same-site",
                },
            )
            response = urllib.request.urlopen(post_request, timeout=5)
            self.assertEqual(response.status, 200)
            check = Database(self.paths.db)
            try:
                row = check.one("SELECT level,status FROM validation_plans WHERE case_id='CASE-2'")
                self.assertIsNotNone(row)
                self.assertEqual(row["level"], "manual_only")
            finally:
                check.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


    def test_http_manual_only_bola_plan_accepts_safari_literal_null_origin_without_auth(self) -> None:
        self.paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\n'
            'ENABLE_ACTIVE_MODULES="yes"\n'
            'DASHBOARD_AUTH_ENABLED="no"\n'
            'DASHBOARD_TRUST_PROXY_HEADERS="no"\n',
            encoding="utf-8",
        )
        self.paths.policy.write_text(json.dumps({
            "schema": 3, "defaults": {},
            "targets": [{
                "name": "example.com", "roots": ["example.com"],
                "include": [r"(^|\\.)example\\.com$"], "exclude": [],
                "active": {"confirmation": "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING"},
            }],
        }), encoding="utf-8")
        db = Database(self.paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO bug_candidates(candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at) VALUES('C3','fp3','A1','R1',NULL,'example.com','example.com','https://example.com/api/account/123','https://example.com/api/account/123','broken_object_authorization','candidate','BOLA candidate','Summary',75,70,80,78,'plausible','[]','[]','[]','Review','[]','v1','unreviewed','',?,?)",
            (now, now),
        )
        db.execute(
            "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) VALUES('CASE-3','k3','A1','R1','example.com','Case','Summary','broken_object_authorization',80,'ready_for_validation','','in_scope',50,?,?)",
            (now, now),
        )
        db.execute("INSERT INTO security_case_members(case_id,member_type,member_id,relation,metadata_json,created_at) VALUES('CASE-3','candidate','C3','supports_case','{}',?)", (now,))
        db.close()

        config = Config(self.paths)
        logger = Logger(self.paths, verbose=False)
        handler = type(
            "ConfiguredDashboardHandler",
            (DashboardHandler,),
            {"db_path": self.paths.db, "paths": self.paths, "logger": logger, "config": config},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            payload = urllib.parse.urlencode({
                "case_id": "CASE-3", "level": "manual_only",
                "return": "/safe-validation?case_id=CASE-3",
            }).encode("utf-8")
            post_request = urllib.request.Request(
                f"http://127.0.0.1:{port}/validation/plan", data=payload, method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "null", "Host": f"127.0.0.1:{port}",
                    "Sec-Fetch-Site": "same-origin",
                },
            )
            response = urllib.request.urlopen(post_request, timeout=5)
            self.assertEqual(response.status, 200)
            check = Database(self.paths.db)
            try:
                row = check.one("SELECT level,status FROM validation_plans WHERE case_id='CASE-3'")
                self.assertIsNotNone(row)
                self.assertEqual(row["level"], "manual_only")
            finally:
                check.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
