from __future__ import annotations

import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import api_server
import api_server_core as api
import dashboard
import dashboard_core
import platform_v6
import test_api_suite_config as http_fixture
import test_platform_v60 as platform_fixture
from core import APP_VERSION, AppPaths, Config, Database, ReconError, utc_now
from platform_v6 import data_quality_snapshot
from session_auth import create_session, create_user, session_cookie


class EmptyReadInputTests(unittest.TestCase):
    QUALITY = "/api/v1/suite/data-quality"

    def setUp(self):
        for name in (
            "subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect",
            "socket.socket.connect_ex", "socket.socket.bind", "urllib.request.urlopen",
        ):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        environment = patch.dict(os.environ, {
            "I_HAVE_AUTHORIZATION": "yes", "TELEGRAM_ENABLED": "no",
            "DASHBOARD_AUTH_ENABLED": "yes", "DASHBOARD_AUTH_MODE": "session",
        })
        environment.start()
        self.addCleanup(environment.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.paths = AppPaths.from_root(Path(temp.name))
        self.paths.ensure()
        self.paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\nTELEGRAM_ENABLED="no"\n'
            'DASHBOARD_AUTH_ENABLED="yes"\nDASHBOARD_AUTH_MODE="session"\n',
            encoding="utf-8",
        )
        self.db = Database(self.paths.db)
        self.addCleanup(self.db.close)
        self._bind(self.paths, self.db)

    def _bind(self, paths, db):
        create_user(paths, "offline-viewer", "offline-test-password", "viewer")
        self.cookie = session_cookie(create_session(paths, "offline-viewer", "viewer")).split(";", 1)[0]
        self.token = api.create_token(db, "offline-viewer", "viewer")
        # Keep the public server entry points' real handler bindings and auth;
        # replace only listeners and the dashboard startup diagnostic thread.
        with patch.object(api, "ControlledAPIHTTPServer") as server:
            api_server.serve_api(paths, Mock(), "127.0.0.1", 0)
        self.api_handler = server.call_args.args[1]
        with patch.object(dashboard_core, "ThreadingHTTPServer") as server, patch.object(dashboard_core.threading, "Thread"):
            dashboard.serve_dashboard(paths, Config(paths), Mock(), "127.0.0.1", 0)
        self.dashboard_handler = server.call_args.args[1]

    def _populated(self):
        temp, self.paths, self.db = platform_fixture.PlatformV60Tests().project()
        self.addCleanup(temp.cleanup)
        self.addCleanup(self.db.close)
        self._bind(self.paths, self.db)

    def _get(self, handler, route, headers="", *, expected=200):
        request = (
            f"GET {route} HTTP/1.1\r\nHost: localhost\r\n{headers}"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        stream = http_fixture.MemoryRequest(request)
        handler(stream, ("127.0.0.1", 0), Mock())
        head, separator, body = stream.output.getvalue().partition(b"\r\n\r\n")
        self.assertTrue(separator, "Handler did not send an HTTP response")
        self.assertEqual(int(head.split(b"\r\n", 1)[0].split()[1]), expected, body[:500])
        fields = dict(line.split(b": ", 1) for line in head.split(b"\r\n")[1:])
        if b"Content-Length" in fields:
            self.assertEqual(int(fields[b"Content-Length"]), len(body))
        self.assertEqual(fields[b"Cache-Control"], b"no-store")
        return fields, body

    def _dashboard(self, route, *, expected=200, authenticated=True):
        headers = f"Cookie: {self.cookie}\r\n" if authenticated else ""
        return self._get(self.dashboard_handler, route, headers, expected=expected)

    def _quality(self, suffix="", *, expected=200, token=None):
        fields, body = self._get(
            self.api_handler, self.QUALITY + suffix,
            f"Authorization: Bearer {self.token if token is None else token}\r\n",
            expected=expected,
        )
        self.assertEqual(fields[b"Content-Type"], b"application/json")
        return json.loads(body)

    def _no_internal_errors(self):
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM error_events")["n"], 0)

    def _unavailable(self, suffix, code):
        payload = self._quality(suffix, expected=404)
        self.assertEqual(payload["code"], code)
        self.assertTrue(payload["error"])
        self.assertNotIn("score", payload)
        self.assertNotIn("targets", payload)
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM data_quality_snapshots")["n"], 0)

    def test_case_missing_or_blank_id_returns_400(self):
        for route in ("/case", "/case?id=", "/case?id=%20%09%0A"):
            with self.subTest(route=route):
                fields, body = self._dashboard(route, expected=400)
                self.assertEqual(fields[b"Content-Type"], b"text/html; charset=utf-8")
                self.assertIn(b"Case ID is required", body)
        self._no_internal_errors()

    def test_case_unknown_id_returns_404(self):
        for route in ("/case?id=missing", "/case?id=%3Cscript%3Ealert(1)%3C/script%3E"):
            with self.subTest(route=route):
                _, body = self._dashboard(route, expected=404)
                self.assertIn(b"Case not found", body)
                self.assertNotIn(b"<script>alert(1)</script>", body)
        self._no_internal_errors()

    def test_existing_case_still_renders_for_viewer(self):
        self._populated()
        for route in ("/case?id=CASE-1", "/case?id=%20CASE-1%20"):
            with self.subTest(route=route):
                _, body = self._dashboard(route)
                self.assertIn(b"Account disclosure case", body)
                self.assertIn(b"CASE-1", body)
        self._no_internal_errors()

    def test_dashboard_auth_precedes_input_validation(self):
        for route in ("/case", "/case?id=missing", "/evidence/export", "/evidence/export?alert_id=abc"):
            with self.subTest(route=route):
                fields, _ = self._dashboard(route, expected=303, authenticated=False)
                self.assertEqual(fields[b"Location"], b"/login")
        self._no_internal_errors()

    def test_export_missing_or_blank_selector_returns_400(self):
        for route in ("/evidence/export", "/evidence/export?target=", "/evidence/export?target=%20%09", "/evidence/export?alert_id="):
            with self.subTest(route=route):
                fields, body = self._dashboard(route, expected=400)
                self.assertIn(b"Target or alert ID is required", body)
                self.assertNotIn(b"Content-Disposition", fields)
        self._no_internal_errors()

    def test_export_invalid_alert_id_returns_400_without_target_fallback(self):
        for value in ("abc", "0", "-1", "1.5", "9223372036854775808"):
            for target in ("", "&target=example.com"):
                with self.subTest(value=value, target=target):
                    self._dashboard("/evidence/export?alert_id=" + value + target, expected=400)
        self._no_internal_errors()

    def test_export_unknown_alert_returns_404_without_target_fallback(self):
        for target in ("", "&target=example.com"):
            with self.subTest(target=target):
                self._dashboard("/evidence/export?alert_id=123" + target, expected=404)
        self._no_internal_errors()

    def _zip_payload(self, route):
        fields, body = self._dashboard(route)
        self.assertEqual(fields[b"Content-Type"], b"application/zip")
        self.assertIn(b"attachment;", fields[b"Content-Disposition"])
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            return json.loads(archive.read("evidence.json"))

    def test_export_valid_target_still_downloads_evidence(self):
        self._populated()
        for selector in ("target=example.com", "target=%20example.com%20&alert_id="):
            with self.subTest(selector=selector):
                payload = self._zip_payload("/evidence/export?" + selector + "&entity_type=asset&entity_value=api.example.com")
                self.assertEqual(payload["target"], "example.com")
                self.assertEqual(payload["assets"][0]["host"], "api.example.com")
        self._no_internal_errors()

    def test_export_valid_alert_does_not_require_target(self):
        self._populated()
        now = utc_now()
        alert_id = self.db.execute(
            "INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
            ("example.com", "offline-alert", "asset", "low", 10, "Fixture alert", "api.example.com", now, now),
        ).lastrowid
        payload = self._zip_payload(f"/evidence/export?alert_id={alert_id}")
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(payload["alert"]["id"], alert_id)
        self.assertEqual(payload["entity_type"], "alert")
        self.assertEqual(payload["assets"][0]["host"], "api.example.com")
        self._no_internal_errors()

    def test_unexpected_case_failure_remains_an_internal_error(self):
        self._populated()
        with patch.object(dashboard_core, "case_detail", side_effect=ReconError("unexpected case failure")):
            self._dashboard("/case?id=CASE-1", expected=500)
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM error_events")["n"], 1)

    def test_unexpected_export_failure_remains_an_internal_error(self):
        with patch.object(dashboard_core, "build_evidence_export", side_effect=ValueError("unexpected export failure")):
            self._dashboard("/evidence/export?target=example.com", expected=500)
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM error_events")["n"], 1)

    def test_quality_empty_database_returns_no_data_404(self):
        for suffix in ("", "?run_id=&target=", "?run_id=%20%09&target=%20%0A"):
            with self.subTest(suffix=suffix):
                self._unavailable(suffix, "no_completed_run")

    def test_quality_does_not_select_unfinished_runs(self):
        now = utc_now()
        for status in ("running", "failed"):
            self.db.execute(
                "INSERT INTO runs(id,version,status,started_at,target_selector,target_count) VALUES(?,?,?,?,?,?)",
                (status, APP_VERSION, status, now, "example.com", 1),
            )
        self._unavailable("", "no_completed_run")

    def test_quality_unknown_run_returns_404(self):
        self._populated()
        for suffix in ("?run_id=missing", "?run_id=missing&target=example.com"):
            with self.subTest(suffix=suffix):
                self._unavailable(suffix, "run_not_found")

    def test_quality_target_without_completed_run_returns_404(self):
        self._populated()
        self._unavailable("?target=other.example", "no_completed_run")

    def test_quality_target_outside_explicit_run_returns_404(self):
        self._populated()
        self._unavailable("?run_id=RUN-1&target=other.example", "target_not_in_run")

    def test_quality_run_without_targets_returns_404(self):
        self._populated()
        self.db.execute("DELETE FROM run_targets WHERE run_id='RUN-1'")
        self._unavailable("?run_id=RUN-1", "run_targets_unavailable")

    def test_quality_valid_requests_preserve_snapshot_and_do_not_persist(self):
        self._populated()
        for suffix, target in (("", None), ("?run_id=RUN-1&target=example.com", "example.com"), ("?run_id=%20RUN-1%20&target=%20example.com%20", "example.com")):
            with self.subTest(suffix=suffix):
                expected = data_quality_snapshot(self.db, "RUN-1", target, persist=False)
                actual = self._quality(suffix)
                expected.pop("generated_at")
                actual.pop("generated_at")
                self.assertEqual(actual, expected)
                self.assertGreater(actual["score"], 0)
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM data_quality_snapshots")["n"], 0)

    def test_quality_explicit_incomplete_run_remains_available(self):
        self._populated()
        self.db.execute("UPDATE runs SET status='running',finished_at=NULL WHERE id='RUN-1'")
        self.db.execute("UPDATE stage_runs SET status='running' WHERE run_id='RUN-1' AND stage='urls'")
        payload = self._quality("?run_id=RUN-1&target=example.com")
        self.assertEqual(payload["run_id"], "RUN-1")
        self.assertEqual(payload["targets"]["example.com"]["metrics"]["stage_status"]["urls"], "running")
        self.assertIn("incomplete_stages", {spot["code"] for spot in payload["blind_spots"]})

    def test_quality_auth_precedes_no_data_validation(self):
        for token in ("", "invalid"):
            with self.subTest(token=token):
                payload = self._quality(expected=401, token=token)
                self.assertNotIn("code", payload)
        worker_token = api.create_token(self.db, "offline-worker", "worker")
        self._quality(expected=401, token=worker_token)

    def test_quality_unexpected_failures_are_not_reported_as_no_data(self):
        for error in (ReconError("unexpected quality failure"), sqlite3.OperationalError("database unavailable")):
            with self.subTest(error=error):
                with patch.object(api, "data_quality_snapshot", side_effect=error):
                    with self.assertRaises(type(error)):
                        self._quality()

    def test_quality_missing_inputs_do_not_persist_or_audit_a_snapshot(self):
        def reject(run_id, target, code):
            before = self.db.one("SELECT COUNT(*) n FROM audit_log")["n"]
            with self.assertRaises(ReconError) as raised:
                data_quality_snapshot(self.db, run_id, target)
            self.assertEqual(raised.exception.code, code)
            self.assertEqual(self.db.one("SELECT COUNT(*) n FROM data_quality_snapshots")["n"], 0)
            self.assertEqual(self.db.one("SELECT COUNT(*) n FROM audit_log")["n"], before)

        reject(None, None, "no_completed_run")
        self._populated()
        reject("missing", None, "run_not_found")
        reject("RUN-1", "other.example", "target_not_in_run")
        self.db.execute("DELETE FROM run_targets WHERE run_id='RUN-1'")
        reject("RUN-1", None, "run_targets_unavailable")

    def test_platform_sync_continues_without_legacy_run_target_records(self):
        self._populated()
        self.db.execute("DELETE FROM run_targets WHERE run_id='RUN-1'")
        result = platform_v6.platform_v6_sync(self.paths, self.db, run_id="RUN-1", analysis_id="AN-1")
        quality = result["data_quality"]
        self.assertTrue(quality["unavailable"])
        self.assertEqual(quality["code"], "run_targets_unavailable")
        self.assertEqual(quality["run_id"], "RUN-1")
        self.assertNotIn("score", quality)
        self.assertGreater(result["review_rankings"], 0)
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM data_quality_snapshots")["n"], 0)

    def test_platform_sync_does_not_hide_unexpected_quality_failures(self):
        self._populated()
        with patch.object(platform_v6, "data_quality_snapshot", side_effect=sqlite3.OperationalError("database unavailable")):
            with self.assertRaises(sqlite3.OperationalError):
                platform_v6.platform_v6_sync(self.paths, self.db, run_id="RUN-1", analysis_id="AN-1")


if __name__ == "__main__":
    unittest.main()
