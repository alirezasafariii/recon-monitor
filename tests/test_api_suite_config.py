from __future__ import annotations

import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import api_server
import api_server_core as api
import test_platform_v60 as platform_fixture
from core import AppPaths, Config, Database, ReconError, utc_now
from platform_v6 import set_revalidation_policy


class MemoryRequest:
    """Feed a real HTTP handler without opening a socket or mocking dispatch."""

    def __init__(self, data: bytes):
        self.input = io.BytesIO(data)
        self.output = io.BytesIO()

    def makefile(self, mode, _buffering):
        if mode != "rb":
            raise AssertionError(f"Unexpected stream mode: {mode}")
        return self.input

    def sendall(self, data):
        self.output.write(data)


class APISuiteConfigTests(unittest.TestCase):
    SCHEDULE = "/api/v1/suite/scheduled-run"
    REVALIDATION = "/api/v1/suite/revalidation-process"
    MARKER = "RECON_API_SUITE_CONFIG_TEST"

    def setUp(self):
        for name in (
            "subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect",
            "socket.socket.connect_ex", "socket.socket.bind", "urllib.request.urlopen",
        ):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        environment = patch.dict(os.environ, {"I_HAVE_AUTHORIZATION": "yes", "TELEGRAM_ENABLED": "no"})
        environment.start()
        os.environ.pop(self.MARKER, None)
        self.addCleanup(environment.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.paths = AppPaths.from_root(Path(temp.name))
        self.paths.ensure()
        self._config(self.paths, "first-file-value")
        self.db = Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.token = api.create_token(self.db, "offline-admin", "admin")
        self.handler = self._bound_handler(self.paths)

    def _config(self, paths, marker):
        paths.config.write_text(f'I_HAVE_AUTHORIZATION="yes"\nTELEGRAM_ENABLED="no"\n{self.MARKER}="{marker}"\n', encoding="utf-8")

    def _bound_handler(self, paths):
        # Use the public server entry point's actual class binding. Only the
        # listener is replaced, keeping API signatures and request behavior real.
        with patch.object(api, "ControlledAPIHTTPServer") as factory:
            api_server.serve_api(paths, Mock(), "127.0.0.1", 0)
        factory.return_value.serve_forever.assert_called_once_with(poll_interval=.5)
        factory.return_value.server_close.assert_called_once()
        return factory.call_args.args[1]

    def _post(self, route, payload, *, token=None, handler=None, authorization=None, expected=200):
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        header = authorization if authorization is not None else "Bearer " + (token or self.token)
        request = (
            f"POST {route} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {header}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(encoded)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii") + encoded
        stream = MemoryRequest(request)
        (handler or self.handler)(stream, ("127.0.0.1", 0), Mock())
        headers, separator, body = stream.output.getvalue().partition(b"\r\n\r\n")
        self.assertTrue(separator, "API did not send an HTTP response")
        self.assertEqual(int(headers.split(b"\r\n", 1)[0].split()[1]), expected)
        fields = dict(line.split(b": ", 1) for line in headers.split(b"\r\n")[1:])
        self.assertEqual(int(fields[b"Content-Length"]), len(body))
        self.assertEqual(fields[b"Content-Type"], b"application/json")
        self.assertEqual(fields[b"Cache-Control"], b"no-store")
        return json.loads(body)

    def _case_project(self):
        temp, paths, db = platform_fixture.PlatformV60Tests().project()
        self.addCleanup(temp.cleanup)
        self.addCleanup(db.close)
        token = api.create_token(db, "offline-case-admin", "admin")
        set_revalidation_policy(db, "CASE-1", "interval", interval_days=1, actor="fixture")
        db.execute("UPDATE revalidation_policies SET next_due_at='2000-01-01T00:00:00Z' WHERE case_id='CASE-1'")
        return paths, db, token, self._bound_handler(paths)

    def test_scheduled_run_reaches_real_dry_run_with_policy_budgets(self):
        now = utc_now()
        self.db.execute(
            "INSERT INTO schedule_policies(target,cadence,enabled,max_runtime_minutes,request_budget,quiet_hours,created_at,updated_at) VALUES('example.test','3h',1,17,123,'',?,?)",
            (now, now),
        )
        result = self._post(self.SCHEDULE, {"target": "example.test", "dry_run": True})
        self.assertEqual(result["status"], "planned")
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["max_runtime_minutes"], 17)
        self.assertEqual(result["request_budget"], 123)
        self.assertIsNone(self.db.one("SELECT last_run_at FROM schedule_policies")[0])
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM runs")[0], 0)

    def test_revalidation_process_executes_real_offline_plan_and_records_actor(self):
        paths, db, token, handler = self._case_project()
        result = self._post(self.REVALIDATION, {"limit": 1, "execute_offline": True}, token=token, handler=handler)
        self.assertEqual((result["due"], result["processed"], result["execute_offline"]), (1, 1, True))
        item = result["items"][0]
        self.assertEqual(item["network_requests"], 0)
        plan = db.one("SELECT level,created_by FROM validation_plans WHERE plan_id=?", (item["plan_id"],))
        self.assertEqual(tuple(plan), ("offline", "offline-case-admin"))
        run = db.one("SELECT executed_by FROM validation_runs WHERE run_id=?", (item["validation_run_id"],))
        self.assertEqual(run[0], "offline-case-admin")
        self.assertIsNotNone(db.one("SELECT 1 FROM validation_intelligence WHERE validation_run_id=?", (item["validation_run_id"],)))
        audit = db.one("SELECT actor FROM audit_log WHERE action='due_revalidations_processed'")
        self.assertEqual(audit[0], "offline-case-admin")

    def test_revalidation_can_prepare_without_executing_offline_plan(self):
        _paths, db, token, handler = self._case_project()
        before = db.one("SELECT COUNT(*) FROM validation_runs")[0]
        result = self._post(self.REVALIDATION, {"execute_offline": "false"}, token=token, handler=handler)
        self.assertEqual(result["processed"], 1)
        self.assertFalse(result["execute_offline"])
        self.assertNotIn("validation_run_id", result["items"][0])
        self.assertEqual(db.one("SELECT COUNT(*) FROM validation_runs")[0], before)
        self.assertEqual(db.one("SELECT level FROM validation_plans WHERE plan_id=?", (result["items"][0]["plan_id"],))[0], "offline")

    def test_scheduled_dispatch_preserves_defaults_target_and_dry_run_flags(self):
        cases = [({}, "", False), ({"target": "example.test", "dry_run": "false"}, "example.test", False), ({"target": "example.test", "dry_run": "true"}, "example.test", True)]
        with patch.object(api, "run_scheduled_workflow", return_value={"marker": "سلام"}) as workflow:
            for payload, target, dry_run in cases:
                with self.subTest(payload=payload):
                    self.assertEqual(self._post(self.SCHEDULE + "?request=offline", payload), {"marker": "سلام"})
                    paths, config, _db, selected_target = workflow.call_args.args
                    self.assertEqual(paths, self.paths)
                    self.assertIsInstance(config, Config)
                    self.assertEqual(config.paths, self.paths)
                    self.assertEqual(selected_target, target)
                    self.assertEqual(workflow.call_args.kwargs, {"dry_run": dry_run, "actor": "offline-admin"})

    def test_revalidation_dispatch_preserves_defaults_limits_and_execution_flags(self):
        cases = [({}, 50, True), ({"limit": "7", "execute_offline": "false"}, 7, False), ({"limit": "invalid", "execute_offline": False}, 50, False)]
        with patch.object(api, "process_due_revalidations", return_value={"processed": 0}) as workflow:
            for payload, limit, execute in cases:
                with self.subTest(payload=payload):
                    self.assertEqual(self._post(self.REVALIDATION, payload), {"processed": 0})
                    paths, config, _db = workflow.call_args.args
                    self.assertEqual(paths, self.paths)
                    self.assertIsInstance(config, Config)
                    self.assertEqual(config.paths, self.paths)
                    self.assertEqual(workflow.call_args.kwargs, {"limit": limit, "execute_offline": execute, "actor": "offline-admin"})

    def test_both_routes_reload_config_for_each_request(self):
        def observe(_paths, config, _db, *_args, **_kwargs):
            return {"marker": config.get(self.MARKER)}

        with patch.object(api, "run_scheduled_workflow", side_effect=observe), patch.object(api, "process_due_revalidations", side_effect=observe):
            for marker in ("first-file-value", "updated-file-value"):
                self._config(self.paths, marker)
                for route in (self.SCHEDULE, self.REVALIDATION):
                    with self.subTest(marker=marker, route=route):
                        self.assertEqual(self._post(route, {}), {"marker": marker})

    def test_both_routes_honor_supported_environment_overrides(self):
        def observe(_paths, config, _db, *_args, **_kwargs):
            return {"marker": config.get(self.MARKER)}

        with patch.dict(os.environ, {self.MARKER: "process-value"}), patch.object(api, "run_scheduled_workflow", side_effect=observe), patch.object(api, "process_due_revalidations", side_effect=observe):
            for route in (self.SCHEDULE, self.REVALIDATION):
                with self.subTest(route=route):
                    self.assertEqual(self._post(route, {}), {"marker": "process-value"})

    def test_api_installations_use_their_own_project_config(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        self._config(paths, "second-installation")
        db = Database(paths.db)
        self.addCleanup(db.close)
        token = api.create_token(db, "second-admin", "admin")
        handler = self._bound_handler(paths)

        def observe(selected_paths, config, _db, *_args, **_kwargs):
            self.assertEqual(config.paths, selected_paths)
            return {"marker": config.get(self.MARKER)}

        with patch.object(api, "run_scheduled_workflow", side_effect=observe), patch.object(api, "process_due_revalidations", side_effect=observe):
            for route in (self.SCHEDULE, self.REVALIDATION):
                self.assertEqual(self._post(route, {}, token=token, handler=handler), {"marker": "second-installation"})
                self.assertEqual(self._post(route, {}), {"marker": "first-file-value"})

    def test_lead_analyst_with_operations_scope_can_dispatch_both_routes(self):
        token = api.create_token(self.db, "offline-operator", "lead_analyst", ["operations"])
        with patch.object(api, "run_scheduled_workflow", return_value={"ok": True}) as schedule, patch.object(api, "process_due_revalidations", return_value={"ok": True}) as revalidate:
            for route, workflow in ((self.SCHEDULE, schedule), (self.REVALIDATION, revalidate)):
                self.assertEqual(self._post(route, {}, token=token), {"ok": True})
                self.assertEqual(workflow.call_args.kwargs["actor"], "offline-operator")

    def _assert_denied(self, tokens=None, headers=None):
        with patch.object(api, "Config", wraps=Config) as config, patch.object(api, "run_scheduled_workflow") as schedule, patch.object(api, "process_due_revalidations") as revalidate:
            for route in (self.SCHEDULE, self.REVALIDATION):
                for token in tokens or []:
                    self.assertEqual(self._post(route, {}, token=token, expected=401), {"error": "unauthorized"})
                for header in headers or []:
                    self.assertEqual(self._post(route, {}, authorization=header, expected=401), {"error": "unauthorized"})
            config.assert_not_called()
            schedule.assert_not_called()
            revalidate.assert_not_called()

    def test_missing_or_invalid_token_never_loads_config_or_dispatches(self):
        self._assert_denied(headers=["", "Basic invalid", "Bearer invalid"])

    def test_role_and_scope_gate_precedes_config_and_operations(self):
        tokens = [api.create_token(self.db, "restricted-" + role, role) for role in ("viewer", "analyst", "worker")]
        tokens.append(api.create_token(self.db, "admin-without-operations", "admin", ["read", "write"]))
        self._assert_denied(tokens=tokens)

    def test_revoked_or_expired_operations_tokens_cannot_dispatch(self):
        revoked = api.create_token(self.db, "revoked-admin", "admin")
        expired = api.create_token(self.db, "expired-admin", "admin")
        self.db.execute("UPDATE api_tokens SET revoked_at=? WHERE name='revoked-admin'", (utc_now(),))
        self.db.execute("UPDATE api_tokens SET expires_at='2000-01-01T00:00:00Z' WHERE name='expired-admin'")
        self._assert_denied(tokens=[revoked, expired])

    def test_workflow_errors_close_auth_and_request_databases(self):
        connections = []

        def connect(path):
            db = Database(path)
            connections.append(db)
            self.addCleanup(db.close)
            return db

        with patch.object(api, "Database", side_effect=connect), patch.object(api, "run_scheduled_workflow", side_effect=ReconError("offline workflow failure")), patch.object(api, "process_due_revalidations", side_effect=ReconError("offline workflow failure")):
            for route in (self.SCHEDULE, self.REVALIDATION):
                with self.assertRaisesRegex(ReconError, "offline workflow failure"):
                    self._post(route, {})
        self.assertEqual(len(connections), 4)
        for db in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                db.conn.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
