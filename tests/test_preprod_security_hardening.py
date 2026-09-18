from __future__ import annotations

import datetime as dt
import hashlib
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import remote_worker
from api_server_core import (
    _request_scope,
    _role_allows,
    create_token,
)
from core import AppPaths, CommandRunner, Database, redact_command_args
from session_auth import (
    create_session,
    create_user,
    disable_user,
    parse_session,
)


class PreProductionSecurityHardeningTests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        paths = AppPaths.from_root(root)
        paths.ensure()
        paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\n',
            encoding="utf-8",
        )
        return temp, paths, Database(paths.db)

    def test_command_logging_redacts_secret_headers_flags_and_query_values(self):
        args = [
            "httpx",
            "-H",
            "Authorization: Bearer REAL_BEARER",
            "-H",
            "Accept: application/json",
            "--api-key",
            "REAL_API_KEY",
            "https://example.test/api?token=REAL_QUERY&safe=1",
        ]
        redacted = redact_command_args(args)
        encoded = " ".join(redacted)
        self.assertNotIn("REAL_BEARER", encoded)
        self.assertNotIn("REAL_API_KEY", encoded)
        self.assertNotIn("REAL_QUERY", encoded)
        self.assertIn("Authorization: <redacted>", encoded)
        self.assertIn("Accept: application/json", encoded)
        source = inspect.getsource(CommandRunner.run)
        self.assertIn("redact_command_args(args)", source)
        self.assertNotIn('" ".join(args)', source)
        self.assertGreaterEqual(source.count("command=display_command"), 3)

    def test_disable_user_revokes_existing_session(self):
        temp, paths, db = self.project()
        try:
            create_user(paths, "alice", "very-secure-password", "analyst")
            session = create_session(paths, "alice", "analyst")
            self.assertIsNotNone(
                parse_session(paths, f"recon_session={session.token}")
            )
            disable_user(paths, "alice")
            self.assertIsNone(
                parse_session(paths, f"recon_session={session.token}")
            )
        finally:
            db.close()
            temp.cleanup()

    def test_role_or_password_update_revokes_existing_session(self):
        temp, paths, db = self.project()
        try:
            create_user(paths, "alice", "very-secure-password", "analyst")
            session = create_session(paths, "alice", "analyst")
            create_user(paths, "alice", "new-secure-password", "viewer")
            self.assertIsNone(
                parse_session(paths, f"recon_session={session.token}")
            )
            replacement = create_session(paths, "alice", "viewer")
            parsed = parse_session(
                paths,
                f"recon_session={replacement.token}",
            )
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed.role, "viewer")
        finally:
            db.close()
            temp.cleanup()

    def test_worker_and_analyst_roles_are_incomparable(self):
        self.assertFalse(_role_allows("analyst", "worker"))
        self.assertFalse(_role_allows("worker", "analyst"))
        self.assertTrue(_role_allows("admin", "worker"))
        self.assertTrue(_role_allows("lead_analyst", "analyst"))

    def test_sensitive_api_routes_require_dedicated_scopes(self):
        self.assertEqual(
            _request_scope("POST", "/api/v1/work/claim"),
            "worker",
        )
        self.assertEqual(
            _request_scope("POST", "/api/v1/validation/run"),
            "validation",
        )
        self.assertEqual(
            _request_scope("POST", "/api/v1/suite/retention-apply"),
            "operations",
        )
        self.assertEqual(
            _request_scope("POST", "/api/v1/analysis/candidates/decision"),
            "write",
        )
        self.assertEqual(
            _request_scope("GET", "/api/v1/assets"),
            "read",
        )

    def test_worker_token_defaults_to_worker_scope_and_cannot_be_analyst_scoped(self):
        temp, paths, db = self.project()
        try:
            create_token(db, "worker-a", "worker")
            row = db.one(
                "SELECT role,scopes_json FROM api_tokens WHERE name=?",
                ("worker-a",),
            )
            self.assertEqual(row["role"], "worker")
            self.assertEqual(json.loads(row["scopes_json"]), ["worker"])
            with self.assertRaises(Exception):
                create_token(db, "bad-worker", "worker", ["read", "write"])
            with self.assertRaises(Exception):
                create_token(db, "bad-analyst", "analyst", ["worker"])
        finally:
            db.close()
            temp.cleanup()

    def test_work_result_requires_same_worker_and_valid_lease(self):
        temp, paths, db = self.project()
        try:
            work_id = db.enqueue_work(
                "run",
                "example.test",
                "remote",
                "item",
                {"kind": "http_head"},
            )
            lease_token = "lease-secret"
            lease_hash = hashlib.sha256(lease_token.encode()).hexdigest()
            expires = (
                dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            self.assertTrue(
                db.work_start(
                    work_id,
                    "worker-a",
                    lease_token_hash=lease_hash,
                    lease_expires_at=expires,
                )
            )
            self.assertFalse(
                db.work_finish(
                    work_id,
                    {"ok": True},
                    worker_id="worker-b",
                    lease_token_hash=lease_hash,
                )
            )
            self.assertFalse(
                db.work_finish(
                    work_id,
                    {"ok": True},
                    worker_id="worker-a",
                    lease_token_hash="wrong",
                )
            )
            self.assertTrue(
                db.work_finish(
                    work_id,
                    {"ok": True},
                    worker_id="worker-a",
                    lease_token_hash=lease_hash,
                )
            )
        finally:
            db.close()
            temp.cleanup()

    def test_expired_remote_work_lease_is_reclaimed_without_touching_local_work(self):
        temp, paths, db = self.project()
        try:
            remote_id = db.enqueue_work(
                "run",
                "example.test",
                "remote",
                "remote-item",
                {"kind": "http_head"},
            )
            local_id = db.enqueue_work(
                "run",
                "example.test",
                "local",
                "local-item",
                {"kind": "http_head"},
            )
            expired = "2000-01-01T00:00:00Z"
            self.assertTrue(
                db.work_start(
                    remote_id,
                    "worker-a",
                    lease_token_hash=hashlib.sha256(b"lease").hexdigest(),
                    lease_expires_at=expired,
                )
            )
            self.assertTrue(db.work_start(local_id, "local-worker"))
            reclaimed = db.reclaim_expired_work_leases(
                "2026-09-18T00:00:00Z"
            )
            self.assertEqual(reclaimed, 1)
            remote = db.one(
                "SELECT status,worker_id,lease_token_hash,lease_expires_at "
                "FROM work_items WHERE id=?",
                (remote_id,),
            )
            local = db.one(
                "SELECT status,worker_id,lease_token_hash,lease_expires_at "
                "FROM work_items WHERE id=?",
                (local_id,),
            )
            self.assertEqual(remote["status"], "retry_pending")
            self.assertIsNone(remote["worker_id"])
            self.assertIsNone(remote["lease_token_hash"])
            self.assertIsNone(remote["lease_expires_at"])
            self.assertEqual(local["status"], "running")
            self.assertEqual(local["worker_id"], "local-worker")
        finally:
            db.close()
            temp.cleanup()

    def test_remote_download_uses_shared_pinned_transport(self):
        transport_result = {
            "final_url": "https://cdn.example.test/app.js",
            "status_code": 200,
            "headers": {"Content-Type": "application/javascript"},
            "data": b"x",
            "error": "",
            "transport_status": "ok",
            "redirect_outside_scope": False,
            "transport_hops": [],
            "resolved_addresses": ["93.184.216.34"],
            "pinned_address": "93.184.216.34",
            "dns_rebinding_protection": "resolution_pinned_each_hop",
            "environment_proxy_used": False,
        }
        with mock.patch.object(
            remote_worker,
            "perform_pinned_download",
            return_value=transport_result,
        ) as transport:
            result = remote_worker.execute_task(
                {
                    "kind": "download_url",
                    "url": "https://cdn.example.test/app.js",
                    "allowed_roots": ["example.test"],
                }
            )
        transport.assert_called_once()
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["pinned_address"], "93.184.216.34")
        self.assertFalse(result["environment_proxy_used"])

    def test_remote_head_repins_each_in_scope_redirect_and_blocks_scope_escape(self):
        in_scope_redirect = {
            "status_code": 302,
            "headers": {"location": "https://b.example.test/final"},
            "error": "http_error",
            "resolved_addresses": ["93.184.216.34"],
            "pinned_address": "93.184.216.34",
            "dns_rebinding_protection": "resolution_pinned",
            "environment_proxy_used": False,
        }
        final = {
            "status_code": 200,
            "headers": {"content-type": "text/html"},
            "error": "",
            "resolved_addresses": ["93.184.216.35"],
            "pinned_address": "93.184.216.35",
            "dns_rebinding_protection": "resolution_pinned",
            "environment_proxy_used": False,
        }
        with mock.patch.object(
            remote_worker,
            "perform_pinned_request",
            side_effect=[(in_scope_redirect, "ok"), (final, "ok")],
        ) as transport:
            result = remote_worker.execute_task(
                {
                    "kind": "http_head",
                    "url": "https://a.example.test/start",
                    "allowed_roots": ["example.test"],
                }
            )
        self.assertEqual(transport.call_count, 2)
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["pinned_address"], "93.184.216.35")

        outside_redirect = {
            **in_scope_redirect,
            "headers": {"location": "https://outside.test/private"},
        }
        with mock.patch.object(
            remote_worker,
            "perform_pinned_request",
            return_value=(outside_redirect, "ok"),
        ) as transport:
            blocked = remote_worker.execute_task(
                {
                    "kind": "http_head",
                    "url": "https://a.example.test/start",
                    "allowed_roots": ["example.test"],
                }
            )
        self.assertEqual(transport.call_count, 1)
        self.assertTrue(blocked["redirect_outside_scope"])
        self.assertEqual(blocked["transport_status"], "stopped_for_safety")


if __name__ == "__main__":
    unittest.main()
