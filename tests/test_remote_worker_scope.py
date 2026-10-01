from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import remote_worker
from api_server_core import APIHandler, create_token
from core import AppPaths, Config, Logger, ReconError, TargetPolicy
from recon_monitor_core import Database
from stages import StageContext, stage_endpoint_validation, stage_javascript


class RemoteWorkerScopeTests(unittest.TestCase):
    START = "https://public.example.test/app.js"

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.policy = TargetPolicy.from_dict({
            "name": "example.test", "roots": ["example.test"],
            "exclude": [r"(^|\.)private\.example\.test$"],
        })

    def _scope(self, policy=None):
        policy = policy or self.policy
        return {"version": 1, "target": policy.name, "roots": list(policy.roots),
                "include": list(policy.include), "exclude": list(policy.exclude)}

    def _payload(self, kind="download_url", url=None, policy=None):
        return {"kind": kind, "url": url or self.START, "scope_policy": self._scope(policy)}

    def _transport(self, payload, locations):
        """Exercise the real shared transport with fake DNS and pinned openers."""
        opened = []

        def open_request(request, **_kwargs):
            opened.append(request.full_url)
            index = len(opened) - 1
            if index < len(locations):
                raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": locations[index]}, io.BytesIO())
            response = MagicMock()
            response.status = 200
            response.headers = {"Content-Type": "application/javascript"}
            response.read.return_value = b"const value = 1;"
            response.__enter__.return_value = response
            return response

        with patch("safe_transport.resolve_public_addresses", return_value=(True, ["93.184.216.34"])) as resolve, patch(
            "safe_transport.build_pinned_opener", return_value=SimpleNamespace(open=open_request),
        ):
            result = remote_worker.execute_task(payload)
        return result, opened, resolve.call_args_list

    def test_excluded_initial_url_is_rejected_before_transport(self):
        for kind in remote_worker.WORKER_CAPABILITIES:
            with self.subTest(kind=kind), patch("remote_worker.perform_pinned_request") as head, patch("remote_worker.perform_pinned_download") as download:
                payload = self._payload(kind, "https://private.example.test/secret.js")
                payload["allowed_roots"] = ["example.test"]
                with self.assertRaises(ReconError):
                    remote_worker.execute_task(payload)
                head.assert_not_called()
                download.assert_not_called()

    def test_include_restriction_is_applied_before_transport(self):
        policy = TargetPolicy.from_dict({"roots": ["example.test"], "include": [r"^public\.example\.test$"]})
        for kind in remote_worker.WORKER_CAPABILITIES:
            with self.subTest(kind=kind), self.assertRaises(ReconError):
                remote_worker.execute_task(self._payload(kind, "https://other.example.test/app.js", policy))

    def test_permissive_include_cannot_expand_the_declared_root_boundary(self):
        policy = TargetPolicy.from_dict({"roots": ["example.test"], "include": [".*"]})
        for kind in remote_worker.WORKER_CAPABILITIES:
            for host in ("outside.test", "example.test.evil.test", "evilexample.test"):
                with self.subTest(kind=kind, host=host), self.assertRaises(ReconError):
                    remote_worker.execute_task(self._payload(kind, "https://" + host + "/", policy))

    def test_head_redirect_checks_exclude_and_include_before_next_dns_lookup(self):
        cases = [(self.policy, "https://private.example.test/secret"),
                 (TargetPolicy.from_dict({"roots": ["example.test"], "include": [r"^public\.example\.test$"]}), "https://other.example.test/secret")]
        for policy, destination in cases:
            with self.subTest(destination=destination):
                payload = self._payload("http_head", policy=policy)
                payload["allowed_roots"] = ["example.test"]
                result, opened, lookups = self._transport(payload, [destination])
                self.assertEqual(opened, [self.START])
                self.assertEqual(len(lookups), 1)
                self.assertTrue(result["redirect_outside_scope"])
                self.assertEqual(result["transport_status"], "stopped_for_safety")

    def test_download_redirect_checks_exclude_and_include_before_next_dns_lookup(self):
        cases = [(self.policy, "https://private.example.test/secret.js"),
                 (TargetPolicy.from_dict({"roots": ["example.test"], "include": [r"^public\.example\.test$"]}), "https://other.example.test/app.js")]
        for policy, destination in cases:
            with self.subTest(destination=destination):
                payload = self._payload(policy=policy)
                payload["allowed_roots"] = ["example.test"]
                result, opened, lookups = self._transport(payload, [destination])
                self.assertEqual(opened, [self.START])
                self.assertEqual(len(lookups), 1)
                self.assertTrue(result["redirect_outside_scope"])
                self.assertEqual(result["transport_status"], "stopped_for_safety")

    def test_scope_is_checked_on_later_redirect_hops(self):
        for kind in remote_worker.WORKER_CAPABILITIES:
            with self.subTest(kind=kind):
                result, opened, lookups = self._transport(self._payload(kind), ["/next.js", "https://private.example.test/secret.js"])
                self.assertEqual(opened, [self.START, "https://public.example.test/next.js"])
                self.assertEqual(len(lookups), 2)
                self.assertEqual(result["transport_status"], "stopped_for_safety")

    def test_allowed_redirects_still_work_and_repin_each_hop(self):
        for kind in remote_worker.WORKER_CAPABILITIES:
            with self.subTest(kind=kind):
                result, opened, lookups = self._transport(self._payload(kind), ["/next.js", "https://cdn.example.test/final.js"])
                self.assertEqual(len(opened), 3)
                self.assertEqual([call.args[0] for call in lookups], ["public.example.test", "public.example.test", "cdn.example.test"])
                self.assertEqual(result["status_code"], 200)
                self.assertEqual(result["url"], "https://cdn.example.test/final.js")
                self.assertEqual(result["transport_status"], "ok")
                self.assertFalse(result["environment_proxy_used"])

    def test_missing_malformed_or_unsupported_scope_is_rejected_without_fallback(self):
        scopes = [None, [], {}, {**self._scope(), "version": 2}, {**self._scope(), "version": True},
                  {**self._scope(), "roots": "example.test"}, {**self._scope(), "roots": []},
                  {**self._scope(), "roots": ["invalid/root"]}, {**self._scope(), "include": []},
                  {**self._scope(), "include": ["["]}, {**self._scope(), "exclude": "private"},
                  {**self._scope(), "exclude": [123]}, {**self._scope(), "target": ""}]
        for missing in ("target", "roots", "include", "exclude", "version"):
            scope = self._scope()
            del scope[missing]
            scopes.append(scope)
        for scope in scopes:
            with self.subTest(scope=scope), patch("remote_worker.perform_pinned_download") as transport:
                payload = self._payload()
                payload.update(scope_policy=scope, allowed_roots=["example.test"])
                with self.assertRaises(ReconError):
                    remote_worker.execute_task(payload)
                transport.assert_not_called()

    def test_legacy_roots_only_task_is_rejected_before_transport(self):
        with patch("remote_worker.perform_pinned_download") as transport, self.assertRaises(ReconError):
            remote_worker.execute_task({"kind": "download_url", "url": self.START, "allowed_roots": ["example.test"]})
        transport.assert_not_called()

    def test_worker_registration_advertises_scope_contract(self):
        with patch("remote_worker._request", side_effect=[{"worker_id": "worker"}, {"ok": True}, {"work": None}]) as request:
            self.assertEqual(remote_worker.run_worker("https://control.test", "offline", "worker", once=True), 0)
        registration = request.call_args_list[0].args[3]
        self.assertEqual(registration["metadata"]["scope_policy_versions"], [1])

    def _context(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        paths = AppPaths.from_root(Path(tmp.name))
        paths.ensure()
        db = Database(paths.db)
        self.addCleanup(db.close)
        run_id = db.create_run(self.policy.name, 1, "offline")
        run_dir = paths.output / run_id
        db.create_run_target(run_id, self.policy, run_dir, True)
        return StageContext(paths, Config(paths), self.policy, db, Logger(paths), SimpleNamespace(), MagicMock(), run_id, run_dir, False)

    def test_javascript_queue_carries_effective_scope_without_headers_or_legacy_roots(self):
        self.policy = TargetPolicy.from_dict({"name": "example.test", "roots": ["example.test"]}, {
            "exclude": [r"(^|\.)private\.example\.test$"], "headers": {"Authorization": "Bearer offline-secret"},
        })
        ctx = self._context()
        (ctx.current / "urls.txt").write_text(self.START + "\n")
        (ctx.current / "url-collection.json").write_text(json.dumps({"run_id": ctx.run_id, "target": self.policy.name, "metrics": {"collection_status": "completed"}}))
        with patch("stages._download_url", return_value={"url": self.START, "status_code": 404, "not_found": True}):
            stage_javascript(ctx)
        payload = json.loads(ctx.db.one("SELECT payload_json FROM work_items WHERE stage='javascript-items'")[0])
        self.assertEqual(payload["scope_policy"], self._scope())
        self.assertNotIn("allowed_roots", payload)
        self.assertNotIn("offline-secret", json.dumps(payload))

    def test_endpoint_validation_queue_carries_effective_scope_and_sources(self):
        ctx = self._context()
        self.policy.modules["endpoint_validation"] = True
        ctx.db.upsert_endpoint_intelligence(self.policy.name, self.START, "url", {"confidence": 90}, "https://public.example.test/source.js", ctx.run_id)
        with patch("stages._safe_validate_endpoint", return_value={"endpoint": self.START, "resolved_url": self.START, "reachable": False}):
            stage_endpoint_validation(ctx)
        payload = json.loads(ctx.db.one("SELECT payload_json FROM work_items WHERE stage='endpoint-validation-items'")[0])
        self.assertEqual(payload["scope_policy"], self._scope())
        self.assertEqual(payload["sources"], ["https://public.example.test/source.js"])
        self.assertNotIn("allowed_roots", payload)

    def _api(self, paths, token, route, payload):
        handler = object.__new__(APIHandler)
        handler.paths = paths
        handler.path = route
        handler.command = "POST"
        encoded = json.dumps(payload).encode()
        handler.headers = {"Authorization": "Bearer " + token, "Content-Length": str(len(encoded))}
        handler.rfile = io.BytesIO(encoded)
        handler.send_json = MagicMock()
        handler.do_POST()
        response = handler.send_json.call_args
        self.assertEqual(response.args[1] if len(response.args) > 1 else 200, 200)
        return response.args[0]

    def _register(self, ctx, *, versions=None):
        token = create_token(ctx.db, "offline-worker", "worker")
        metadata = {} if versions is None else {"scope_policy_versions": versions}
        self._api(ctx.paths, token, "/api/v1/workers/register", {
            "worker_id": "worker", "capabilities": ["http_head", "download_url"], "metadata": metadata,
        })
        return token

    def test_api_does_not_assign_scoped_tasks_to_legacy_workers(self):
        for versions in (None, [2], [True], "1"):
            with self.subTest(versions=versions):
                ctx = self._context()
                token = self._register(ctx, versions=versions)
                ctx.db.enqueue_work(ctx.run_id, self.policy.name, "remote", "item", self._payload())
                response = self._api(ctx.paths, token, "/api/v1/work/claim", {"worker_id": "worker"})
                self.assertIsNone(response["work"])
                self.assertEqual(ctx.db.work_status(ctx.run_id, self.policy.name, "remote", "item"), "queued")

    def test_api_skips_unsafe_payloads_and_leases_a_valid_task(self):
        ctx = self._context()
        token = self._register(ctx, versions=[1])
        invalid = [{"kind": "download_url", "url": self.START, "allowed_roots": ["example.test"]},
                   self._payload(url="https://private.example.test/secret.js"),
                   self._payload(kind="unsupported"), {}]
        mismatched = copy.deepcopy(self._payload())
        mismatched["scope_policy"]["target"] = "another-target"
        invalid.append(mismatched)
        # Legacy work must not fill the first claim page and starve valid work.
        invalid.extend(copy.deepcopy(invalid[0]) for _ in range(50))
        for index, payload in enumerate(invalid):
            ctx.db.enqueue_work(ctx.run_id, self.policy.name, "remote", str(index), payload)
        valid = self._payload()
        work_id = ctx.db.enqueue_work(ctx.run_id, self.policy.name, "remote", "valid", valid)
        response = self._api(ctx.paths, token, "/api/v1/work/claim", {"worker_id": "worker"})
        self.assertEqual(response["id"], work_id)
        self.assertTrue(response["lease_token"])
        self.assertEqual(json.loads(response["payload_json"]), valid)
        self.assertEqual(ctx.db.work_status(ctx.run_id, self.policy.name, "remote", "valid"), "running")
        for index in range(len(invalid)):
            self.assertEqual(ctx.db.work_status(ctx.run_id, self.policy.name, "remote", str(index)), "queued")
        result, opened, _lookups = self._transport(json.loads(response["payload_json"]), ["https://private.example.test/secret.js"])
        self.assertEqual(opened, [self.START])
        self.assertEqual(result["transport_status"], "stopped_for_safety")


if __name__ == "__main__":
    unittest.main()
