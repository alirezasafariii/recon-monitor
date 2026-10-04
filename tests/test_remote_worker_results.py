from __future__ import annotations

import datetime as dt
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from email.utils import format_datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import remote_worker
from api_server_core import APIHandler, create_token
from core import AppPaths, Database, TargetPolicy
from worker_results import classify_worker_result, worker_retry_ready
from worker_scope import worker_scope_snapshot


class RemoteWorkerResultTests(unittest.TestCase):
    URL = "https://public.example.test/app.js"
    NOW = dt.datetime(2026, 10, 4, 12, 0, tzinfo=dt.timezone.utc)

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect", "urllib.request.urlopen"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.policy = TargetPolicy.from_dict({
            "name": "example.test", "roots": ["example.test"],
            "exclude": [r"(^|\.)private\.example\.test$"],
        })

    def payload(self, kind="download_url"):
        return {"kind": kind, "url": self.URL, "scope_policy": worker_scope_snapshot(self.policy)}

    def result(self, status=200, transport="ok", **extra):
        return {"url": self.URL, "status_code": status, "transport_status": transport,
                "transport_error": "", "truncated": False, "redirect_outside_scope": False, **extra}

    def project(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        paths = AppPaths.from_root(Path(tmp.name))
        paths.ensure()
        db = Database(paths.db)
        self.addCleanup(db.close)
        run_id = db.create_run(self.policy.name, 1, "offline")
        token = create_token(db, "offline-worker", "worker")
        self.api(paths, token, "/api/v1/workers/register", {
            "worker_id": "worker", "capabilities": list(remote_worker.WORKER_CAPABILITIES),
            "metadata": {"scope_policy_versions": [1]},
        })
        return paths, db, run_id, token

    def api(self, paths, token, route, payload, expected_status=200):
        handler = object.__new__(APIHandler)
        handler.paths, handler.path, handler.command = paths, route, "POST"
        encoded = json.dumps(payload).encode()
        handler.headers = {"Authorization": "Bearer " + token, "Content-Length": str(len(encoded))}
        handler.rfile = io.BytesIO(encoded)
        handler.send_json = MagicMock()
        handler.do_POST()
        response = handler.send_json.call_args.args
        self.assertEqual(response[1] if len(response) > 1 else 200, expected_status)
        return response[0]

    def claim(self, paths, db, run_id, token, kind="download_url", key="item"):
        work_id = db.enqueue_work(run_id, self.policy.name, "remote", key, self.payload(kind))
        work = self.api(paths, token, "/api/v1/work/claim", {"worker_id": "worker"})
        self.assertEqual(work["id"], work_id)
        return work

    def deliver(self, paths, token, work, result, **extra):
        return self.api(paths, token, "/api/v1/work/result", {
            "id": work["id"], "worker_id": "worker", "lease_token": work["lease_token"],
            "ok": True, "result": result, **extra,
        })

    def test_head_http_errors_are_valid_observations_but_downloads_must_succeed(self):
        for status in (200, 204, 206, 301, 401, 403, 404, 408, 425, 500, 503):
            with self.subTest(status=status):
                result = self.result(status, transport_error="http_error" if status >= 400 else "")
                self.assertTrue(classify_worker_result(self.payload("http_head"), result).ok)
                download = classify_worker_result(self.payload(), result)
                self.assertEqual(download.ok, 200 <= status < 300)
                self.assertEqual(download.retry, status in {408, 425} or status >= 500)

    def test_transport_errors_retain_retry_instead_of_becoming_success(self):
        for kind in remote_worker.WORKER_CAPABILITIES:
            with self.subTest(kind=kind):
                outcome = classify_worker_result(self.payload(kind), self.result(0, "error", transport_error="timed out"))
                self.assertFalse(outcome.ok)
                self.assertTrue(outcome.retry)
                self.assertEqual(outcome.error, "timed out")

    def test_safety_and_partial_results_are_terminal_even_with_valid_http_status(self):
        cases = [self.result(302, "stopped_for_safety", transport_error="redirect_outside_scope"),
                 self.result(0, "stopped_for_safety", transport_error="non_public_resolution_blocked"),
                 self.result(302, "stopped_for_safety", transport_error="redirect_limit_exceeded"),
                 self.result(302, "stopped_for_safety", transport_error="redirect_scheme_downgrade_blocked"),
                 self.result(200, "stopped_for_safety", transport_error="response_budget_exceeded", truncated=True),
                 self.result(200, redirect_outside_scope=True), self.result(200, truncated=True),
                 self.result(429, "stopped_for_safety", redirect_outside_scope=True),
                 self.result(429, "stopped_for_safety", transport_error="response_budget_exceeded"),
                 self.result(200, url="https://private.example.test/secret"),
                 self.result(200, url="https://outside.test/secret")]
        for kind in remote_worker.WORKER_CAPABILITIES:
            for result in cases:
                with self.subTest(kind=kind, result=result):
                    outcome = classify_worker_result(self.payload(kind), result)
                    self.assertFalse(outcome.ok)
                    self.assertFalse(outcome.retry)

    def test_malformed_results_fail_closed_without_api_exceptions(self):
        cases = [None, [], {}, self.result(0), self.result(100), self.result(600),
                 self.result(True), self.result("200"), self.result(200, []),
                 self.result(200, {}), self.result(200, "unknown"),
                 self.result(200, truncated="false"), self.result(200, url=None),
                 self.result(200, transport_error="unexplained failure")]
        for result in cases:
            with self.subTest(result=result):
                outcome = classify_worker_result(self.payload(), result)
                self.assertFalse(outcome.ok)
                self.assertFalse(outcome.retry)

    def test_429_retries_with_controller_clock_and_retry_after(self):
        cases = [("", 60), ("invalid", 60), ("-2", 60), ("0", 60), ("120", 120),
                 (format_datetime(self.NOW + dt.timedelta(seconds=180), usegmt=True), 180),
                 (format_datetime(self.NOW - dt.timedelta(seconds=10), usegmt=True), 60),
                 ("999999999999", 999999999999)]
        for kind in remote_worker.WORKER_CAPABILITIES:
            for header, delay in cases:
                with self.subTest(kind=kind, header=header):
                    outcome = classify_worker_result(self.payload(kind), self.result(
                        429, "stopped_for_safety", transport_error="http_error", retry_after=header), now=self.NOW)
                    self.assertFalse(outcome.ok)
                    self.assertTrue(outcome.retry)
                    self.assertEqual(outcome.reason, "rate_limited")
                    self.assertEqual(outcome.retry_delay_seconds, delay)

    def test_download_service_error_obeys_retry_after(self):
        outcome = classify_worker_result(self.payload(), self.result(503, transport_error="http_error", retry_after="90"))
        self.assertTrue(outcome.retry)
        self.assertEqual(outcome.retry_delay_seconds, 90)

    def test_invalid_scope_cannot_be_reported_as_success(self):
        for payload in ({"kind": "download_url"}, {**self.payload(), "scope_policy": {}}, {**self.payload(), "kind": "shell"}):
            with self.subTest(payload=payload):
                outcome = classify_worker_result(payload, self.result())
                self.assertFalse(outcome.ok)
                self.assertFalse(outcome.retry)

    def test_end_to_end_transport_timeout_fails_and_can_retry_without_network(self):
        paths, db, run_id, token = self.project()
        reports = []

        def controller(_server, _token, route, payload):
            if route.endswith("/result"):
                reports.append(payload)
            return self.api(paths, token, route, payload)

        for index, kind in enumerate(remote_worker.WORKER_CAPABILITIES):
            work_id = db.enqueue_work(run_id, self.policy.name, "remote", str(index), self.payload(kind))
            opener = SimpleNamespace(open=MagicMock(side_effect=TimeoutError("timed out")))
            with patch("remote_worker._request", side_effect=controller), patch(
                "safe_transport.resolve_public_addresses", return_value=(True, ["93.184.216.34"]),
            ), patch("safe_transport.build_pinned_opener", return_value=opener):
                self.assertEqual(remote_worker.run_worker("https://controller.test", token, "worker", once=True), 0)
            row = db.one("SELECT * FROM work_items WHERE id=?", (work_id,))
            result = json.loads(row["result_json"])
            self.assertEqual(row["status"], "retry_pending")
            self.assertEqual(row["error"], "timed out")
            self.assertEqual(result["status_code"], 0)
            self.assertEqual(result["transport_status"], "error")
            self.assertEqual(result["pinned_address"], "93.184.216.34")
            self.assertFalse(reports[-1]["ok"])
            self.assertTrue(reports[-1]["retry"])
            self.assertIsNone(row["lease_token_hash"])
            self.assertEqual(row["attempts"], 1)
            # The controller must not immediately claim the just-failed item.
            self.assertIsNone(self.api(paths, token, "/api/v1/work/claim", {"worker_id": "worker"})["work"])
        db.execute("UPDATE work_items SET finished_at='2000-01-01T00:00:00Z'")
        retry = self.api(paths, token, "/api/v1/work/claim", {"worker_id": "worker"})
        self.assertEqual(retry["id"], reports[0]["id"])
        current = db.one("SELECT * FROM work_items WHERE id=?", (retry["id"],))
        self.assertEqual(current["attempts"], 2)
        self.assertIsNone(current["finished_at"])
        self.assertNotEqual(retry["lease_token"], reports[0]["lease_token"])

    def test_real_transport_retains_429_header_for_both_task_kinds(self):
        paths, db, run_id, token = self.project()
        reports = []

        def controller(_server, _token, route, payload):
            if route.endswith("/result"):
                reports.append(payload)
            return self.api(paths, token, route, payload)

        for index, kind in enumerate(remote_worker.WORKER_CAPABILITIES):
            work_id = db.enqueue_work(run_id, self.policy.name, "remote", str(index), self.payload(kind))
            error = urllib.error.HTTPError(self.URL, 429, "rate limited", {"Retry-After": "120"}, io.BytesIO(b"limited"))
            self.addCleanup(error.close)
            with self.subTest(kind=kind), patch("remote_worker._request", side_effect=controller), patch("safe_transport.resolve_public_addresses", return_value=(True, ["93.184.216.34"])), patch(
                "safe_transport.build_pinned_opener", return_value=SimpleNamespace(open=MagicMock(side_effect=error)),
            ):
                self.assertEqual(remote_worker.run_worker("https://controller.test", token, "worker", once=True), 0)
                row = db.one("SELECT * FROM work_items WHERE id=?", (work_id,))
                result = json.loads(row["result_json"])
                self.assertEqual(result["status_code"], 429)
                self.assertEqual(result["retry_after"], "120")
                self.assertEqual(result["transport_status"], "stopped_for_safety")
                self.assertFalse(reports[-1]["ok"])
                self.assertTrue(reports[-1]["retry"])
                self.assertEqual(row["status"], "retry_pending")
                self.assertEqual(result["_worker_outcome"]["retry_delay_seconds"], 120)

    def test_api_reclassifies_legacy_workers_and_ignores_claimed_result_kind(self):
        paths, db, run_id, token = self.project()
        cases = [("download_url", self.result(0, "error", transport_error="connection refused"), "retry_pending"),
                 ("download_url", self.result(404, transport_error="http_error", kind="http_head"), "failed"),
                 ("download_url", self.result(503, transport_error="http_error"), "retry_pending"),
                 ("download_url", self.result(200, truncated=True), "failed"),
                 ("download_url", self.result(302, "stopped_for_safety", redirect_outside_scope=True), "failed"),
                 ("download_url", self.result(), "completed"),
                 ("http_head", self.result(404, transport_error="http_error"), "completed"),
                 ("http_head", self.result(503, transport_error="http_error"), "completed")]
        for index, (kind, result, expected) in enumerate(cases):
            with self.subTest(kind=kind, result=result):
                work = self.claim(paths, db, run_id, token, kind, str(index))
                self.assertTrue(self.deliver(paths, token, work, result)["ok"])
                row = db.one("SELECT * FROM work_items WHERE id=?", (work["id"],))
                self.assertEqual(row["status"], expected)
                saved = json.loads(row["result_json"])
                self.assertEqual(saved["status_code"], result["status_code"])
                self.assertEqual(saved["_worker_outcome"]["ok"], expected == "completed")

    def test_api_429_cooldown_is_persisted_and_cannot_be_forged_by_worker(self):
        paths, db, run_id, token = self.project()
        work = self.claim(paths, db, run_id, token)
        self.deliver(paths, token, work, self.result(429, "stopped_for_safety", transport_error="http_error", retry_after="120", _worker_outcome={"retry_delay_seconds": 0}))
        row = db.one("SELECT * FROM work_items WHERE id=?", (work["id"],))
        self.assertEqual(row["status"], "retry_pending")
        saved = json.loads(row["result_json"])
        self.assertEqual(saved["_worker_outcome"]["retry_delay_seconds"], 120)
        finished = dt.datetime.fromisoformat(row["finished_at"].replace("Z", "+00:00"))
        self.assertFalse(worker_retry_ready(row, now=finished + dt.timedelta(seconds=119)))
        self.assertTrue(worker_retry_ready(row, now=finished + dt.timedelta(seconds=120)))
        self.assertIsNone(self.api(paths, token, "/api/v1/work/claim", {"worker_id": "worker"})["work"])

    def test_retry_cooldown_does_not_starve_ready_work_on_later_claim_pages(self):
        paths, db, run_id, token = self.project()
        for index in range(55):
            work = self.claim(paths, db, run_id, token, key=str(index))
            self.deliver(paths, token, work, self.result(429, "stopped_for_safety", transport_error="http_error"))
        ready = self.claim(paths, db, run_id, token, key="ready")
        self.assertTrue(ready["lease_token"])
        self.assertEqual(db.one("SELECT count(*) FROM work_items WHERE status='retry_pending'")[0], 55)

    def test_failure_and_success_delivery_cannot_modify_wrong_or_expired_leases(self):
        paths, db, run_id, token = self.project()
        work = self.claim(paths, db, run_id, token)
        original_result = db.one("SELECT result_json FROM work_items WHERE id=?", (work["id"],))[0]
        for result in (self.result(), self.result(0, "error")):
            with self.subTest(result=result):
                self.api(paths, token, "/api/v1/work/result", {
                    "id": work["id"], "worker_id": "worker", "lease_token": "wrong", "ok": True, "result": result,
                }, expected_status=409)
                self.assertEqual(db.one("SELECT status FROM work_items WHERE id=?", (work["id"],))[0], "running")
        db.execute("UPDATE work_items SET lease_expires_at='2000-01-01T00:00:00Z' WHERE id=?", (work["id"],))
        self.api(paths, token, "/api/v1/work/result", {
            "id": work["id"], "worker_id": "worker", "lease_token": work["lease_token"], "ok": True, "result": self.result(0, "error"),
        }, expected_status=409)
        row = db.one("SELECT * FROM work_items WHERE id=?", (work["id"],))
        self.assertEqual(row["result_json"], original_result)
        self.assertIsNone(row["finished_at"])

    def test_stale_result_cannot_overwrite_new_retry_lease(self):
        paths, db, run_id, token = self.project()
        old = self.claim(paths, db, run_id, token)
        self.deliver(paths, token, old, self.result(0, "error", transport_error="timed out"))
        db.execute("UPDATE work_items SET finished_at='2000-01-01T00:00:00Z' WHERE id=?", (old["id"],))
        new = self.api(paths, token, "/api/v1/work/claim", {"worker_id": "worker"})
        self.api(paths, token, "/api/v1/work/result", {
            "id": old["id"], "worker_id": "worker", "lease_token": old["lease_token"], "ok": True, "result": self.result(),
        }, expected_status=409)
        self.deliver(paths, token, new, self.result())
        self.assertEqual(db.one("SELECT status FROM work_items WHERE id=?", (old["id"],))[0], "completed")

    def test_api_rejects_malformed_and_truthy_success_envelopes(self):
        paths, db, run_id, token = self.project()
        for index, (ok, result) in enumerate([(True, []), (True, {}), (True, self.result(200, [])), ("true", self.result())]):
            with self.subTest(ok=ok, result=result):
                work = self.claim(paths, db, run_id, token, key=str(index))
                self.deliver(paths, token, work, result, ok=ok)
                self.assertEqual(db.one("SELECT status FROM work_items WHERE id=?", (work["id"],))[0], "failed")

    def test_worker_validation_failure_is_terminal_while_unexpected_failure_retries(self):
        work = {"id": 1, "lease_token": "lease", "payload_json": json.dumps(self.payload())}
        for error, retry in ((remote_worker.ReconError("invalid scope"), False), (OSError("temporary failure"), True)):
            with self.subTest(error=error), patch("remote_worker._request", side_effect=[{"worker_id": "worker"}, {"ok": True}, work, {"ok": True}]) as request, patch(
                "remote_worker.execute_task", side_effect=error,
            ):
                self.assertEqual(remote_worker.run_worker("https://controller.test", "token", "worker", once=True), 0)
                report = request.call_args_list[-1].args[3]
                self.assertFalse(report["ok"])
                self.assertEqual(report["retry"], retry)
                self.assertEqual(report["error"], str(error))

    def test_error_only_delivery_preserves_retry_choice_and_error(self):
        paths, db, run_id, token = self.project()
        for index, (retry, result) in enumerate(((True, None), (False, None), (True, {}), (False, {}))):
            with self.subTest(retry=retry, result=result):
                work = self.claim(paths, db, run_id, token, key=str(index))
                self.deliver(paths, token, work, result, ok=False, retry=retry, error="offline exception")
                row = db.one("SELECT * FROM work_items WHERE id=?", (work["id"],))
                self.assertEqual(row["status"], "retry_pending" if retry else "failed")
                self.assertEqual(row["error"], "offline exception")
                self.assertEqual(json.loads(row["result_json"])["_worker_outcome"]["retry_delay_seconds"], 5 if retry else 0)

    def test_controller_delivery_error_is_not_reported_again_as_target_failure(self):
        work = {"id": 1, "lease_token": "lease", "payload_json": json.dumps(self.payload())}
        for result in (self.result(), self.result(0, "error")):
            with self.subTest(result=result), patch("remote_worker._request", side_effect=[{"worker_id": "worker"}, {"ok": True}, work, OSError("controller unavailable")]) as request, patch(
                "remote_worker.execute_task", return_value=result,
            ):
                with self.assertRaisesRegex(OSError, "controller unavailable"):
                    remote_worker.run_worker("https://controller.test", "token", "worker", once=True)
                self.assertEqual(len([call for call in request.call_args_list if call.args[2].endswith("/result")]), 1)

    def test_missing_lease_is_rejected_without_execution_or_delivery(self):
        with patch("remote_worker._request", side_effect=[{"worker_id": "worker"}, {"ok": True}, {"id": 1}]) as request, patch("remote_worker.execute_task") as execute:
            with self.assertRaisesRegex(remote_worker.ReconError, "lease token"):
                remote_worker.run_worker("https://controller.test", "token", "worker", once=True)
            execute.assert_not_called()
            self.assertEqual(request.call_count, 3)


if __name__ == "__main__":
    unittest.main()
