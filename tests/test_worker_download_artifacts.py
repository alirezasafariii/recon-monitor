from __future__ import annotations

import copy
import datetime as dt
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import remote_worker
from api_server_core import APIHandler, create_token
from core import AppPaths, Config, Database, Logger, TargetPolicy, sha256_bytes
from execution import WorkQueue
from operations import BackupManager
from stages import StageContext, stage_javascript
from storage import ContentAddressedStore
from worker_artifacts import MAX_DOWNLOAD_BYTES, encode_artifact
from worker_scope import worker_scope_snapshot


class WorkerDownloadArtifactTests(unittest.TestCase):
    URL = "https://public.example.test/app.js"
    JS = 'const label = "سلام"; fetch("/api/items");\n'.encode()

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect", "urllib.request.urlopen"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.paths = AppPaths.from_root(Path(tmp.name))
        self.paths.ensure()
        self.db = Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.policy = TargetPolicy.from_dict({
            "name": "example.test", "roots": ["example.test"], "exclude": [r"(^|\.)private\.example\.test$"],
            "limits": {"timeout_seconds": 1800}, "javascript": {"download_source_maps": False},
        })
        self.run_id = self.db.create_run(self.policy.name, 1, "offline")
        run_dir = self.paths.output / self.run_id
        self.db.create_run_target(self.run_id, self.policy, run_dir, True)
        self.ctx = StageContext(self.paths, Config(self.paths), self.policy, self.db, Logger(self.paths), SimpleNamespace(), MagicMock(), self.run_id, run_dir, False)
        self.token = create_token(self.db, "offline-worker", "worker")
        self.register()
        self.store = ContentAddressedStore(self.paths, self.db)
        (self.ctx.current / "urls.txt").write_text(self.URL + "\n")
        (self.ctx.current / "url-collection.json").write_text(json.dumps({
            "run_id": self.run_id, "target": self.policy.name, "metrics": {"collection_status": "completed"},
        }))

    def api(self, route, payload, *, expected=200):
        handler = object.__new__(APIHandler)
        handler.paths, handler.path, handler.command = self.paths, route, "POST"
        encoded = json.dumps(payload).encode()
        handler.headers = {"Authorization": "Bearer " + self.token, "Content-Length": str(len(encoded))}
        handler.rfile = io.BytesIO(encoded)
        handler.send_json = MagicMock()
        handler.do_POST()
        response = handler.send_json.call_args.args
        self.assertEqual(response[1] if len(response) > 1 else 200, expected)
        return response[0]

    def register(self, versions=None):
        versions = [1] if versions is None else versions
        self.api("/api/v1/workers/register", {"worker_id": "worker", "capabilities": ["http_head", "download_url"],
                 "metadata": {"scope_policy_versions": [1], "download_artifact_versions": versions}})

    def enqueue(self, key=None, kind="download_url", **extra):
        return self.db.enqueue_work(self.run_id, self.policy.name, "javascript-items", key or self.URL, {
            "kind": kind, "url": self.URL, "scope_policy": worker_scope_snapshot(self.policy),
            "max_bytes": self.policy.limits.max_js_bytes, **extra,
        })

    def claim(self, **extra):
        work_id = self.enqueue(**extra)
        work = self.api("/api/v1/work/claim", {"worker_id": "worker"})
        self.assertEqual(work["id"], work_id)
        return work

    def result(self, data=None, **extra):
        data = self.JS if data is None else data
        return {"url": self.URL, "status_code": 200, "transport_status": "ok", "transport_error": "",
                "content_type": "application/javascript", "content_length": len(data),
                "truncated": False, "redirect_outside_scope": False, "artifact": encode_artifact(data), **extra}

    def deliver(self, work, result, *, expected=200, **extra):
        return self.api("/api/v1/work/result", {"id": work["id"], "worker_id": "worker", "lease_token": work["lease_token"],
                       "ok": True, "result": result, **extra}, expected=expected)

    def row(self, work):
        return dict(self.db.one("SELECT * FROM work_items WHERE id=?", (work["id"],)))

    def process_cached(self):
        with patch("stages._download_url", side_effect=AssertionError("cached artifact caused a new request")) as download:
            result = stage_javascript(self.ctx)
        download.assert_not_called()
        return result

    def local_result(self):
        return {"url": self.URL, "status_code": 200, "data": self.JS, "content_type": "application/javascript"}

    def object_path(self, digest):
        relative = self.db.one("SELECT relative_path FROM object_store WHERE sha256=?", (digest,))[0]
        return self.paths.state / relative

    def test_worker_api_cas_and_javascript_processing_preserve_exact_bytes(self):
        work_id = self.enqueue()
        response = MagicMock()
        response.status = 200
        response.headers = {"Content-Type": "application/javascript", "Content-Length": str(len(self.JS)), "ETag": '"offline"', "Last-Modified": "Mon, 01 Jun 2026 10:00:00 GMT"}
        response.read.return_value = self.JS
        response.__enter__.return_value = response
        opened, reports = [], []

        def open_request(request, **_kwargs):
            opened.append(request)
            return response

        def controller(_server, _token, route, payload):
            if route.endswith("/result"):
                reports.append(payload)
            return self.api(route, payload)

        with patch("remote_worker._request", side_effect=controller), patch("safe_transport.resolve_public_addresses", return_value=(True, ["93.184.216.34"])), patch(
            "safe_transport.build_pinned_opener", return_value=SimpleNamespace(open=open_request),
        ):
            self.assertEqual(remote_worker.run_worker("https://controller.test", self.token, "worker", once=True), 0)
        self.assertEqual(len(opened), 1)
        self.assertIsNone(opened[0].get_header("Range"))
        self.assertTrue(reports[0]["ok"])
        row = self.row({"id": work_id})
        self.assertEqual(row["status"], "artifact_ready")
        self.assertIsNone(row["finished_at"])
        self.assertEqual(self.db.one("SELECT count(*) FROM js_files")[0], 0)
        saved = json.loads(row["result_json"])
        self.assertNotIn("data", saved["artifact"])
        digest = saved["artifact"]["sha256"]
        self.assertEqual(self.store.get(digest), self.JS)
        self.assertEqual(self.db.one("SELECT reference_count FROM object_store WHERE sha256=?", (digest,))[0], 1)
        self.assertEqual(self.store.retention_candidates(cutoff=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)), [])
        self.assertIsNone(self.api("/api/v1/work/claim", {"worker_id": "worker"})["work"])
        result = self.process_cached()
        self.assertEqual(result["collection_status"], "completed")
        self.assertEqual(result["download_attempts"], 0)
        self.assertEqual(result["remote_artifacts_reused"], 1)
        self.assertEqual(result["downloaded"], 1)
        js = self.db.one("SELECT * FROM js_files WHERE target=? AND url=?", (self.policy.name, self.URL))
        self.assertEqual(Path(js["blob_path"]).read_bytes(), self.JS)
        self.assertEqual(js["raw_hash"], sha256_bytes(self.JS))
        self.assertEqual(js["etag"], '"offline"')
        self.assertEqual(js["last_modified"], response.headers["Last-Modified"])
        self.assertGreater(self.db.one("SELECT count(*) FROM js_indicators")[0], 0)
        self.assertGreater(self.db.one("SELECT count(*) FROM endpoint_intelligence")[0], 0)
        self.assertEqual(self.row({"id": work_id})["status"], "completed")
        self.assertEqual(self.db.one("SELECT count(*) FROM cas_references WHERE owner_kind='work_item'")[0], 0)
        reused = self.process_cached()
        self.assertEqual(reused["reused_work_items"], 1)

    def test_legacy_workers_can_observe_head_but_cannot_claim_downloads(self):
        for versions in ([], [2], [True], "1"):
            self.register(versions)
            work_id = self.enqueue(key=str(versions))
            self.assertIsNone(self.api("/api/v1/work/claim", {"worker_id": "worker"})["work"])
            self.assertEqual(self.row({"id": work_id})["status"], "queued")
        head = self.claim(key="head", kind="http_head")
        result = self.result(status_code=404, transport_error="http_error")
        result.pop("artifact")
        self.deliver(head, result)
        self.assertEqual(self.row(head)["status"], "completed")

    def test_inflight_legacy_metadata_is_retryable_and_cannot_complete_javascript(self):
        work = self.claim()
        self.register([])
        result = self.result()
        result.pop("artifact")
        self.deliver(work, result)
        row = self.row(work)
        self.assertEqual(row["status"], "retry_pending")
        self.assertIn("artifact is missing", row["error"])
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 0)
        self.assertEqual(self.db.one("SELECT count(*) FROM js_files")[0], 0)

    def test_invalid_artifacts_fail_before_any_cas_write(self):
        original = self.result()
        cases = []
        for field, value in (("version", True), ("version", 2), ("encoding", "path"), ("size", True), ("size", MAX_DOWNLOAD_BYTES + 1),
                             ("sha256", "0" * 64), ("sha256", "../../secret"), ("data", "!" * len(original["artifact"]["data"]))):
            result = copy.deepcopy(original)
            result["artifact"][field] = value
            cases.append(result)
        cases.extend([self.result(content_length=len(self.JS) + 1), self.result(truncated=True),
                      self.result(url="https://private.example.test/secret.js"), self.result(url="https://outside.test/app.js")])
        for index, result in enumerate(cases):
            with self.subTest(result=result):
                work = self.claim(key=str(index))
                self.deliver(work, result)
                row = self.row(work)
                self.assertEqual(row["status"], "failed")
                self.assertNotIn('"data":', row["result_json"])
                self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 0)
                self.assertEqual(self.db.one("SELECT count(*) FROM cas_references")[0], 0)

    def test_wrong_expired_and_replayed_leases_cannot_store_files(self):
        work = self.claim()
        with patch("storage.ContentAddressedStore.put", wraps=self.store.put) as put:
            self.deliver(work, self.result(), expected=409, lease_token="wrong")
            put.assert_not_called()
        self.db.execute("UPDATE work_items SET lease_expires_at='2000-01-01T00:00:00Z' WHERE id=?", (work["id"],))
        self.deliver(work, self.result(), expected=409)
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 0)
        self.db.execute("UPDATE work_items SET lease_expires_at='2099-01-01T00:00:00Z' WHERE id=?", (work["id"],))
        self.deliver(work, self.result())
        before = self.row(work)
        self.deliver(work, self.result(b"replacement"), expected=409)
        self.assertEqual(self.row(work), before)
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 1)

    def test_one_megabyte_and_empty_artifacts_fit_the_existing_api_body_limit(self):
        for index, data in enumerate((b"", b"//" + b"x" * (MAX_DOWNLOAD_BYTES - 2))):
            work = self.claim(key=str(index))
            result = self.result(data)
            self.assertLess(len(json.dumps({"result": result}).encode()), 2_000_000)
            self.deliver(work, result)
            self.assertEqual(self.row(work)["status"], "artifact_ready")
            self.assertEqual(self.store.get(sha256_bytes(data)), data)

    def test_artifacts_obey_the_transferred_limit_and_run_byte_budget(self):
        work = self.claim(max_bytes=10)
        self.deliver(work, self.result())
        self.assertEqual(self.row(work)["status"], "failed")
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 0)
        work = self.claim(key="budget")
        self.db.budget_init(self.run_id, self.policy.name, {"download_bytes": len(self.JS) - 1})
        self.deliver(work, self.result())
        self.assertEqual(self.row(work)["status"], "failed")
        self.assertIn("run download budget", self.row(work)["error"])
        self.assertEqual(self.db.one("SELECT used FROM run_budgets WHERE metric='download_bytes'")[0], 0)
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 0)

    def test_deduplication_keeps_independent_work_owners_and_charges_once(self):
        self.db.budget_init(self.run_id, self.policy.name, {"download_bytes": len(self.JS) * 2})
        first = self.claim(key="first")
        self.deliver(first, self.result())
        self.deliver(first, self.result(), expected=409)
        second = self.claim(key="second")
        self.deliver(second, self.result())
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 1)
        self.assertEqual(self.db.one("SELECT reference_count FROM object_store")[0], 2)
        self.assertEqual(self.db.one("SELECT used FROM run_budgets WHERE metric='download_bytes'")[0], len(self.JS) * 2)

    def test_storage_failure_rolls_back_receipt_and_allows_retry(self):
        work = self.claim()
        with patch.object(Database, "work_receive_artifact", side_effect=OSError("disk failure after CAS write")):
            self.deliver(work, self.result())
        self.assertEqual(self.row(work)["status"], "retry_pending")
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 0)
        self.assertEqual(self.db.one("SELECT count(*) FROM cas_references")[0], 0)
        self.db.execute("UPDATE work_items SET finished_at='2000-01-01T00:00:00Z' WHERE id=?", (work["id"],))
        retried = self.api("/api/v1/work/claim", {"worker_id": "worker"})
        self.deliver(retried, self.result())
        self.assertEqual(self.process_cached()["downloaded"], 1)

    def test_legacy_completed_metadata_is_reopened_and_actually_processed(self):
        work_id = self.enqueue()
        self.db.work_start(work_id, "old-worker")
        legacy = self.result()
        legacy.pop("artifact")
        self.db.work_finish(work_id, legacy)
        with patch("stages._download_url", return_value=self.local_result()) as download:
            result = stage_javascript(self.ctx)
        self.assertEqual(download.call_count, 1)
        self.assertEqual(result["repaired_completed_work_items"], 1)
        self.assertEqual(result["downloaded"], 1)
        self.assertEqual(result["reused_work_items"], 0)
        self.assertEqual(self.db.one("SELECT count(*) FROM js_files")[0], 1)
        self.assertEqual(self.row({"id": work_id})["status"], "completed")

    def test_failed_repair_of_legacy_metadata_is_partial_and_not_completed(self):
        work_id = self.enqueue()
        self.db.work_start(work_id, "old-worker")
        self.db.work_finish(work_id, {"status_code": 200, "content_length": len(self.JS)})
        with patch("stages._download_url", return_value={"url": self.URL, "error": "offline timeout"}):
            result = stage_javascript(self.ctx)
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["downloaded"], 0)
        self.assertEqual(self.row({"id": work_id})["status"], "retry_pending")
        self.assertEqual(self.db.one("SELECT count(*) FROM js_files")[0], 0)

    def test_missing_and_corrupt_received_artifacts_require_a_fresh_download(self):
        for index, corruption in enumerate(("missing", "corrupt")):
            with self.subTest(corruption=corruption):
                work = self.claim(key=self.URL if index == 0 else self.URL + "?v=2")
                if index:
                    # Keep the stage selection tied to this work item's URL.
                    self.db.execute("UPDATE work_items SET item_key=? WHERE id=?", (self.URL, work["id"]))
                self.deliver(work, self.result())
                path = self.object_path(sha256_bytes(self.JS))
                if corruption == "missing":
                    path.unlink()
                else:
                    path.write_bytes(b"corrupt")
                with patch("stages._download_url", return_value=self.local_result()) as download:
                    result = stage_javascript(self.ctx)
                self.assertEqual(download.call_count, 1)
                self.assertEqual(result["artifact_redownloads"], 1)
                self.assertEqual(result["remote_artifacts_reused"], 0)
                self.assertEqual(result["downloaded"], 1)
                self.assertEqual(path.read_bytes(), self.JS)
                self.assertEqual(self.row(work)["status"], "completed")
                self.db.execute("DELETE FROM work_items WHERE id=?", (work["id"],))

    def test_missing_artifact_with_failed_download_remains_partial(self):
        work = self.claim()
        self.deliver(work, self.result())
        self.object_path(sha256_bytes(self.JS)).unlink()
        with patch("stages._download_url", return_value={"url": self.URL, "error": "offline timeout"}):
            result = stage_javascript(self.ctx)
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["downloaded"], 0)
        self.assertEqual(self.row(work)["status"], "retry_pending")
        self.assertEqual(self.db.one("SELECT count(*) FROM js_files")[0], 0)

    def test_processing_failure_keeps_verified_bytes_for_resume(self):
        work = self.claim()
        self.deliver(work, self.result())
        with patch("stages.extract_js_indicators", side_effect=RuntimeError("offline processing fault")), patch("stages._download_url") as download:
            with self.assertRaisesRegex(RuntimeError, "processing fault"):
                stage_javascript(self.ctx)
        download.assert_not_called()
        self.assertEqual(self.row(work)["status"], "retry_pending")
        self.assertEqual(self.db.one("SELECT count(*) FROM js_files")[0], 0)
        self.assertEqual(self.db.one("SELECT count(*) FROM cas_references WHERE owner_kind='work_item'")[0], 1)
        self.assertEqual(self.process_cached()["downloaded"], 1)
        self.assertEqual(self.row(work)["status"], "completed")

    def test_html_artifact_is_not_completed_as_javascript_and_next_retry_can_download(self):
        work = self.claim()
        self.deliver(work, self.result(b"<html>Login</html>", content_type="text/html"))
        result = self.process_cached()
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["unexpected_content_types"], 1)
        self.assertEqual(self.row(work)["status"], "retry_pending")
        self.assertEqual(self.db.one("SELECT count(*) FROM js_files")[0], 0)
        with patch("stages._download_url", return_value=self.local_result()) as download:
            result = stage_javascript(self.ctx)
        self.assertEqual(download.call_count, 1)
        self.assertEqual(result["downloaded"], 1)

    def test_active_remote_lease_is_deferred_without_another_download(self):
        work = self.claim()
        before = self.row(work)
        result = self.process_cached()
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["deferred_work_items"], 1)
        self.assertEqual(result["downloaded"], 0)
        self.assertEqual(self.row(work), before)

    def test_terminal_remote_failure_is_reported_without_overwriting_retry_policy(self):
        work = self.claim()
        self.deliver(work, self.result(status_code=403, transport_error="http_error"))
        result = self.process_cached()
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["errors"], 1)
        self.assertEqual(result["deferred_work_items"], 0)
        self.assertEqual(self.row(work)["status"], "failed")

    def test_remote_not_found_is_processed_as_availability_without_artifact(self):
        work = self.claim()
        result = self.result(status_code=404, transport_error="http_error")
        result.pop("artifact")
        self.deliver(work, result)
        self.assertEqual(self.row(work)["status"], "failed")
        metrics = self.process_cached()
        self.assertEqual(metrics["not_found"], 1)
        self.assertEqual(metrics["errors"], 0)
        self.assertEqual(self.row(work)["status"], "completed")
        self.assertEqual(self.process_cached()["reused_work_items"], 1)

    def test_processed_javascript_with_missing_or_corrupt_cas_is_repaired(self):
        with patch("stages._download_url", return_value=self.local_result()):
            stage_javascript(self.ctx)
        path = self.object_path(sha256_bytes(self.JS))
        for corruption in ("corrupt", "missing"):
            with self.subTest(corruption=corruption):
                if corruption == "missing":
                    path.unlink()
                else:
                    path.write_bytes(b"corrupt")
                with patch("stages._download_url", return_value=self.local_result()) as download:
                    result = stage_javascript(self.ctx)
                self.assertEqual(download.call_count, 1)
                self.assertEqual(result["repaired_completed_work_items"], 1)
                self.assertEqual(path.read_bytes(), self.JS)

    def test_worker_does_not_package_partial_ranges_or_short_responses(self):
        cases = [(206, "bytes 0-2/100", "3", False), (206, "bytes 1-3/4", "3", False),
                 (206, "bytes 0-2/3", "3", True), (200, "", "4", False), (200, "", "3", True)]
        for status, content_range, length, complete in cases:
            response = MagicMock()
            response.status = status
            response.headers = {"Content-Type": "application/javascript", "Content-Length": length, "Content-Range": content_range}
            response.read.return_value = b"abc"
            response.__enter__.return_value = response
            payload = {"kind": "download_url", "url": self.URL, "scope_policy": worker_scope_snapshot(self.policy)}
            with self.subTest(status=status, content_range=content_range), patch("safe_transport.resolve_public_addresses", return_value=(True, ["93.184.216.34"])), patch(
                "safe_transport.build_pinned_opener", return_value=SimpleNamespace(open=MagicMock(return_value=response)),
            ):
                result = remote_worker.execute_task(payload)
            self.assertEqual("artifact" in result, complete)
            self.assertEqual(result["truncated"], not complete)
            self.assertEqual(result["transport_status"], "ok" if complete else "stopped_for_safety")

    def test_controller_rejects_206_prefix_even_when_its_digest_is_correct(self):
        work = self.claim()
        result = self.result(b"abc", status_code=206, content_range="bytes 0-2/100")
        self.deliver(work, result)
        self.assertEqual(self.row(work)["status"], "failed")
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 0)

    def test_worker_byte_limit_is_enforced_before_packaging_or_reading_large_body(self):
        response = MagicMock()
        response.status = 200
        response.headers = {"Content-Length": "11"}
        response.__enter__.return_value = response
        payload = {"kind": "download_url", "url": self.URL, "max_bytes": 10, "scope_policy": worker_scope_snapshot(self.policy)}
        with patch("safe_transport.resolve_public_addresses", return_value=(True, ["93.184.216.34"])), patch(
            "safe_transport.build_pinned_opener", return_value=SimpleNamespace(open=MagicMock(return_value=response)),
        ):
            result = remote_worker.execute_task(payload)
        response.read.assert_not_called()
        self.assertEqual(result["transport_status"], "stopped_for_safety")
        self.assertNotIn("artifact", result)

    def test_pending_artifact_is_included_in_reference_only_backups(self):
        work = self.claim()
        self.deliver(work, self.result())
        backup = BackupManager(self.paths, self.db, Logger(self.paths))
        inventory = backup._reference_inventory(self.paths.db)
        relative = self.object_path(sha256_bytes(self.JS)).relative_to(self.paths.root).as_posix()
        self.assertIn(relative, inventory["required_files"])
        self.assertEqual(inventory["issues"], [])
        created = backup.create()
        self.assertTrue(backup.verify(created["backup_id"])["ok"])
        with tarfile.open(created["path"]) as archive:
            with archive.extractfile(relative) as artifact:
                self.assertEqual(artifact.read(), self.JS)
        self.assertEqual(self.db.one("SELECT count(*) FROM js_files")[0], 0)

    def test_file_write_failure_does_not_publish_artifact_or_completion(self):
        work = self.claim()
        with patch("storage.atomic_write_bytes", side_effect=OSError("no space left")):
            self.deliver(work, self.result())
        self.assertEqual(self.row(work)["status"], "retry_pending")
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 0)
        self.assertEqual(self.db.one("SELECT count(*) FROM cas_references")[0], 0)

    def test_lease_expiry_during_receipt_rolls_back_cas_ownership(self):
        work = self.claim()
        with patch.object(Database, "work_receive_artifact", return_value=False):
            self.deliver(work, self.result(), expected=409)
        self.assertEqual(self.row(work)["status"], "running")
        self.assertEqual(self.db.one("SELECT count(*) FROM object_store")[0], 0)
        self.assertEqual(self.db.one("SELECT count(*) FROM cas_references")[0], 0)

    def test_missing_download_body_is_distinct_from_a_valid_empty_file(self):
        payload = {"kind": "download_url", "url": self.URL, "scope_policy": worker_scope_snapshot(self.policy)}
        with patch("remote_worker.perform_pinned_download", return_value={
            "final_url": self.URL, "status_code": 200, "headers": {}, "transport_status": "ok", "data": None,
        }):
            result = remote_worker.execute_task(payload)
        self.assertEqual(result["transport_status"], "error")
        self.assertNotIn("artifact", result)
        self.assertIn("body is missing", result["transport_error"])

    def test_receipt_arriving_during_resume_selection_is_loaded_without_redownload(self):
        work = self.claim()
        start = WorkQueue.start

        def receive_then_start(queue, work_id, worker_id):
            self.deliver(work, self.result())
            return start(queue, work_id, worker_id)

        with patch.object(WorkQueue, "start", receive_then_start):
            result = self.process_cached()
        self.assertEqual(result["remote_artifacts_reused"], 1)
        self.assertEqual(result["downloaded"], 1)
        self.assertEqual(self.row(work)["status"], "completed")
