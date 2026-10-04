from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from core import AppPaths, Config, Logger, TargetPolicy, sha256_bytes
from execution import BudgetManager, DatabaseWriter, WorkQueue
from recon_monitor_core import Database, Orchestrator
from run_lifecycle_state import record_target_lifecycle
from stages import StageContext, stage_javascript
from storage import ContentAddressedStore


class SourceMapResumeTests(unittest.TestCase):
    URL = "https://example.test/app.js"
    MAP = URL + ".map"
    JS = b'const chunk = "./chunk.js";\n//# sourceMappingURL=app.js.map\n'
    MAP_DATA = json.dumps({
        "version": 3, "sources": ["src/client.ts"],
        "sourcesContent": ['fetch("/api/export");'], "mappings": "",
    }).encode()

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
            "name": "example.test", "roots": ["example.test"],
            "limits": {"timeout_seconds": 1800},
        })
        self.run_id = self.db.create_run(self.policy.name, 1, "offline")
        run_dir = self.paths.output / self.run_id
        self.db.create_run_target(self.run_id, self.policy, run_dir, True)
        self.ctx = StageContext(self.paths, Config(self.paths), self.policy, self.db, Logger(self.paths),
                                SimpleNamespace(), MagicMock(), self.run_id, run_dir, False)
        self.inputs([self.URL])

    def inputs(self, urls):
        (self.ctx.current / "urls.txt").write_text("".join(url + "\n" for url in urls))
        (self.ctx.current / "url-collection.json").write_text(json.dumps({
            "run_id": self.run_id, "target": self.policy.name,
            "metrics": {"collection_status": "completed"},
        }))

    def result(self, url, data):
        return {"url": url, "status_code": 200, "data": data,
                "content_type": "application/json" if url.endswith(".map") else "application/javascript"}

    def first_failure(self, failure=None):
        failure = failure or {"url": self.MAP, "status_code": 0, "error": "timed out"}
        with patch("stages._download_url", side_effect=lambda _ctx, url, _limit:
                   self.result(url, self.JS) if url == self.URL else failure):
            return stage_javascript(self.ctx)

    def map_items(self):
        return self.db.all("SELECT * FROM work_items WHERE stage='javascript-source-map-items' ORDER BY id")

    def rows(self, name):
        return [json.loads(line) for line in (self.ctx.current / name).read_text().splitlines()]

    def complete(self, js=None, source_map=None):
        with patch("stages._download_url", side_effect=lambda _ctx, url, _limit:
                   self.result(url, js if js is not None else self.JS) if url == self.URL
                   else self.result(url, source_map if source_map is not None else self.MAP_DATA)):
            return stage_javascript(self.ctx)

    def resume_map(self, source_map=None):
        with patch("stages._download_url", return_value=self.result(
            self.MAP, source_map if source_map is not None else self.MAP_DATA,
        )) as download:
            metrics = stage_javascript(self.ctx)
        download.assert_called_once_with(self.ctx, self.MAP, self.policy.limits.max_js_bytes)
        return metrics

    def new_run(self):
        self.run_id = self.db.create_run(self.policy.name, 1, "offline")
        self.ctx.run_id = self.run_id
        self.ctx.run_dir = self.paths.output / self.run_id
        self.db.create_run_target(self.run_id, self.policy, self.ctx.run_dir, False)
        self.inputs([self.URL])

    def test_map_failure_is_persistent_and_resume_downloads_only_the_map(self):
        first = self.first_failure()
        self.assertEqual(first["collection_status"], "partial")
        self.assertEqual(first["source_map_failures"], 1)
        self.assertEqual(self.db.work_status(self.run_id, self.policy.name, "javascript-items", self.URL), "completed")
        self.assertEqual(len(self.map_items()), 1)
        self.assertEqual(self.map_items()[0]["status"], "retry_pending")
        with patch("stages._download_url", return_value=self.result(self.MAP, self.MAP_DATA)) as download:
            resumed = stage_javascript(self.ctx)
        download.assert_called_once_with(self.ctx, self.MAP, self.policy.limits.max_js_bytes)
        self.assertEqual(resumed["download_attempts"], 0)
        self.assertEqual(resumed["reused_work_items"], 1)
        self.assertEqual(resumed["source_map_failures"], 0)
        self.assertEqual(resumed["collection_status"], "completed")
        self.assertEqual(self.map_items()[0]["status"], "completed")
        self.assertEqual(self.map_items()[0]["attempts"], 2)
        self.assertEqual(self.rows("source-map-sources.jsonl")[0]["source_name"], "src/client.ts")
        self.assertEqual(self.rows("javascript-chunk-edges.jsonl"), [
            {"js_url": self.URL, "chunk_url": "https://example.test/chunk.js"},
        ])

    def test_repeated_failed_resume_stays_partial_instead_of_claiming_completion(self):
        self.first_failure()
        with patch("stages._download_url", return_value={"url": self.MAP, "error": "connection refused"}) as download:
            resumed = stage_javascript(self.ctx)
        download.assert_called_once_with(self.ctx, self.MAP, self.policy.limits.max_js_bytes)
        self.assertEqual(resumed["collection_status"], "partial")
        self.assertEqual(resumed["source_map_failures"], 1)
        self.assertIn("source_map_download_errors", resumed["collection_reasons"])

    def test_legacy_completed_js_without_a_map_subtask_is_recovered(self):
        self.first_failure()
        self.db.execute("DELETE FROM work_items WHERE stage='javascript-source-map-items'")
        self.assertEqual(self.db.work_status(self.run_id, self.policy.name, "javascript-items", self.URL), "completed")
        self.assertEqual(self.resume_map()["collection_status"], "completed")
        self.assertEqual(self.map_items()[0]["attempts"], 1)

    def test_successful_resume_reuses_map_and_restores_all_evidence_without_requests(self):
        first = self.complete()
        sources = self.rows("source-map-sources.jsonl")
        chunks = self.rows("javascript-chunk-edges.jsonl")
        refs = [tuple(row) for row in self.db.all("SELECT owner_kind,owner_key,sha256 FROM cas_references ORDER BY owner_kind,owner_key")]
        events = self.ctx.events_path.read_text()
        with patch("stages._download_url", side_effect=AssertionError("completed artifacts requested network")):
            resumed = stage_javascript(self.ctx)
        self.assertEqual(resumed["collection_status"], "completed")
        self.assertEqual(resumed["source_map_attempts"], 0)
        self.assertEqual(resumed["source_map_reused_work_items"], 1)
        self.assertEqual(resumed["source_maps"], 0)
        self.assertEqual(resumed["source_map_sources"], first["source_map_sources"])
        self.assertEqual(self.rows("source-map-sources.jsonl"), sources)
        self.assertEqual(self.rows("javascript-chunk-edges.jsonl"), chunks)
        self.assertEqual(self.ctx.events_path.read_text(), events)
        self.assertEqual([tuple(row) for row in self.db.all("SELECT owner_kind,owner_key,sha256 FROM cas_references ORDER BY owner_kind,owner_key")], refs)
        self.assertEqual(self.map_items()[0]["attempts"], 1)

    def test_failure_survives_database_reopen_and_uses_database_writer_on_resume(self):
        self.first_failure()
        work_id = self.map_items()[0]["id"]
        self.db.close()
        self.db = Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.ctx.db = self.db
        writer = DatabaseWriter(self.paths.db)
        self.addCleanup(writer.close)
        self.ctx.db_writer = writer
        resumed = self.resume_map()
        self.assertEqual(resumed["collection_status"], "completed")
        self.assertEqual(self.map_items()[0]["id"], work_id)
        self.assertEqual(self.map_items()[0]["attempts"], 2)

    def test_mixed_map_results_resume_only_failed_map_and_keep_successful_sources(self):
        other_js, other_map = "https://example.test/other.js", "https://example.test/other.js.map"
        other_data = b"//# sourceMappingURL=other.js.map\n"
        self.inputs([self.URL, other_js])

        def first_download(_ctx, url, _limit):
            if url == self.URL:
                return self.result(url, self.JS)
            if url == other_js:
                return self.result(url, other_data)
            if url == self.MAP:
                return self.result(url, self.MAP_DATA)
            return {"url": url, "status_code": 503, "error": "http_error"}

        with patch("stages._download_url", side_effect=first_download):
            first = stage_javascript(self.ctx)
        self.assertEqual(first["collection_status"], "partial")
        self.assertEqual([row["status"] for row in self.map_items()], ["completed", "retry_pending"])
        second_map = json.dumps({"sources": ["src/other.ts"], "sourcesContent": ["const other = 1;"]}).encode()
        with patch("stages._download_url", return_value=self.result(other_map, second_map)) as download:
            resumed = stage_javascript(self.ctx)
        download.assert_called_once_with(self.ctx, other_map, self.policy.limits.max_js_bytes)
        self.assertEqual(resumed["collection_status"], "completed")
        self.assertEqual(resumed["source_map_reused_work_items"], 1)
        self.assertEqual({row["source_name"] for row in self.rows("source-map-sources.jsonl")}, {"src/client.ts", "src/other.ts"})

    def test_invalid_json_stays_pending_and_does_not_retire_previous_source_references(self):
        self.complete()
        refs = [tuple(row) for row in self.db.all("SELECT owner_kind,owner_key,sha256 FROM cas_references WHERE owner_kind LIKE 'source_map%' ORDER BY owner_kind,owner_key")]
        self.new_run()
        result = self.complete(js=self.JS + b"const build = 2;", source_map=b"<html>not a source map</html>")
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["source_map_failures"], 1)
        self.assertEqual(self.map_items()[-1]["status"], "retry_pending")
        self.assertEqual([tuple(row) for row in self.db.all("SELECT owner_kind,owner_key,sha256 FROM cas_references WHERE owner_kind LIKE 'source_map%' ORDER BY owner_kind,owner_key")], refs)
        self.assertEqual(self.rows("source-map-work.jsonl")[0]["work_status"], "retry_pending")
        self.assertTrue(self.rows("source-map-work.jsonl")[0]["error"])
        self.assertEqual(self.resume_map()["collection_status"], "completed")

    def test_non_object_json_cannot_complete_map(self):
        for body in (b"[]", b"null", b'"text"', b"123", b""):
            with self.subTest(body=body):
                self.new_run()
                result = self.complete(source_map=body)
                self.assertEqual(result["collection_status"], "partial")
                self.assertEqual(self.map_items()[-1]["status"], "retry_pending")

    def test_missing_and_corrupt_completed_map_redownload_only_that_map(self):
        self.complete()
        digest = sha256_bytes(self.MAP_DATA)
        path = self.paths.state / self.db.one("SELECT relative_path FROM object_store WHERE sha256=?", (digest,))[0]
        for corruption in ("missing", "corrupt"):
            with self.subTest(corruption=corruption):
                if corruption == "missing":
                    path.unlink()
                else:
                    path.write_bytes(b"changed bytes")
                result = self.resume_map()
                self.assertEqual(result["collection_status"], "completed")
                self.assertEqual(path.read_bytes(), self.MAP_DATA)
                self.assertEqual(self.db.work_status(self.run_id, self.policy.name, "javascript-items", self.URL), "completed")
        self.assertEqual(self.map_items()[0]["attempts"], 3)

    def test_metadata_only_or_mismatched_map_completion_is_repaired(self):
        self.complete()
        work_id = self.map_items()[0]["id"]
        proof = json.loads(self.map_items()[0]["result_json"])
        for invalid in ({}, {**proof, "size": True}, {**proof, "source_map_url": "https://outside.test/other.map"}):
            with self.subTest(proof=invalid):
                self.db.execute("UPDATE work_items SET result_json=? WHERE id=?", (json.dumps(invalid), work_id))
                self.assertEqual(self.resume_map()["collection_status"], "completed")
        self.assertEqual(self.map_items()[0]["attempts"], 4)

    def test_missing_map_owner_reference_forces_repair_even_if_blob_exists(self):
        self.complete()
        store = ContentAddressedStore(self.paths, self.db)
        store.drop_reference("source_map", self.policy.name + "\n" + self.URL)
        self.assertEqual(self.resume_map()["collection_status"], "completed")
        self.assertEqual(self.map_items()[0]["attempts"], 2)

    def test_processing_error_requeues_map_while_parent_stays_completed(self):
        original = self.db.upsert_js_indicator

        def fail_embedded(*args, **kwargs):
            if args[2] == "source_map_source":
                raise RuntimeError("source-map processing failed")
            return original(*args, **kwargs)

        with patch.object(self.db, "upsert_js_indicator", side_effect=fail_embedded):
            with self.assertRaisesRegex(RuntimeError, "source-map processing failed"):
                self.complete()
        self.assertEqual(self.db.work_status(self.run_id, self.policy.name, "javascript-items", self.URL), "completed")
        self.assertEqual(self.map_items()[0]["status"], "retry_pending")
        self.assertEqual(self.resume_map()["collection_status"], "completed")

    def test_keyboard_interrupt_requeues_map_and_resume_keeps_parent(self):
        original = self.db.upsert_js_indicator

        def interrupt_embedded(*args, **kwargs):
            if args[2] == "source_map_source":
                raise KeyboardInterrupt()
            return original(*args, **kwargs)

        with patch.object(self.db, "upsert_js_indicator", side_effect=interrupt_embedded):
            with self.assertRaises(KeyboardInterrupt):
                self.complete()
        self.assertEqual(self.map_items()[0]["status"], "retry_pending")
        self.assertEqual(self.db.work_status(self.run_id, self.policy.name, "javascript-items", self.URL), "completed")
        self.assertEqual(self.resume_map()["collection_status"], "completed")

    def test_download_exception_is_persisted_without_losing_completed_parent(self):
        def download(_ctx, url, _limit):
            if url == self.URL:
                return self.result(url, self.JS)
            raise TimeoutError("Source Map timeout")

        with patch("stages._download_url", side_effect=download):
            result = stage_javascript(self.ctx)
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(self.map_items()[0]["error"], "Source Map timeout")
        self.assertEqual(json.loads(self.map_items()[0]["result_json"])["error"], "Source Map timeout")
        self.assertEqual(self.rows("source-map-work.jsonl")[0]["error"], "Source Map timeout")
        self.assertEqual(self.resume_map()["collection_status"], "completed")

    def test_http_status_and_failure_duration_are_persisted_without_body(self):
        result = self.first_failure({"url": self.MAP, "status_code": 503, "error": "http_error",
                                     "transport_status": "ok", "duration": 0.125})
        self.assertEqual(result["collection_status"], "partial")
        diagnostic = json.loads(self.map_items()[0]["result_json"])
        self.assertEqual(diagnostic["status_code"], 503)
        self.assertEqual(diagnostic["duration"], 0.125)
        self.assertNotIn("data", diagnostic)
        self.assertEqual(self.rows("source-map-work.jsonl")[0]["status_code"], 503)

    def test_partial_failed_or_out_of_scope_response_cannot_complete_even_with_json_bytes(self):
        for fields in ({"status_code": 206}, {"status_code": 503}, {"truncated": True},
                       {"redirect_outside_scope": True}, {"final_url": "https://outside.test/app.map"}):
            with self.subTest(fields=fields):
                self.new_run()
                self.first_failure({**self.result(self.MAP, self.MAP_DATA), **fields})
                self.assertEqual(self.map_items()[-1]["status"], "retry_pending")

    def test_map_limit_cannot_be_bypassed_by_valid_json(self):
        self.policy.limits.max_js_bytes = 100
        oversize = json.dumps({"sources": [], "padding": "x" * 100}).encode()
        result = self.complete(source_map=oversize)
        self.assertEqual(result["collection_status"], "partial")
        self.assertIn("file limit", self.map_items()[0]["error"])
        self.assertIsNone(self.db.one("SELECT sha256 FROM object_store WHERE sha256=?", (sha256_bytes(oversize),)))

    def test_operator_next_leaves_map_pending_until_resume(self):
        first = self.first_failure({"url": self.MAP, "operator_next": True})
        self.assertEqual(first["collection_status"], "partial")
        self.assertIn("operator_next", first["collection_reasons"])
        self.assertEqual(self.map_items()[0]["error"], "operator_next")
        self.assertEqual(self.resume_map()["collection_status"], "completed")

    def test_running_map_is_deferred_without_duplicate_request_or_completion(self):
        self.first_failure()
        queue = WorkQueue(self.db, self.run_id, self.policy.name, "javascript-source-map-items")
        work_id = self.map_items()[0]["id"]
        self.assertTrue(queue.start(work_id, "local-source-map"))
        with patch("stages._download_url", side_effect=AssertionError("running map requested twice")):
            result = stage_javascript(self.ctx)
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["source_map_deferred_work_items"], 1)
        self.assertEqual(result["source_map_attempts"], 0)
        self.assertEqual(self.map_items()[0]["status"], "running")
        self.assertEqual(self.map_items()[0]["attempts"], 2)

    def test_disabled_maps_respect_policy_and_retry_after_reenable(self):
        self.first_failure()
        self.policy.raw["javascript"] = {"download_source_maps": False}
        with patch("stages._download_url", side_effect=AssertionError("disabled map requested")):
            result = stage_javascript(self.ctx)
        self.assertEqual(result["collection_status"], "completed")
        self.assertEqual(result["source_map_pending_work_items"], 0)
        self.assertEqual(self.map_items()[0]["status"], "retry_pending")
        self.policy.raw["javascript"]["download_source_maps"] = True
        self.assertEqual(self.resume_map()["collection_status"], "completed")

    def test_out_of_scope_map_is_never_enqueued_or_requested(self):
        js = b"//# sourceMappingURL=https://outside.test/app.js.map\n"
        with patch("stages._download_url", return_value=self.result(self.URL, js)) as download:
            result = stage_javascript(self.ctx)
        download.assert_called_once_with(self.ctx, self.URL, self.policy.limits.max_js_bytes)
        self.assertEqual(result["collection_status"], "completed")
        self.assertEqual(self.map_items(), [])

    def test_not_found_parent_has_no_map_subtask_and_resumes_without_requests(self):
        with patch("stages._download_url", return_value={"url": self.URL, "status_code": 404, "not_found": True}):
            first = stage_javascript(self.ctx)
        self.assertEqual(first["collection_status"], "completed")
        with patch("stages._download_url", side_effect=AssertionError("not-found parent requested")):
            second = stage_javascript(self.ctx)
        self.assertEqual(second["collection_status"], "completed")
        self.assertEqual(self.map_items(), [])

    def test_map_subtask_identity_includes_parent_raw_hash_across_runs(self):
        self.complete()
        self.new_run()
        changed_js = self.JS + b"const build = 2;"
        self.complete(js=changed_js)
        items = self.map_items()
        self.assertEqual(len(items), 2)
        self.assertNotEqual(items[0]["item_key"], items[1]["item_key"])
        self.assertEqual(json.loads(items[1]["payload_json"])["js_raw_hash"], sha256_bytes(changed_js))
        self.assertEqual([row["attempts"] for row in items], [1, 1])

    def test_resumed_map_uses_existing_request_gate_and_budgets(self):
        self.first_failure()
        self.ctx.budget = BudgetManager.create(self.db, self.run_id, self.policy.name, self.policy)
        self.ctx.request_gate = MagicMock()

        def transport(url, _policy, **kwargs):
            kwargs["before_request"](url)
            return {"url": url, "status_code": 200, "data": self.MAP_DATA, "error": "",
                    "headers": {"Content-Type": "application/json"}, "transport_status": "ok"}

        with patch("stages.perform_pinned_download", side_effect=transport) as download:
            result = stage_javascript(self.ctx)
        self.assertEqual(download.call_count, 1)
        self.assertEqual(download.call_args.args[0], self.MAP)
        self.ctx.request_gate.assert_called_once_with(self.MAP)
        self.assertEqual(result["collection_status"], "completed")
        snapshot = self.ctx.budget.snapshot()
        self.assertEqual(snapshot["http_requests"]["used"], 1)
        self.assertEqual(snapshot["download_bytes"]["used"], len(self.MAP_DATA))
        with patch("stages.perform_pinned_download", side_effect=AssertionError("cache requested transport")):
            stage_javascript(self.ctx)
        self.assertEqual(self.ctx.budget.snapshot(), snapshot)

    def test_exhausted_request_budget_blocks_map_request_and_leaves_it_pending(self):
        self.first_failure()
        self.policy.limits.max_http_requests = 1
        self.ctx.budget = BudgetManager.create(self.db, self.run_id, self.policy.name, self.policy)
        self.ctx.budget.consume("http_requests")

        def transport(url, _policy, **kwargs):
            kwargs["before_request"](url)
            self.fail("budget allowed a map request")

        with patch("stages.perform_pinned_download", side_effect=transport):
            result = stage_javascript(self.ctx)
        self.assertEqual(result["collection_status"], "partial")
        self.assertIn("Run budget exhausted", self.map_items()[0]["error"])
        self.assertEqual(self.db.work_status(self.run_id, self.policy.name, "javascript-items", self.URL), "completed")

    def test_incomplete_map_resume_does_not_advance_successful_source_snapshot(self):
        self.complete()
        self.db.finish_run_target(self.run_id, self.policy.name, "success")
        baseline = self.db.one("SELECT committed_run_id FROM successful_recon_derived_sets WHERE target=? AND state_type='source_map_source'", (self.policy.name,))[0]
        self.new_run()
        self.first_failure()
        self.db.finish_run_target(self.run_id, self.policy.name, "partial")
        self.assertEqual(self.db.one("SELECT committed_run_id FROM successful_recon_derived_sets WHERE target=? AND state_type='source_map_source'", (self.policy.name,))[0], baseline)
        self.resume_map()
        record_target_lifecycle(self.db, self.run_id, self.policy.name, collection_status="success",
                                analysis_status="not_run", report_status="not_run",
                                notification_status="not_run", overall_status="partial",
                                baseline_reason="collection_complete", details_json="{}")
        self.db.finish_run_target(self.run_id, self.policy.name, "success")
        self.assertEqual(self.db.one("SELECT committed_run_id FROM successful_recon_derived_sets WHERE target=? AND state_type='source_map_source'", (self.policy.name,))[0], self.run_id)

    def test_real_stage_resume_persists_partial_then_success_for_map_retry(self):
        orchestrator = Orchestrator(self.paths, self.ctx.config, self.ctx.logger, self.db,
                                    progress=False, allow_active=False)
        self.addCleanup(orchestrator.db_writer.close)
        self.ctx.progress, self.ctx.runner = orchestrator.progress, orchestrator.runner
        args = (self.ctx, "javascript", "JavaScript", 1, 1, 1, 1, True)
        with patch("stages._download_url", side_effect=lambda _ctx, url, _limit:
                   self.result(url, self.JS) if url == self.URL else {"url": url, "error": "timeout"}):
            status, first = orchestrator._run_stage(*args, False)
        self.assertEqual(status, "success")
        self.assertEqual(first["collection_status"], "partial")
        self.assertEqual(self.db.stage_status(self.run_id, self.policy.name, "javascript"), "partial")
        with patch("stages._download_url", return_value=self.result(self.MAP, self.MAP_DATA)) as download:
            status, resumed = orchestrator._run_stage(*args, True)
        download.assert_called_once_with(self.ctx, self.MAP, self.policy.limits.max_js_bytes)
        self.assertEqual(status, "success")
        self.assertEqual(resumed["collection_status"], "completed")
        self.assertEqual(self.db.stage_status(self.run_id, self.policy.name, "javascript"), "success")


if __name__ == "__main__":
    unittest.main()
