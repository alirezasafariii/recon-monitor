from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from core import AppPaths, Config, Logger, TargetPolicy, classify_url
from recon_monitor_core import Database
from stages import StageContext, stage_javascript, stage_urls


class JavascriptExecutionQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        paths = AppPaths.from_root(Path(self.tmp.name))
        paths.ensure()
        db = Database(paths.db)
        self.addCleanup(db.close)
        policy = TargetPolicy.from_dict({
            "name": "example.test", "roots": ["example.test"],
            "limits": {"timeout_seconds": 1800, "request_rate": 3},
            "javascript": {"download_source_maps": False},
        })
        run_id = db.create_run(policy.name, 1, "offline")
        run_dir = paths.output / run_id
        db.create_run_target(run_id, policy, run_dir, True)
        self.ctx = StageContext(
            paths, Config(paths), policy, db, Logger(paths), SimpleNamespace(),
            MagicMock(), run_id, run_dir, False,
        )

    def inputs(self, urls, *, upstream_status="completed", dropped=0):
        (self.ctx.current / "urls.txt").write_text("".join(url + "\n" for url in urls))
        (self.ctx.current / "url-collection.json").write_text(json.dumps({
            "run_id": self.ctx.run_id, "target": self.ctx.policy.name,
            "metrics": {"collection_status": upstream_status, "url_selection": {
                "javascript_candidates": sum(classify_url(url) == "javascript" for url in urls) + dropped,
                "javascript_dropped": dropped,
            }},
        }))

    def test_missing_url_file_is_partial_not_completed(self):
        with patch("stages._download_url") as download, patch(
            "stages._prepare_javascript_derived_differentials", return_value=([], {}),
        ) as derived:
            result = stage_javascript(self.ctx)
        download.assert_not_called()
        self.assertEqual(result["collection_status"], "partial")
        self.assertIn("url_input_missing", result["zero_download_reasons"])
        self.assertFalse(derived.call_args.kwargs["chunks_complete"])

    def test_no_classified_js_is_no_input_with_explicit_classifier(self):
        self.inputs(["https://example.test/", "https://example.test/script?id=1"])
        with patch("stages._download_url") as download:
            result = stage_javascript(self.ctx)
        download.assert_not_called()
        self.assertEqual(result["collection_status"], "no_input")
        self.assertEqual(result["classification_method"], "url_path_extension")
        self.assertEqual(result["zero_download_reasons"], ["no_javascript_urls_classified"])
        self.assertEqual(result["source_url_count"], 2)

    def test_partial_url_collection_does_not_prepare_empty_removals(self):
        self.inputs([], upstream_status="partial")
        with patch("stages._prepare_javascript_derived_differentials", return_value=([], {})) as derived:
            result = stage_javascript(self.ctx)
        self.assertEqual(result["collection_status"], "partial")
        self.assertIn("upstream_url_collection_partial", result["zero_download_reasons"])
        self.assertFalse(derived.call_args.kwargs["chunks_complete"])
        self.assertFalse(derived.call_args.kwargs["source_maps_complete"])

    def test_url_selection_reports_discovered_js_removed_by_cap(self):
        self.ctx.policy.limits.max_urls = 100
        js_url = "https://example.test/app.js"

        def fake_run(_args, **kwargs):
            lines = [f"https://example.test/api/user/{index}" for index in range(100)] + [js_url]
            Path(kwargs["output_path"]).write_text("\n".join(lines) + "\n")
            return SimpleNamespace(returncode=0, timed_out=False, duration=0.01, lines=len(lines))

        self.ctx.runner = SimpleNamespace(run=fake_run)
        with patch("stages.tool_path", side_effect=lambda name: name == "katana"), patch(
            "stages._probe_live_origins", return_value=(["https://example.test"], []),
        ):
            url_result = stage_urls(self.ctx)
        selection = url_result["url_selection"]
        self.assertEqual(selection["javascript_candidates"], 1)
        self.assertEqual(selection["javascript_selected"], 0)
        self.assertEqual(selection["javascript_dropped"], 1)
        evidence = json.loads((self.ctx.current / "javascript-selection.jsonl").read_text())
        self.assertEqual(evidence["url"], js_url)
        self.assertEqual(evidence["reason"], "max_urls")
        with patch("stages._download_url") as download:
            result = stage_javascript(self.ctx)
        download.assert_not_called()
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["javascript_discovered"], 1)
        self.assertIn("url_selection_limit", result["zero_download_reasons"])

    def test_download_error_is_partial(self):
        url = "https://example.test/private.js"
        self.inputs([url])
        with patch("stages._download_url", return_value={"url": url, "status_code": 403, "error": "http_error"}):
            result = stage_javascript(self.ctx)
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["download_attempts"], 1)
        self.assertEqual(result["downloaded"], 0)
        self.assertEqual(result["zero_download_reasons"], ["download_errors"])

    def test_wrong_content_type_finishes_work_attempt_and_records_cause(self):
        url = "https://example.test/app.js"
        self.inputs([url])
        with patch("stages._download_url", return_value={
            "url": url, "status_code": 200, "data": b"<html>Login</html>", "content_type": "text/html",
        }):
            result = stage_javascript(self.ctx)
        self.assertEqual(result["collection_status"], "partial")
        self.assertEqual(result["unexpected_content_types"], 1)
        self.assertEqual(result["zero_download_reasons"], ["unexpected_content_type"])
        self.assertEqual(self.ctx.db.work_status(
            self.ctx.run_id, self.ctx.policy.name, "javascript-items", url,
        ), "retry_pending")

    def test_not_found_is_accounted_separately_from_download_errors(self):
        url = "https://example.test/old.js"
        self.inputs([url])
        with patch("stages._download_url", return_value={"url": url, "status_code": 404, "not_found": True}):
            result = stage_javascript(self.ctx)
        self.assertEqual(result["not_found"], 1)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(result["zero_download_reasons"], ["not_found"])

    def test_completed_work_is_reported_as_reused_not_no_discovery(self):
        url = "https://example.test/app.js"
        self.inputs([url])
        item_id = self.ctx.db.enqueue_work(self.ctx.run_id, self.ctx.policy.name, "javascript-items", url)
        self.ctx.db.work_start(item_id)
        self.ctx.db.work_finish(item_id, {"raw_hash": "offline"})
        with patch("stages._download_url") as download:
            result = stage_javascript(self.ctx)
        download.assert_not_called()
        self.assertEqual(result["input_url_count"], 1)
        self.assertEqual(result["reused_work_items"], 1)
        self.assertEqual(result["zero_download_reasons"], ["already_processed"])

    def test_js_file_limit_and_mjs_query_classification_are_recorded(self):
        self.ctx.policy.limits.max_js_files = 1
        urls = ["https://example.test/a.MJS?v=1", "https://example.test/b.js"]
        self.inputs(urls)
        with patch("stages._download_url", side_effect=lambda _ctx, url, _limit: {
            "url": url, "status_code": 200, "data": b"const value = 1;", "content_type": "application/javascript",
        }) as download:
            result = stage_javascript(self.ctx)
        self.assertEqual(download.call_count, 1)
        self.assertEqual(result["input_url_count"], 2)
        self.assertEqual(result["downloaded"], 1)
        self.assertEqual(result["javascript_dropped_by_file_limit"], 1)
        self.assertEqual(result["collection_status"], "partial")
        self.assertIn("javascript_file_limit", result["collection_reasons"])


if __name__ == "__main__":
    unittest.main()
