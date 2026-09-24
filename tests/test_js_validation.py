from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "app", ROOT / "tools"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from core import AppPaths, Config, ReconError, TargetPolicy
from js_validation import execute_validation, select_fresh_js
from stages import _download_url


class SavedRunJSValidationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.paths = AppPaths.from_root(Path(temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.config = Config(self.paths)
        self.policy = TargetPolicy.from_dict({
            "name": "example.test", "roots": ["example.test"],
            "limits": {"max_js_files": 3, "request_rate": 3},
        })
        self.run_id = "20260920-064940-d4f63ee0"
        self.current = (self.paths.output / self.policy.name / "runs"
                        / self.run_id / "current")
        self.current.mkdir(parents=True)
        (self.current / "url-collection.json").write_text(json.dumps({
            "run_id": self.run_id, "target": self.policy.name,
            "metrics": {"collection_status": "completed"},
        }), encoding="utf-8")
        urls = [
            "https://a.example.test/0.js",
            "https://a.example.test/1.js",
            "https://a.example.test/2.js",
            "https://b.example.test/0.js",
            "https://b.example.test/1.js",
            "https://b.example.test/query.js?token=x",
            "https://outside.invalid/0.js",
        ]
        (self.current / "urls.txt").write_text(
            "\n".join(urls) + "\n", encoding="utf-8",
        )
        (self.current / "javascript-availability.jsonl").write_text(
            json.dumps({"url": "https://a.example.test/0.js",
                        "state": "not_found", "status_code": 404}) + "\n",
            encoding="utf-8",
        )

    def plan(self, **kwargs):
        return select_fresh_js(
            self.current,
            run_id=self.run_id, target=self.policy.name, policy=self.policy,
            allowed_hosts=("a.example.test", "b.example.test"),
            max_new=3, per_host=2, **kwargs,
        )

    def test_preview_selects_only_new_scoped_quota_urls_and_is_read_only(self):
        before = {
            p.name: p.read_bytes()
            for p in self.current.iterdir() if p.is_file()
        }
        chosen, counts = self.plan()
        self.assertEqual(chosen, [
            "https://b.example.test/0.js",
            "https://a.example.test/1.js",
        ])
        self.assertEqual(counts, {"a.example.test": 1, "b.example.test": 1})
        self.assertEqual(
            before,
            {p.name: p.read_bytes() for p in self.current.iterdir() if p.is_file()},
        )

    def test_rejects_unsafe_scope_and_invalid_caps_without_network(self):
        with self.assertRaises(ReconError):
            self.plan(allowed_hosts=("outside.invalid",))
        with self.assertRaises(ReconError):
            self.plan(max_new=13)
        with self.assertRaises(ReconError):
            self.plan(run_id="../another-run")
        (self.current / "url-collection.json").write_text(
            json.dumps({"run_id": self.run_id, "target": "other.test"}),
            encoding="utf-8",
        )
        with self.assertRaises(ReconError):
            self.plan()

    def test_execute_uses_pinned_downloader_no_redirects_and_isolated_evidence(self):
        initial = {
            p.name: p.read_bytes()
            for p in self.current.iterdir() if p.is_file()
        }
        urls = [
            "https://a.example.test/1.js",
            "https://b.example.test/0.js",
            "https://a.example.test/2.js",
        ]
        downloaded = []
        pauses = []

        def downloader(_ctx, url, _max_bytes, *, max_redirects):
            self.assertEqual(max_redirects, 0)
            downloaded.append(url)
            if len(downloaded) == 1:
                return {"url": url, "status_code": 200,
                        "content_type": "application/javascript",
                        "data": b"const x=1;"}
            if len(downloaded) == 2:
                return {"url": url, "status_code": 200,
                        "content_type": "text/html", "data": b"<html/>"}
            return {"url": url, "status_code": 429, "error": "http_error"}

        directory, rows = execute_validation(
            self.paths, self.config, self.policy, self.run_id, urls,
            download=downloader, pause=pauses.append,
        )
        self.assertEqual(downloaded, urls)
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            [r["state"] for r in rows],
            ["javascript", "unexpected_content_type", "error"],
        )
        self.assertEqual(rows[-1]["status_code"], 429)
        self.assertEqual(pauses, [1 / 3, 1 / 3])
        self.assertFalse(self.paths.lock.exists())
        self.assertNotIn("1.js", (directory / "results.jsonl").read_text())
        self.assertEqual(
            json.loads((directory / "summary.json").read_text())["attempted"],
            3,
        )
        self.assertEqual(
            initial,
            {p.name: p.read_bytes() for p in self.current.iterdir() if p.is_file()},
        )

    def test_pinned_download_respects_opt_in_zero_redirects(self):
        ctx = SimpleNamespace(
            policy=self.policy, config=self.config, budget=None,
            next_requested=lambda: False,
        )
        with patch("stages.perform_pinned_download", return_value={
            "status_code": 302, "error": "redirect_limit_exceeded",
        }) as transport:
            result = _download_url(ctx, "https://a.example.test/1.js",
                                   4096, max_redirects=0)
        self.assertEqual(result["status_code"], 302)
        self.assertEqual(transport.call_args.kwargs["max_redirects"], 0)


if __name__ == "__main__":
    unittest.main()
