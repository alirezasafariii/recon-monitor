from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "app", ROOT / "tools"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from core import AppPaths, Config, Database, ReconError, TargetPolicy
from js_stage_isolated import prior_validation_hashes, run_isolated_stage
from js_validation import select_fresh_js


class IsolatedJavascriptStageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.paths = AppPaths.from_root(Path(temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.config = Config(self.paths)
        self.policy = TargetPolicy.from_dict({
            "name": "example.test", "roots": ["example.test"],
            "limits": {"max_js_files": 4, "js_workers": 3, "request_rate": 3},
            "analysis": {"asset_graph": False},
        })
        self.source_id = "20260920-064940-d4f63ee0"
        self.current = (
            self.paths.output / self.policy.name / "runs"
            / self.source_id / "current"
        )
        self.current.mkdir(parents=True)
        (self.current / "urls.txt").write_text(
            "".join(f"https://a.example.test/{i}.js\n" for i in range(3)),
            encoding="utf-8",
        )
        (self.current / "javascript-availability.jsonl").write_text(
            "", encoding="utf-8",
        )
        (self.current / "url-collection.json").write_text(
            json.dumps({
                "run_id": self.source_id, "target": self.policy.name,
                "metrics": {"collection_status": "completed"},
            }),
            encoding="utf-8",
        )
        source_db = Database(self.paths.db)
        source_db.close()

    def test_previously_validated_hashes_are_excluded_from_next_stage_plan(self):
        previous_url = "https://a.example.test/0.js"
        previous = (
            self.paths.output / self.policy.name / "js-validations"
            / f"{self.source_id}-previous"
        )
        previous.mkdir(parents=True)
        digest = hashlib.sha256(previous_url.encode("utf-8")).hexdigest()
        (previous / "results.jsonl").write_text(
            json.dumps({"url_sha256": digest, "status_code": 200}) + "\n",
            encoding="utf-8",
        )
        excluded = prior_validation_hashes(
            self.paths, self.policy.name, self.source_id,
        )
        self.assertEqual(excluded, frozenset({digest}))
        chosen, _ = select_fresh_js(
            self.current,
            run_id=self.source_id,
            target=self.policy.name,
            policy=self.policy,
            allowed_hosts=("a.example.test",),
            max_new=2, per_host=3,
            excluded_url_sha256=excluded,
        )
        self.assertEqual(chosen, [
            "https://a.example.test/1.js",
            "https://a.example.test/2.js",
        ])

    def test_source_evidence_and_database_untouched_and_map_fetch_disabled(self):
        original_files = {
            p.name: p.read_bytes() for p in self.current.iterdir() if p.is_file()
        }
        original_db_bytes = self.paths.db.read_bytes()
        network = []

        def fake_transport(url, policy, **kwargs):
            self.assertEqual(kwargs["max_redirects"], 0)
            self.assertEqual(kwargs["max_response_bytes"], self.policy.limits.max_js_bytes)
            kwargs["before_request"](url)
            network.append(url)
            return {
                "status_code": 200,
                "final_url": url,
                "headers": {"Content-Type": "application/javascript"},
                "data": b"const answer = 42;\n//# sourceMappingURL=secret.js.map",
            }

        with patch("stages.perform_pinned_download", side_effect=fake_transport):
            out, summary = run_isolated_stage(
                self.paths, self.config, self.policy, self.source_id,
                ["https://a.example.test/0.js", "https://a.example.test/1.js"],
            )
        self.assertEqual(len(network), 2)
        self.assertEqual(summary["network_requests_observed"], 2)
        self.assertEqual(summary["downloaded"], 2)
        self.assertEqual(summary["collection_status"], "partial")
        self.assertEqual(
            original_files,
            {p.name: p.read_bytes() for p in self.current.iterdir() if p.is_file()},
        )
        self.assertEqual(original_db_bytes, self.paths.db.read_bytes())
        self.assertFalse(self.paths.lock.exists())
        self.assertFalse((self.paths.output / self.policy.name / "LATEST").exists())
        self.assertFalse((self.paths.output / self.policy.name / "latest").exists())
        self.assertTrue((out / "state" / "recon-v2.db").is_file())
        stage_results = list((out / "output" / self.policy.name / "runs").glob(
            "*/current/source-map-sources.jsonl"
        ))
        self.assertEqual(len(stage_results), 1)
        self.assertEqual(stage_results[0].read_text(), "")
        sandbox_db = Database(out / "state" / "recon-v2.db")
        try:
            run = sandbox_db.one("SELECT status FROM runs LIMIT 1")
            self.assertEqual(run["status"], "partial")
            self.assertEqual(
                int(sandbox_db.one("SELECT COUNT(*) AS n FROM js_files")["n"]), 2,
            )
        finally:
            sandbox_db.close()

    def test_http_429_prevents_any_further_pinned_requests(self):
        calls = []

        def fake_transport(url, policy, **kwargs):
            kwargs["before_request"](url)
            calls.append(url)
            if len(calls) == 2:
                return {
                    "status_code": 429, "final_url": url,
                    "headers": {"Content-Type": "text/plain"},
                    "error": "http_error",
                }
            return {
                "status_code": 200, "final_url": url,
                "headers": {"Content-Type": "application/javascript"},
                "data": b"const value = 1;",
            }

        with patch("stages.perform_pinned_download", side_effect=fake_transport):
            _, summary = run_isolated_stage(
                self.paths, self.config, self.policy, self.source_id,
                [f"https://a.example.test/{i}.js" for i in range(3)],
            )
        self.assertEqual(len(calls), 2)
        self.assertEqual(summary["network_requests_observed"], 2)
        self.assertEqual(summary["stopped_after_http_status"], 429)
        self.assertEqual(summary["downloaded"], 1)
        self.assertEqual(summary["collection_status"], "partial")

    def test_denies_execution_without_authorization_or_for_out_of_scope(self):
        denied = Config(self.paths)
        denied.values["I_HAVE_AUTHORIZATION"] = "no"
        with self.assertRaises(ReconError):
            run_isolated_stage(
                self.paths, denied, self.policy, self.source_id,
                ["https://a.example.test/0.js"],
            )
        with self.assertRaises(ReconError):
            run_isolated_stage(
                self.paths, self.config, self.policy, self.source_id,
                ["https://outside.invalid/0.js"],
            )
        self.assertFalse(self.paths.lock.exists())


if __name__ == "__main__":
    unittest.main()
