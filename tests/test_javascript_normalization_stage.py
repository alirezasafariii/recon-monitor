from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from core import AppPaths, Config, Database, Logger, TargetPolicy, sha256_text
from stages import StageContext, stage_javascript


class JavaScriptNormalizationStageTests(unittest.TestCase):
    URL = "https://example.test/app.js"

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect", "urllib.request.urlopen"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.paths = AppPaths.from_root(Path(temporary.name))
        self.paths.ensure()
        self.db = Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.policy = TargetPolicy.from_dict({"name": "example.test", "roots": ["example.test"],
                                             "javascript": {"download_source_maps": False}})

    def run_js(self, data):
        run_id = self.db.create_run(self.policy.name, 1, "offline")
        run_dir = self.paths.output / run_id
        self.db.create_run_target(run_id, self.policy, run_dir, False)
        self.ctx = StageContext(self.paths, Config(self.paths), self.policy, self.db, Logger(self.paths),
                                SimpleNamespace(), MagicMock(), run_id, run_dir, False)
        (self.ctx.current / "urls.txt").write_text(self.URL + "\n")
        (self.ctx.current / "url-collection.json").write_text(json.dumps({
            "run_id": run_id, "target": self.policy.name, "metrics": {"collection_status": "completed"},
        }))
        with patch("stages._download_url", return_value={"url": self.URL, "data": data,
                                                       "status_code": 200, "content_type": "application/javascript"}):
            return stage_javascript(self.ctx)

    def test_two_runs_record_changed_string_as_semantic_change(self):
        self.run_js(b'const redirect="//first.example/path";')
        result = self.run_js(b'const redirect="//second.example/path";')
        self.assertEqual(result["raw_changed"], 1)
        self.assertEqual(result["semantic_changed"], 1)
        self.assertEqual((self.ctx.changes / "semantic-js-changes.txt").read_text(), self.URL + "\n")
        events = [json.loads(line) for line in self.ctx.events_path.read_text().splitlines()]
        event = next(event for event in events if event["category"] == "changed_js")
        self.assertTrue(event["details"]["semantic_changed"])
        diff = self.db.one("SELECT old_semantic_hash,new_semantic_hash,diff_text FROM js_diffs WHERE run_id=?", (self.ctx.run_id,))
        self.assertNotEqual(diff["old_semantic_hash"], diff["new_semantic_hash"])
        self.assertIn("//second.example/path", diff["diff_text"])

    def test_identical_raw_content_rehashes_legacy_digest_without_change(self):
        source = b"const value = 1;"
        self.run_js(source)
        self.db.execute("UPDATE js_files SET semantic_hash=?,last_changed='unchanged-marker'", (sha256_text("const value=1;"),))
        result = self.run_js(source)
        self.assertEqual(result["raw_changed"], 0)
        self.assertEqual(result["semantic_changed"], 0)
        self.assertEqual(self.db.one("SELECT last_changed FROM js_files")[0], "unchanged-marker")

    def test_formatting_only_change_uses_recomputed_legacy_baseline(self):
        self.run_js(b"const value = 1; // first build")
        self.db.execute("UPDATE js_files SET semantic_hash=?,last_changed='unchanged-marker'", (sha256_text("const value=1;"),))
        result = self.run_js(b"const   value=1; // next build")
        self.assertEqual(result["raw_changed"], 1)
        self.assertEqual(result["semantic_changed"], 0)
        self.assertEqual(self.db.one("SELECT last_changed FROM js_files")[0], "unchanged-marker")

    def test_changed_template_is_preserved_and_semantic_comparison_is_unknown(self):
        self.run_js(b'const url=`//first.example/${value}`;')
        result = self.run_js(b'const url=`//second.example/${value}`;')
        self.assertEqual(result['raw_changed'], 1)
        self.assertEqual(result['semantic_changed'], 0)
        self.assertEqual(result['semantic_unknown'], 1)
        self.assertEqual((self.ctx.changes / 'semantic-js-unknown.txt').read_text(), self.URL + '\n')
        events = [json.loads(line) for line in self.ctx.events_path.read_text().splitlines()]
        details = next(event['details'] for event in events if event['category'] == 'changed_js')
        self.assertEqual(details['semantic_comparison'], 'unknown')
        self.assertIsNone(details['semantic_changed'])
        self.assertEqual(details['semantic_normalization_reason'], 'template_requires_parser')
        self.assertFalse(any('Raw-only' in reason for event in events for reason in event['risk_reasons']))

    def test_missing_previous_artifact_cannot_be_called_formatting_only(self):
        self.run_js(b'const value=1;')
        Path(self.db.one('SELECT blob_path FROM js_files')[0]).unlink()
        result = self.run_js(b'const value = 1;')
        self.assertEqual(result['raw_changed'], 1)
        self.assertEqual(result['semantic_unknown'], 1)

    def test_corrupt_previous_artifact_is_not_used_as_a_baseline(self):
        self.run_js(b'const value=1;')
        Path(self.db.one('SELECT blob_path FROM js_files')[0]).write_bytes(b'const value=2;')
        result = self.run_js(b'const value=2;')
        self.assertEqual(result['semantic_unknown'], 1)

    def test_previous_crlf_literal_bytes_are_not_converted_during_comparison(self):
        source = b'const value="first\\\r\n second";'
        self.run_js(source + b' // first build')
        self.db.execute("UPDATE js_files SET last_changed='unchanged-marker'")
        result = self.run_js(source + b' // next build')
        self.assertEqual(result['raw_changed'], 1)
        self.assertEqual(result['semantic_changed'], 0)
        self.assertEqual(result['semantic_unknown'], 0)
        self.assertEqual(self.db.one('SELECT last_changed FROM js_files')[0], 'unchanged-marker')

    def test_distinct_invalid_utf8_bodies_keep_distinct_durable_fingerprints(self):
        self.run_js(b'const value="\xff";')
        previous = self.db.one('SELECT semantic_hash FROM js_files')[0]
        result = self.run_js(b'const value="\xfe";')
        self.assertEqual(result['raw_changed'], 1)
        self.assertEqual(result['semantic_unknown'], 1)
        self.assertEqual(result['semantic_normalization_fallbacks'], 1)
        self.assertNotEqual(self.db.one('SELECT semantic_hash FROM js_files')[0], previous)

    def test_legacy_completed_resume_rehashes_from_cas_without_requests(self):
        self.run_js(b'const value=1;')
        legacy = sha256_text('const value=1;')
        self.db.execute('UPDATE js_files SET semantic_hash=?', (legacy,))
        row = self.db.one("SELECT id,result_json FROM work_items WHERE stage='javascript-items'")
        saved = json.loads(row['result_json'])
        saved['semantic_hash'] = legacy
        for key in list(saved):
            if key.startswith('semantic_normalization'):
                del saved[key]
        self.db.execute('UPDATE work_items SET result_json=? WHERE id=?', (json.dumps(saved), row['id']))
        with patch('stages._download_url', side_effect=AssertionError('valid Resume attempted network')):
            result = stage_javascript(self.ctx)
        self.assertEqual(result['download_attempts'], 0)
        self.assertEqual(result['semantic_changed'], 0)
        self.assertNotEqual(self.db.one('SELECT semantic_hash FROM js_files')[0], legacy)
        resumed = json.loads(self.db.one('SELECT result_json FROM work_items WHERE id=?', (row['id'],))[0])
        self.assertEqual(resumed['semantic_hash'], self.db.one('SELECT semantic_hash FROM js_files')[0])
        self.assertEqual(resumed['semantic_normalization_version'], 1)


if __name__ == "__main__":
    unittest.main()
