from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from core import AppPaths, TargetPolicy, json_dumps, sha256_text
from derived_change_advisory import _signal_affinity, _validated_signal
from stages import _prepare_javascript_derived_differentials, _source_map_entries
from storage import ContentAddressedStore
from successful_snapshot import SuccessfulSnapshotDatabase


class JavaScriptNormalizationSourceTests(unittest.TestCase):
    TARGET = "example.test"
    JS = "https://example.test/app.js"
    MAP = JS + ".map"

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect", "urllib.request.urlopen"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.paths = AppPaths.from_root(Path(temporary.name))
        self.paths.ensure()
        self.db = SuccessfulSnapshotDatabase(self.paths.db)
        self.addCleanup(self.db.close)
        self.store = ContentAddressedStore(self.paths, self.db)
        self.policy = TargetPolicy.from_dict({"name": self.TARGET, "roots": [self.TARGET]})

    def prepare(self, content, *, baseline=False):
        entry = _source_map_entries(self.MAP, {"sources": ["src/client.js"], "sourcesContent": [content]})[0]
        self.store.put(content.encode(), content_type="text/plain")
        entry.update(js_url=self.JS, source_map_url=self.MAP, source_map_hash="fixture-map")
        run_id = self.db.create_run(self.TARGET, 1, "offline")
        self.db.create_run_target(run_id, self.policy, self.paths.output / run_id, baseline)
        ctx = SimpleNamespace(paths=self.paths, db=self.db, run_id=run_id, policy=self.policy)
        signals, _meta = _prepare_javascript_derived_differentials(ctx, [entry], [], source_maps_complete=True, chunks_complete=True)
        return run_id, signals

    def set_legacy_hash(self, digest):
        row = self.db.one("SELECT item_key,item_json FROM successful_recon_derived_state WHERE state_type='source_map_source'")
        payload = json.loads(row['item_json'])
        payload['semantic_hash'] = digest
        text = json_dumps(payload)
        self.db.execute("UPDATE successful_recon_derived_state SET item_json=?,item_hash=? WHERE item_key=?",
                        (text, sha256_text(text), row['item_key']))

    def test_source_map_string_change_is_not_lost_in_hash_or_signal(self):
        first, _ = self.prepare('const redirect="//first.example/path";', baseline=True)
        self.db.finish_run_target(first, self.TARGET, 'success')
        self.set_legacy_hash(sha256_text('const redirect="'))
        _run, signals = self.prepare('const redirect="//second.example/path";')
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]['semantic_comparison'], 'changed')
        self.assertNotEqual(signals[0]['before']['semantic_hash'], signals[0]['after']['semantic_hash'])

    def test_equal_source_bytes_do_not_emit_algorithm_upgrade_signal(self):
        first, _ = self.prepare('const value=1;', baseline=True)
        self.db.finish_run_target(first, self.TARGET, 'success')
        self.set_legacy_hash(sha256_text('const value=1;'))
        _run, signals = self.prepare('const value=1;')
        self.assertEqual(signals, [])

    def test_template_source_stays_unknown_through_advisory_validation(self):
        first, _ = self.prepare('const url=`//first.example/${value}`;', baseline=True)
        self.db.finish_run_target(first, self.TARGET, 'success')
        run_id, signals = self.prepare('const url=`//second.example/${value}`;')
        self.assertEqual(len(signals), 1)
        row = _validated_signal(signals[0], run_id=run_id, target=self.TARGET)
        self.assertEqual(row['semantic_comparison'], 'unknown')
        arguments = dict(endpoint=self.JS, source_ref='src/client.js', summary='')
        score, reasons = _signal_affinity(row, **arguments)
        known_score, _ = _signal_affinity({**row, 'semantic_comparison': 'changed'}, **arguments)
        self.assertEqual(known_score, score + 8)
        self.assertFalse(any('semantic hash changed' in reason for reason in reasons))


if __name__ == '__main__':
    unittest.main()
