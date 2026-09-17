from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from analysis import _snapshot
from core import APP_VERSION, AppPaths, TargetPolicy, utc_now, write_jsonl
from stages import _prepare_javascript_derived_differentials
from successful_snapshot import SuccessfulSnapshotDatabase


class ReconP3DerivedDifferentialTests(unittest.TestCase):
    TARGET = "example.test"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.db = SuccessfulSnapshotDatabase(self.paths.db)
        self.policy = TargetPolicy.from_dict(
            {"name": self.TARGET, "roots": [self.TARGET]}
        )

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _start(self, run_id: str, *, baseline: bool = False) -> None:
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,target_selector,target_count) "
            "VALUES(?,?,?,?,?,1)",
            (run_id, APP_VERSION, "running", now, self.TARGET),
        )
        run_dir = self.paths.output / self.TARGET / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        self.db.create_run_target(run_id, self.policy, run_dir, baseline)

    def test_failed_run_never_promotes_derived_state(self) -> None:
        self._start("RUN-1", baseline=True)
        first = self.db.replace_recon_derived_working_state(
            "RUN-1",
            self.TARGET,
            "source_map_source",
            {
                "a": {"source_name": "src/a.ts", "content_hash": "h1"},
                "c": {"source_name": "src/c.ts", "content_hash": "hc"},
            },
        )
        self.assertFalse(first["baseline_exists"])
        self.db.finish_run_target("RUN-1", self.TARGET, "success")

        status = self.db.successful_snapshot_status(self.TARGET)
        self.assertEqual(status["derived_set_count"], 1)
        self.assertEqual(status["derived_row_count"], 2)

        self._start("RUN-BAD")
        bad = self.db.replace_recon_derived_working_state(
            "RUN-BAD",
            self.TARGET,
            "source_map_source",
            {
                "a": {"source_name": "src/a.ts", "content_hash": "h2"},
                "b": {"source_name": "src/b.ts", "content_hash": "hb"},
            },
        )
        self.assertEqual(bad["baseline_run_id"], "RUN-1")
        self.assertEqual([row["item_key"] for row in bad["added"]], ["b"])
        self.assertEqual([row["item_key"] for row in bad["removed"]], ["c"])
        self.assertEqual([row["item_key"] for row in bad["changed"]], ["a"])
        self.db.finish_run_target("RUN-BAD", self.TARGET, "failed")

        self._start("RUN-2")
        again = self.db.replace_recon_derived_working_state(
            "RUN-2",
            self.TARGET,
            "source_map_source",
            {
                "a": {"source_name": "src/a.ts", "content_hash": "h2"},
                "b": {"source_name": "src/b.ts", "content_hash": "hb"},
            },
        )
        self.assertEqual(again["baseline_run_id"], "RUN-1")
        self.assertEqual([row["item_key"] for row in again["added"]], ["b"])
        self.assertEqual([row["item_key"] for row in again["removed"]], ["c"])
        self.assertEqual([row["item_key"] for row in again["changed"]], ["a"])
        self.db.finish_run_target("RUN-2", self.TARGET, "success")

        self._start("RUN-3")
        removed = self.db.replace_recon_derived_working_state(
            "RUN-3",
            self.TARGET,
            "source_map_source",
            {},
        )
        self.assertEqual(removed["baseline_run_id"], "RUN-2")
        self.assertEqual(
            [row["item_key"] for row in removed["removed"]],
            ["a", "b"],
        )

    def test_incomplete_source_map_collection_does_not_advance_that_set(self) -> None:
        source_v1 = {
            "js_url": "https://example.test/app.js",
            "source_map_url": "https://example.test/app.js.map",
            "source_identity": "https://example.test/app.js.map#0:src/a.ts",
            "source_name": "src/a.ts",
            "content_hash": "h1",
            "semantic_hash": "s1",
            "embedded": True,
        }
        chunk_v1 = {
            "js_url": "https://example.test/app.js",
            "chunk_url": "https://example.test/chunk-a.js",
        }

        self._start("RUN-A", baseline=True)
        ctx_a = SimpleNamespace(db=self.db, run_id="RUN-A", policy=self.policy)
        signals, meta = _prepare_javascript_derived_differentials(
            ctx_a,
            [source_v1],
            [chunk_v1],
            source_maps_complete=True,
            chunks_complete=True,
        )
        self.assertEqual(signals, [])
        self.assertEqual(meta["initialized_sets"], 2)
        self.db.finish_run_target("RUN-A", self.TARGET, "success")

        source_v2 = {**source_v1, "content_hash": "h2", "semantic_hash": "s2"}
        chunk_v2 = {
            "js_url": "https://example.test/app.js",
            "chunk_url": "https://example.test/chunk-b.js",
        }
        self._start("RUN-B")
        ctx_b = SimpleNamespace(db=self.db, run_id="RUN-B", policy=self.policy)
        signals, meta = _prepare_javascript_derived_differentials(
            ctx_b,
            [source_v2],
            [chunk_v2],
            source_maps_complete=False,
            chunks_complete=True,
        )
        self.assertEqual(meta["prepared_sets"], 1)
        self.assertEqual(
            sorted(signal["signal_type"] for signal in signals),
            ["javascript_chunk_added", "javascript_chunk_removed"],
        )
        self.db.finish_run_target("RUN-B", self.TARGET, "success")

        self._start("RUN-C")
        ctx_c = SimpleNamespace(db=self.db, run_id="RUN-C", policy=self.policy)
        signals, _meta = _prepare_javascript_derived_differentials(
            ctx_c,
            [source_v2],
            [chunk_v2],
            source_maps_complete=True,
            chunks_complete=True,
        )
        source_changes = [
            signal for signal in signals
            if signal["state_type"] == "source_map_source"
        ]
        self.assertEqual(len(source_changes), 1)
        self.assertEqual(source_changes[0]["signal_type"], "source_map_source_changed")
        self.assertEqual(source_changes[0]["baseline_run_id"], "RUN-A")

    def test_run_snapshot_includes_source_map_and_chunk_state(self) -> None:
        run_dir = Path(self.temp.name) / "run"
        current = run_dir / "current"
        current.mkdir(parents=True)
        write_jsonl(
            current / "source-map-sources.jsonl",
            [
                {
                    "source_identity": "https://example.test/app.js.map#0:src/a.ts",
                    "js_url": "https://example.test/app.js",
                    "source_map_url": "https://example.test/app.js.map",
                    "source_name": "src/a.ts",
                    "embedded": True,
                    "content_hash": "h1",
                    "semantic_hash": "s1",
                    "source_map_hash": "m1",
                }
            ],
        )
        write_jsonl(
            current / "javascript-chunk-edges.jsonl",
            [
                {
                    "js_url": "https://example.test/app.js",
                    "chunk_url": "https://example.test/chunk.js",
                }
            ],
        )

        snapshot = _snapshot(run_dir)
        self.assertEqual(len(snapshot["source_map_sources"]), 1)
        self.assertEqual(len(snapshot["javascript_chunks"]), 1)
        source_payload = json.loads(next(iter(snapshot["source_map_sources"])))
        chunk_payload = json.loads(next(iter(snapshot["javascript_chunks"])))
        self.assertEqual(source_payload["content_hash"], "h1")
        self.assertEqual(chunk_payload["chunk_url"], "https://example.test/chunk.js")


if __name__ == "__main__":
    unittest.main()
