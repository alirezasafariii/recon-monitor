from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import test_baseline_raw_analysis_v960 as baseline_fixture
from analysis_engine import replay_analysis, run_analysis
from analysis_input_snapshot import analysis_inputs
from core import APP_VERSION, ReconError, utc_now


class AnalysisInputSnapshotTests(unittest.TestCase):
    def project(self):
        return baseline_fixture.BaselineRawAnalysisV960Tests().project()

    def test_replay_preserves_raw_inputs_after_new_scan(self):
        temp, paths, db, _ctx = self.project()
        try:
            now = utc_now()
            db.execute(
                """INSERT INTO endpoint_intelligence(
                    target,endpoint,kind,primary_category,confidence,
                    categories_json,reasons_json,sources_json,
                    first_seen,last_seen,last_run_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "example.test",
                    "https://example.test/login",
                    "endpoint",
                    "authentication",
                    80,
                    "[]",
                    "[]",
                    "[]",
                    now,
                    now,
                    "RUN-BASELINE",
                ),
            )

            first = run_analysis(
                paths,
                db,
                "RUN-BASELINE",
                "example.test",
            )
            db.execute(
                "UPDATE endpoint_intelligence "
                "SET last_run_id='RUN-NEXT',"
                "endpoint='https://example.test/other'"
            )
            second = replay_analysis(
                paths,
                db,
                "RUN-BASELINE",
                "example.test",
            )

            first_raw = first["bug_candidates"]["raw_surface_routing"]
            second_raw = second["bug_candidates"]["raw_surface_routing"]
            self.assertGreater(first_raw["hypotheses"], 0)
            self.assertEqual(
                first_raw["hypotheses"],
                second_raw["hypotheses"],
            )
            self.assertEqual(
                first["input_snapshot"]["integrity_hash"],
                second["input_snapshot"]["integrity_hash"],
            )
            self.assertEqual(
                db.one(
                    "SELECT endpoint FROM main.endpoint_intelligence"
                )[0],
                "https://example.test/other",
            )
            self.assertFalse(
                db.all(
                    "SELECT name FROM sqlite_temp_master "
                    "WHERE type='table'"
                )
            )
        finally:
            db.close()
            temp.cleanup()

    def test_missing_or_corrupted_snapshot_fails_closed(self):
        temp, paths, db, _ctx = self.project()
        try:
            with self.assertRaisesRegex(ReconError, "no immutable"):
                replay_analysis(
                    paths,
                    db,
                    "RUN-BASELINE",
                    "example.test",
                )

            run_analysis(
                paths,
                db,
                "RUN-BASELINE",
                "example.test",
            )
            db.execute(
                "UPDATE analysis_input_snapshots SET payload_json='{}'"
            )
            with self.assertRaisesRegex(ReconError, "integrity"):
                replay_analysis(
                    paths,
                    db,
                    "RUN-BASELINE",
                    "example.test",
                )
            self.assertFalse(
                db.all(
                    "SELECT name FROM sqlite_temp_master "
                    "WHERE type='table'"
                )
            )
        finally:
            db.close()
            temp.cleanup()

    def test_javascript_artifact_is_frozen_in_cas(self):
        temp, paths, db, _ctx = self.project()
        try:
            now = utc_now()
            source = paths.state / "mutable-analysis-input.js"
            source.write_text(
                "window.replayValue = 'old';",
                encoding="utf-8",
            )
            db.execute(
                "INSERT INTO js_files("
                "target,url,raw_hash,semantic_hash,blob_path,"
                "content_length,first_seen,last_seen,last_changed,last_run_id"
                ") VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    "example.test",
                    "https://example.test/app.js",
                    "legacy-raw-hash",
                    "semantic",
                    str(source),
                    source.stat().st_size,
                    now,
                    now,
                    now,
                    "RUN-BASELINE",
                ),
            )

            with analysis_inputs(
                paths,
                db,
                "RUN-BASELINE",
                "example.test",
            ) as first:
                frozen_path = Path(
                    db.one(
                        "SELECT blob_path FROM js_files "
                        "WHERE url='https://example.test/app.js'"
                    )["blob_path"]
                )
                self.assertTrue(frozen_path.is_file())
                self.assertEqual(
                    frozen_path.read_text(encoding="utf-8"),
                    "window.replayValue = 'old';",
                )

            stored = db.one(
                "SELECT payload_json FROM analysis_input_snapshots "
                "WHERE run_id='RUN-BASELINE' AND scope='example.test'"
            )
            payload = json.loads(stored["payload_json"])
            marker = payload["js_files"][0]["blob_path"]
            self.assertTrue(marker.startswith("cas:"))
            digest = marker[4:]
            self.assertEqual(
                db.one(
                    "SELECT COUNT(*) count FROM cas_references "
                    "WHERE owner_kind='analysis_input_snapshot' "
                    "AND sha256=?",
                    (digest,),
                )["count"],
                1,
            )

            source.write_text(
                "window.replayValue = 'new';",
                encoding="utf-8",
            )
            with analysis_inputs(
                paths,
                db,
                "RUN-BASELINE",
                "example.test",
                replay=True,
            ) as second:
                replay_path = Path(
                    db.one(
                        "SELECT blob_path FROM js_files "
                        "WHERE url='https://example.test/app.js'"
                    )["blob_path"]
                )
                self.assertEqual(
                    replay_path.read_text(encoding="utf-8"),
                    "window.replayValue = 'old';",
                )
                self.assertEqual(
                    first["integrity_hash"],
                    second["integrity_hash"],
                )
        finally:
            db.close()
            temp.cleanup()

    def test_first_analysis_of_superseded_run_fails_closed(self):
        temp, paths, db, _ctx = self.project()
        try:
            now = utc_now()
            db.execute(
                "INSERT INTO runs("
                "id,version,status,started_at,finished_at,"
                "target_selector,target_count"
                ") VALUES('RUN-NEXT',?,'success',?,?,?,1)",
                (APP_VERSION, now, now, "example.test"),
            )
            db.execute(
                "INSERT INTO run_targets("
                "run_id,target,policy_hash,status,current_stage,"
                "started_at,finished_at,run_dir,baseline"
                ") VALUES("
                "'RUN-NEXT','example.test','policy','success',"
                "'report',?,?,?,0)",
                (
                    now,
                    now,
                    str(paths.output / "RUN-NEXT"),
                ),
            )

            with self.assertRaisesRegex(
                ReconError,
                "Historical analysis inputs were not preserved",
            ):
                with analysis_inputs(
                    paths,
                    db,
                    "RUN-BASELINE",
                    "example.test",
                ):
                    pass
            self.assertIsNone(
                db.one(
                    "SELECT 1 FROM analysis_input_snapshots "
                    "WHERE run_id='RUN-BASELINE'"
                )
            )
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
