from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import test_baseline_raw_analysis_v960 as baseline_fixture
from analysis_engine import replay_analysis, run_analysis
from analysis_input_snapshot import CAS_MARKER_PREFIX, analysis_inputs
from core import ReconError, sha256_bytes, utc_now


class AnalysisInputSnapshotTests(unittest.TestCase):
    def project(self):
        return baseline_fixture.BaselineRawAnalysisV960Tests().project()

    def test_replay_uses_first_analysis_inventory_after_live_rows_change(self):
        temp, paths, db, _ctx = self.project()
        try:
            now = utc_now()
            original = "https://example.test/login"
            db.execute(
                """INSERT INTO endpoint_intelligence(
                    target,endpoint,kind,primary_category,confidence,
                    categories_json,reasons_json,sources_json,
                    first_seen,last_seen,last_run_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "example.test", original, "endpoint", "authentication",
                    80, "[]", "[]", "[]", now, now, "RUN-BASELINE",
                ),
            )
            first = run_analysis(
                paths, db, "RUN-BASELINE", "example.test"
            )
            db.execute(
                "UPDATE endpoint_intelligence "
                "SET endpoint=?,last_run_id=? "
                "WHERE target=? AND endpoint=?",
                (
                    "https://example.test/newer-only",
                    "RUN-NEXT",
                    "example.test",
                    original,
                ),
            )
            second = replay_analysis(
                paths, db, "RUN-BASELINE", "example.test"
            )
            self.assertEqual(
                first["input_snapshot"],
                second["input_snapshot"],
            )
            self.assertEqual(
                first["bug_candidates"]["raw_surface_routing"]["hypotheses"],
                second["bug_candidates"]["raw_surface_routing"]["hypotheses"],
            )
            live = db.one(
                "SELECT endpoint,last_run_id "
                "FROM main.endpoint_intelligence WHERE target=?",
                ("example.test",),
            )
            self.assertEqual(
                (str(live["endpoint"]), str(live["last_run_id"])),
                ("https://example.test/newer-only", "RUN-NEXT"),
            )
        finally:
            db.close()
            temp.cleanup()

    def test_replay_without_snapshot_fails_closed(self):
        temp, paths, db, _ctx = self.project()
        try:
            with self.assertRaisesRegex(ReconError, "no immutable"):
                replay_analysis(
                    paths, db, "RUN-BASELINE", "example.test"
                )
        finally:
            db.close()
            temp.cleanup()

    def test_javascript_snapshot_uses_portable_cas_identity(self):
        temp, paths, db, _ctx = self.project()
        try:
            now = utc_now()
            source = paths.state / "mutable-app.js"
            body = b"const historicalValue = 1;"
            source.write_bytes(body)
            digest = sha256_bytes(body)
            db.execute(
                """INSERT INTO js_files(
                    target,url,raw_hash,semantic_hash,blob_path,content_length,
                    first_seen,last_seen,last_run_id
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    "example.test",
                    "https://example.test/app.js",
                    digest,
                    digest,
                    str(source),
                    len(body),
                    now,
                    now,
                    "RUN-BASELINE",
                ),
            )
            with analysis_inputs(
                paths, db, "RUN-BASELINE", "example.test"
            ) as captured:
                frozen = db.one(
                    "SELECT blob_path FROM js_files "
                    "WHERE target='example.test'"
                )
                frozen_path = Path(str(frozen["blob_path"]))
                self.assertTrue(frozen_path.is_file())
                self.assertTrue(
                    frozen_path.resolve().is_relative_to(
                        paths.objects.resolve()
                    )
                )
                self.assertEqual(frozen_path.read_bytes(), body)
                self.assertEqual(captured["artifacts"], 1)

            stored = db.one(
                "SELECT payload_json FROM analysis_input_snapshots "
                "WHERE run_id='RUN-BASELINE' AND scope='example.test'"
            )
            self.assertIn(
                CAS_MARKER_PREFIX + digest,
                str(stored["payload_json"]),
            )
            reference = db.one(
                "SELECT reference_count FROM object_store WHERE sha256=?",
                (digest,),
            )
            self.assertGreaterEqual(
                int(reference["reference_count"]), 1
            )

            source.unlink()
            with analysis_inputs(
                paths,
                db,
                "RUN-BASELINE",
                "example.test",
                replay=True,
            ):
                replayed = db.one(
                    "SELECT blob_path FROM js_files "
                    "WHERE target='example.test'"
                )
                replayed_path = Path(str(replayed["blob_path"]))
                self.assertTrue(replayed_path.is_file())
                self.assertEqual(replayed_path.read_bytes(), body)

            live = db.one(
                "SELECT blob_path FROM main.js_files "
                "WHERE target='example.test'"
            )
            self.assertEqual(str(live["blob_path"]), str(source))
        finally:
            db.close()
            temp.cleanup()

    def test_temp_shadow_tables_are_removed_after_failure(self):
        temp, paths, db, _ctx = self.project()
        try:
            with self.assertRaisesRegex(
                RuntimeError, "fixture interruption"
            ):
                with analysis_inputs(
                    paths, db, "RUN-BASELINE", "example.test"
                ):
                    raise RuntimeError("fixture interruption")
            self.assertEqual(
                db.all(
                    "SELECT name FROM sqlite_temp_master "
                    "WHERE type='table'"
                ),
                [],
            )
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
