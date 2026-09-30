from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import recon_monitor_core as runtime
import test_baseline_raw_analysis_v960 as baseline_fixture
from analysis_engine import ENGINE_VERSION, replay_analysis, run_analysis
from analysis_input_snapshot import analysis_inputs
from core import APP_VERSION, AppPaths, Config, Logger, PolicySet, ReconError, TargetPolicy, utc_now
from storage import ContentAddressedStore


class AnalysisResumeSnapshotTests(unittest.TestCase):
    TARGET = "example.test"
    RUN = "RUN-BASELINE"

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.temp, self.paths, self.db, _ctx = baseline_fixture.BaselineRawAnalysisV960Tests().project()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.db.close)
        self._asset("first.example.test")

    def _asset(self, host, target=None):
        self.db.upsert_asset(target or self.TARGET, host, ["offline-fixture"], self.RUN)

    def _hosts(self, db=None):
        return {str(row[0]) for row in (db or self.db).all("SELECT host FROM assets ORDER BY host")}

    def _later_run(self):
        now = utc_now()
        self.db.execute("INSERT INTO runs(id,version,status,started_at,target_count) VALUES('RUN-NEXT',?,'success',?,1)", (APP_VERSION, now))
        self.db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,started_at,run_dir,baseline) VALUES('RUN-NEXT',?,'policy','success',?,?,0)",
            (self.TARGET, now, str(self.paths.output / "next")),
        )

    def _observe_analysis(self, paths, db, run_id, target=None, **kwargs):
        analysis_id = "offline-analysis-" + uuid.uuid4().hex
        summary = {"observed_hosts": sorted(self._hosts(db))}
        summary["input_snapshot"] = dict(kwargs.get("input_snapshot") or {})
        db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,summary_json) VALUES(?,?,?,?,?,?,'success',?,?)",
            (analysis_id, run_id, target or "*", ENGINE_VERSION, "offline", kwargs.get("mode", "analysis"), utc_now(), json.dumps(summary)),
        )
        return {"analysis_id": analysis_id, **summary}

    def _versions(self, scope=None):
        return self.db.all(
            "SELECT * FROM analysis_input_snapshot_versions WHERE run_id=? AND scope=? ORDER BY revision",
            (self.RUN, scope or self.TARGET),
        )

    def test_automatic_analysis_after_resume_reads_new_inputs(self):
        with patch("analysis_engine._run_analysis_impl", side_effect=self._observe_analysis):
            first = run_analysis(self.paths, self.db, self.RUN, self.TARGET, mode="automatic")
            self._asset("resumed.example.test")
            second = run_analysis(self.paths, self.db, self.RUN, self.TARGET, mode="automatic")
        self.assertEqual(first["observed_hosts"], ["first.example.test"])
        self.assertEqual(second["observed_hosts"], ["first.example.test", "resumed.example.test"])
        self.assertEqual(first["input_snapshot"]["revision"], 1)
        self.assertEqual(second["input_snapshot"]["revision"], 2)
        self.assertNotEqual(first["input_snapshot"]["integrity_hash"], second["input_snapshot"]["integrity_hash"])
        versions = self._versions()
        self.assertEqual(len(versions), 2)
        self.assertEqual({row["host"] for row in json.loads(versions[0]["payload_json"])["assets"]}, {"first.example.test"})
        self.assertEqual(self._hosts(), {"first.example.test", "resumed.example.test"})

    def test_unchanged_inputs_reuse_the_revision(self):
        with patch("analysis_engine._run_analysis_impl", side_effect=self._observe_analysis):
            first = run_analysis(self.paths, self.db, self.RUN, self.TARGET)
            second = run_analysis(self.paths, self.db, self.RUN, self.TARGET)
        self.assertEqual(first["input_snapshot"], second["input_snapshot"])
        self.assertEqual(len(self._versions()), 1)

    def test_old_and_latest_replay_remain_independent_after_resume(self):
        with patch("analysis_engine._run_analysis_impl", side_effect=self._observe_analysis):
            first = run_analysis(self.paths, self.db, self.RUN, self.TARGET)
            self._asset("resumed.example.test")
            second = run_analysis(self.paths, self.db, self.RUN, self.TARGET)
            self._later_run()
            self.db.execute("DELETE FROM assets")
            self._asset("newer.example.test")
            old = replay_analysis(self.paths, self.db, self.RUN, self.TARGET, revision=1)
            latest = replay_analysis(self.paths, self.db, self.RUN, self.TARGET)
        self.assertEqual(old["observed_hosts"], first["observed_hosts"])
        self.assertEqual(old["input_snapshot"], first["input_snapshot"])
        self.assertEqual(latest["observed_hosts"], second["observed_hosts"])
        self.assertEqual(latest["input_snapshot"], second["input_snapshot"])
        self.assertEqual(len(self._versions()), 2)
        self.assertEqual(self._hosts(), {"newer.example.test"})
        self.assertFalse(self.db.all("SELECT name FROM sqlite_temp_master WHERE type='table'"))

    def test_refresh_of_superseded_run_uses_frozen_inputs(self):
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET) as first:
            first_hosts = self._hosts()
        self._later_run()
        self.db.execute("DELETE FROM assets")
        self._asset("newer.example.test")
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True) as second:
            self.assertEqual(self._hosts(), first_hosts)
        self.assertEqual(first, second)
        self.assertEqual(len(self._versions()), 1)

    def test_combined_scope_refreshes_when_target_snapshot_changes(self):
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET):
            pass
        with analysis_inputs(self.paths, self.db, self.RUN, None, replay=True) as combined:
            self.assertEqual(self._hosts(), {"first.example.test"})
        self._asset("resumed.example.test")
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True):
            pass
        self._later_run()
        self.db.execute("DELETE FROM assets")
        self._asset("newer.example.test")
        with analysis_inputs(self.paths, self.db, self.RUN, None, refresh=True) as refreshed:
            self.assertEqual(self._hosts(), {"first.example.test", "resumed.example.test"})
        self.assertNotEqual(combined["integrity_hash"], refreshed["integrity_hash"])
        with analysis_inputs(self.paths, self.db, self.RUN, None, replay=True, revision=1):
            self.assertEqual(self._hosts(), {"first.example.test"})

    def test_revisions_are_isolated_by_target(self):
        self._asset("api.other.test", "other.test")
        with analysis_inputs(self.paths, self.db, self.RUN, "other.test") as other:
            self.assertEqual(self._hosts(), {"api.other.test"})
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET):
            pass
        self._asset("resumed.example.test")
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True) as refreshed:
            self.assertEqual(refreshed["revision"], 2)
        with analysis_inputs(self.paths, self.db, self.RUN, "other.test", refresh=True) as unchanged:
            self.assertEqual(unchanged, other)

    def test_missing_or_invalid_revision_fails_closed(self):
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET):
            pass
        for revision in (0, -1, 99):
            with self.subTest(revision=revision), self.assertRaises(ReconError):
                with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, replay=True, revision=revision):
                    self.fail("invalid revision was installed")
        with self.assertRaises(ReconError):
            with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, revision=1):
                self.fail("revision selection requires replay")
        self.assertEqual(len(self._versions()), 1)
        self.assertFalse(self.db.all("SELECT name FROM sqlite_temp_master WHERE type='table'"))

    def test_existing_v2_snapshot_is_migrated_without_changing_history(self):
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET) as first:
            pass
        old = dict(self.db.one("SELECT * FROM analysis_input_snapshots"))
        self.db.execute("DROP TABLE analysis_input_snapshot_versions")
        self.db.execute("DROP TABLE analysis_input_snapshots")
        self.db.execute("CREATE TABLE analysis_input_snapshots(run_id TEXT,scope TEXT,payload_json TEXT,integrity_hash TEXT,schema_version INTEGER,created_at TEXT,PRIMARY KEY(run_id,scope))")
        self.db.execute(
            "INSERT INTO analysis_input_snapshots VALUES(?,?,?,?,?,?)",
            tuple(old[key] for key in ("run_id", "scope", "payload_json", "integrity_hash", "schema_version", "created_at")),
        )
        self._asset("resumed.example.test")
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True) as second:
            self.assertEqual(second["revision"], 2)
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, replay=True, revision=1) as migrated:
            self.assertEqual(migrated["integrity_hash"], first["integrity_hash"])
            self.assertEqual(self._hosts(), {"first.example.test"})

    def test_js_artifacts_from_both_revisions_remain_pinned(self):
        source = self.paths.state / "mutable.js"
        source.write_text("window.version = 'first';")
        now = utc_now()
        self.db.execute(
            "INSERT INTO js_files(target,url,raw_hash,semantic_hash,blob_path,content_length,first_seen,last_seen,last_changed,last_run_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.TARGET, "https://example.test/app.js", "raw", "semantic", str(source), source.stat().st_size, now, now, now, self.RUN),
        )
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET) as first:
            first_blob = Path(self.db.one("SELECT blob_path FROM js_files")[0])
        source.write_text("window.version = 'resumed';")
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True) as second:
            second_blob = Path(self.db.one("SELECT blob_path FROM js_files")[0])
        self.assertNotEqual(first["integrity_hash"], second["integrity_hash"])
        store = ContentAddressedStore(self.paths, self.db)
        store.reconcile_reference_counts()
        for path in (first_blob, second_blob):
            self.assertGreater(self.db.one("SELECT reference_count FROM object_store WHERE sha256=?", (path.name,))[0], 0)
        source.unlink()
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, replay=True, revision=1):
            self.assertEqual(Path(self.db.one("SELECT blob_path FROM js_files")[0]).read_text(), "window.version = 'first';")
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, replay=True):
            self.assertEqual(Path(self.db.one("SELECT blob_path FROM js_files")[0]).read_text(), "window.version = 'resumed';")

    def test_failed_refresh_leaves_previous_revision_usable(self):
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET) as first:
            pass
        with patch("analysis_input_snapshot._freeze_js_artifacts", side_effect=ReconError("artifact missing")):
            with self.assertRaisesRegex(ReconError, "artifact missing"):
                with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True):
                    pass
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, replay=True) as replayed:
            self.assertEqual(first, replayed)
        self.assertEqual(len(self._versions()), 1)

    def test_real_analysis_summary_persists_the_selected_revision(self):
        first = run_analysis(self.paths, self.db, self.RUN, self.TARGET, mode="automatic")
        self._asset("resumed.example.test")
        second = run_analysis(self.paths, self.db, self.RUN, self.TARGET, mode="automatic")
        for result in (first, second):
            summary = json.loads(self.db.one("SELECT summary_json FROM analysis_runs WHERE id=?", (result["analysis_id"],))[0])
            self.assertEqual(summary["input_snapshot"], result["input_snapshot"])
        self.assertEqual(second["input_snapshot"]["revision"], 2)

    def test_archived_replay_is_independent_of_a_corrupted_latest_pointer(self):
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET):
            pass
        self._asset("resumed.example.test")
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True):
            pass
        self.db.execute("UPDATE analysis_input_snapshots SET payload_json='{}'")
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, replay=True, revision=1):
            self.assertEqual(self._hosts(), {"first.example.test"})
        with self.assertRaisesRegex(ReconError, "integrity"):
            with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, replay=True):
                pass

    def test_head_and_revision_are_committed_atomically(self):
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET) as first:
            pass
        self._asset("resumed.example.test")
        execute = self.db.execute

        def fail_head_update(sql, params=()):
            if sql.startswith("INSERT INTO analysis_input_snapshots "):
                raise ReconError("head update failed")
            return execute(sql, params)

        with patch.object(self.db, "execute", side_effect=fail_head_update), self.assertRaisesRegex(ReconError, "head update failed"):
            with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True):
                pass
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, replay=True) as replayed:
            self.assertEqual(first, replayed)
        self.assertEqual(len(self._versions()), 1)

    def test_cli_replays_the_requested_historical_revision(self):
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n')
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET):
            pass
        self._asset("resumed.example.test")
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True):
            pass
        output = io.StringIO()
        with patch("recon_monitor_core.ROOT_DIR", self.paths.root), patch("analysis_engine._run_analysis_impl", side_effect=self._observe_analysis), contextlib.redirect_stdout(output):
            code = runtime.main(["analysis", "replay", "--run", self.RUN, "--target", self.TARGET, "--input-revision", "1"])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["observed_hosts"], ["first.example.test"])
        self.assertEqual(result["input_snapshot"]["revision"], 1)

    def test_failed_analysis_keeps_its_input_revision_in_the_summary(self):
        with patch("analysis_engine._analysis_targets", side_effect=ReconError("analysis failed")):
            with self.assertRaisesRegex(ReconError, "analysis failed"):
                run_analysis(self.paths, self.db, self.RUN, self.TARGET, mode="automatic")
        row = self.db.one("SELECT status,summary_json FROM analysis_runs ORDER BY rowid DESC LIMIT 1")
        self.assertEqual(row["status"], "failed")
        self.assertEqual(json.loads(row["summary_json"])["input_snapshot"]["revision"], 1)
        self.assertFalse(self.db.all("SELECT name FROM sqlite_temp_master WHERE type='table'"))

    def test_nested_context_cannot_advance_the_latest_revision(self):
        with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET):
            with self.assertRaisesRegex(ReconError, "Nested"):
                with analysis_inputs(self.paths, self.db, self.RUN, self.TARGET, refresh=True):
                    pass
            self.assertEqual(self._hosts(), {"first.example.test"})
        self.assertEqual(len(self._versions()), 1)

    def test_real_orchestrator_resume_creates_a_new_analysis_input_revision(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            paths = AppPaths.from_root(Path(tmp))
            paths.ensure()
            paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nAUTO_RETENTION="no"\nAUTO_DIGEST_HOURS="0"\n')
            db = runtime.Database(paths.db)
            stack.callback(db.close)
            policy = TargetPolicy.from_dict({"name": self.TARGET, "roots": [self.TARGET]})
            orchestrator = runtime.Orchestrator(paths, Config(paths), Logger(paths), db, progress=False, allow_active=False)
            stack.enter_context(patch.object(orchestrator, "_record_versions"))
            stack.enter_context(patch.object(orchestrator, "install_signal_handlers"))
            stack.enter_context(patch("analysis_engine._run_analysis_impl", side_effect=self._observe_analysis))
            phase = ["first"]
            captured = []

            def collect(ctx):
                ctx.db.upsert_asset(self.TARGET, phase[0] + ".example.test", ["offline"], ctx.run_id)
                return {"collection_status": "partial" if phase[0] == "first" else "completed"}

            def report(ctx, _baseline):
                result = run_analysis(ctx.paths, ctx.db, ctx.run_id, ctx.policy.name, mode="automatic")
                captured.append(result)
                return {"analysis": result, "finding_notifications": {"status": "success"}}

            stages = {name: lambda _ctx: {"collection_status": "completed"} for name in runtime.STAGE_FUNCTIONS}
            stages["subdomains"] = collect
            stack.enter_context(patch.dict(runtime.STAGE_FUNCTIONS, stages))
            stack.enter_context(patch("recon_monitor_core.stage_report", side_effect=report))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            policies = PolicySet({}, [policy], paths.policy)
            self.assertEqual(orchestrator.run(policies), 2)
            run_id = orchestrator.current_run_id
            phase[0] = "resumed"
            self.assertEqual(orchestrator.run(policies, resume_id=run_id), 0)
            self.assertEqual(captured[0]["observed_hosts"], ["first.example.test"])
            self.assertEqual(captured[1]["observed_hosts"], ["first.example.test", "resumed.example.test"])
            self.assertEqual(captured[1]["input_snapshot"]["revision"], 2)


if __name__ == "__main__":
    unittest.main()
