from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import recon_monitor_core
from core import AppPaths, Config, Logger, PolicySet, TargetPolicy


class ControlledOrchestrator(recon_monitor_core.Orchestrator):
    """Run the real lifecycle while replacing external stage work with statuses."""

    def __init__(self, *args, fail_stage: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self.fail_stage = fail_stage
        self.stage_calls: list[str] = []

    def _record_versions(self, run_id: str) -> None:
        return None

    def install_signal_handlers(self) -> None:
        return None

    def _update_latest_pointers(self, target_name: str, run_dir: Path) -> None:
        return None

    def _run_stage(
        self,
        ctx,
        stage_name: str,
        label: str,
        stage_index: int,
        stage_total: int,
        target_index: int,
        target_total: int,
        baseline: bool,
        resume: bool,
    ):
        del label, stage_index, stage_total, target_index, target_total, baseline, resume
        self.stage_calls.append(stage_name)
        status = "failed" if stage_name == self.fail_stage else "success"
        self.db.stage_begin(ctx.run_id, ctx.policy.name, stage_name, 1)
        self.db.stage_finish(
            ctx.run_id,
            ctx.policy.name,
            stage_name,
            status,
            exit_code=1 if status == "failed" else 0,
            error="controlled failure" if status == "failed" else None,
            metrics={"controlled": True},
        )
        return status, {"controlled": True}


class ReportFailureLifecycleTests(unittest.TestCase):
    TARGET = "example.test"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text(
            'I_HAVE_AUTHORIZATION="yes"\n'
            'AUTO_RETENTION="no"\n'
            'AUTO_DIGEST_HOURS="0"\n',
            encoding="utf-8",
        )
        self.config = Config(self.paths)
        self.logger = Logger(self.paths, verbose=False)
        self.db = recon_monitor_core.Database(self.paths.db)
        self.policy = TargetPolicy.from_dict(
            {"name": self.TARGET, "roots": [self.TARGET]}
        )
        self.policies = PolicySet({}, [self.policy], self.paths.policy)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _run(self, fail_stage: str = "") -> tuple[int, ControlledOrchestrator]:
        orchestrator = ControlledOrchestrator(
            self.paths,
            self.config,
            self.logger,
            self.db,
            progress=False,
            allow_active=False,
            fail_stage=fail_stage,
        )
        return orchestrator.run(self.policies), orchestrator

    def _latest_rows(self):
        run = self.db.one(
            "SELECT id,status FROM runs ORDER BY rowid DESC LIMIT 1"
        )
        self.assertIsNotNone(run)
        target = self.db.one(
            "SELECT status FROM run_targets WHERE run_id=? AND target=?",
            (str(run["id"]), self.TARGET),
        )
        self.assertIsNotNone(target)
        return run, target

    def test_runtime_guard_is_installed(self) -> None:
        self.assertTrue(
            getattr(
                recon_monitor_core.Orchestrator.run,
                "_strict_lifecycle_status",
                False,
            )
        )

    def test_report_failure_marks_target_and_run_unsuccessful(self) -> None:
        code, orchestrator = self._run("report")
        run, target = self._latest_rows()

        self.assertEqual(code, 2)
        self.assertEqual(str(target["status"]), "failed")
        self.assertEqual(str(run["status"]), "partial")
        self.assertEqual(orchestrator.stage_calls[-1], "report")
        self.assertEqual(
            self.db.stage_status(str(run["id"]), self.TARGET, "report"),
            "failed",
        )
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertFalse(
            self.db.successful_snapshot_status(self.TARGET)["exists"]
        )

    def test_successful_report_preserves_success_and_commits_snapshot(self) -> None:
        code, orchestrator = self._run()
        run, target = self._latest_rows()

        self.assertEqual(code, 0)
        self.assertEqual(str(target["status"]), "success")
        self.assertEqual(str(run["status"]), "success")
        self.assertEqual(orchestrator.stage_calls[-1], "report")
        snapshot = self.db.successful_snapshot_status(self.TARGET)
        self.assertTrue(snapshot["exists"])
        self.assertEqual(snapshot["run_id"], str(run["id"]))

    def test_collection_failure_still_attempts_report_but_remains_failed(self) -> None:
        code, orchestrator = self._run("dns")
        run, target = self._latest_rows()

        self.assertEqual(code, 2)
        self.assertEqual(str(target["status"]), "failed")
        self.assertEqual(str(run["status"]), "partial")
        self.assertIn("report", orchestrator.stage_calls)
        self.assertEqual(
            self.db.stage_status(str(run["id"]), self.TARGET, "report"),
            "success",
        )
        self.assertFalse(self.db.target_has_history(self.TARGET))


if __name__ == "__main__":
    unittest.main()
