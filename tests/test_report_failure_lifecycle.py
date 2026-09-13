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

    def __init__(
        self,
        *args,
        fail_stage: str = "",
        analysis_failed: bool = False,
        notification_failed: bool = False,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.fail_stage = fail_stage
        self.analysis_failed = analysis_failed
        self.notification_failed = notification_failed
        self.stage_calls: list[str] = []

    def _record_versions(self, run_id: str) -> None:
        return None

    def install_signal_handlers(self) -> None:
        return None

    def _update_latest_pointers(self, target_name: str, run_dir: Path) -> None:
        return None

    def _report_metrics(self) -> dict:
        if self.analysis_failed:
            return {
                "analysis": {"status": "failed", "error": "controlled analysis failure"},
                "finding_notifications": {
                    "status": "no_analysis",
                    "queued": 0,
                    "delivery": {"queued": 0, "delivered": 0, "error": ""},
                },
            }
        finding = {
            "status": "failed" if self.notification_failed else "success",
            "queued": 1 if self.notification_failed else 0,
            "delivery": {
                "queued": 1 if self.notification_failed else 0,
                "delivered": 0,
                "error": "controlled notification failure" if self.notification_failed else "",
            },
        }
        return {
            "analysis": {"analysis_id": "AN-CONTROLLED"},
            "finding_notifications": finding,
        }

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
        metrics = self._report_metrics() if stage_name == "report" and status == "success" else {"controlled": True}
        self.db.stage_begin(ctx.run_id, ctx.policy.name, stage_name, 1)
        self.db.stage_finish(
            ctx.run_id,
            ctx.policy.name,
            stage_name,
            status,
            exit_code=1 if status == "failed" else 0,
            error="controlled failure" if status == "failed" else None,
            metrics=metrics,
        )
        return status, metrics


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

    def _run(
        self,
        fail_stage: str = "",
        *,
        analysis_failed: bool = False,
        notification_failed: bool = False,
    ) -> tuple[int, ControlledOrchestrator]:
        orchestrator = ControlledOrchestrator(
            self.paths,
            self.config,
            self.logger,
            self.db,
            progress=False,
            allow_active=False,
            fail_stage=fail_stage,
            analysis_failed=analysis_failed,
            notification_failed=notification_failed,
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
        lifecycle = self.db.one(
            "SELECT * FROM target_run_lifecycle WHERE run_id=? AND target=?",
            (str(run["id"]), self.TARGET),
        )
        self.assertIsNotNone(lifecycle)
        return run, target, lifecycle

    def test_runtime_guard_is_installed(self) -> None:
        self.assertTrue(
            getattr(
                recon_monitor_core.Orchestrator.run,
                "_strict_lifecycle_status",
                False,
            )
        )
        self.assertEqual(
            getattr(recon_monitor_core.Orchestrator.run, "_lifecycle_status_version", ""),
            "2.0.0",
        )

    def test_report_failure_is_partial_but_complete_recon_establishes_baseline(self) -> None:
        code, orchestrator = self._run("report")
        run, target, lifecycle = self._latest_rows()

        self.assertEqual(code, 2)
        self.assertEqual(str(target["status"]), "partial")
        self.assertEqual(str(run["status"]), "partial")
        self.assertEqual(orchestrator.stage_calls[-1], "report")
        self.assertEqual(str(lifecycle["collection_status"]), "success")
        self.assertEqual(str(lifecycle["report_status"]), "failed")
        self.assertEqual(str(lifecycle["overall_status"]), "partial")
        self.assertEqual(str(lifecycle["baseline_state"]), "established")
        self.assertTrue(bool(lifecycle["baseline_eligible"]))
        self.assertTrue(self.db.target_has_history(self.TARGET))
        snapshot = self.db.successful_snapshot_status(self.TARGET)
        self.assertTrue(snapshot["exists"])
        self.assertEqual(snapshot["run_id"], str(run["id"]))

    def test_successful_pipeline_records_all_component_states_and_baseline(self) -> None:
        code, orchestrator = self._run()
        run, target, lifecycle = self._latest_rows()

        self.assertEqual(code, 0)
        self.assertEqual(str(target["status"]), "success")
        self.assertEqual(str(run["status"]), "success")
        self.assertEqual(orchestrator.stage_calls[-1], "report")
        self.assertEqual(str(lifecycle["collection_status"]), "success")
        self.assertEqual(str(lifecycle["analysis_status"]), "success")
        self.assertEqual(str(lifecycle["report_status"]), "success")
        self.assertEqual(str(lifecycle["notification_status"]), "success")
        self.assertEqual(str(lifecycle["overall_status"]), "success")
        self.assertEqual(str(lifecycle["baseline_state"]), "established")
        snapshot = self.db.successful_snapshot_status(self.TARGET)
        self.assertTrue(snapshot["exists"])
        self.assertEqual(snapshot["run_id"], str(run["id"]))

    def test_analysis_failure_is_partial_without_invalidating_complete_recon(self) -> None:
        code, _ = self._run(analysis_failed=True)
        run, target, lifecycle = self._latest_rows()

        self.assertEqual(code, 2)
        self.assertEqual(str(target["status"]), "partial")
        self.assertEqual(str(lifecycle["collection_status"]), "success")
        self.assertEqual(str(lifecycle["analysis_status"]), "failed")
        self.assertEqual(str(lifecycle["report_status"]), "success")
        self.assertEqual(str(lifecycle["notification_status"]), "not_run")
        self.assertEqual(str(lifecycle["overall_status"]), "partial")
        self.assertEqual(str(lifecycle["baseline_state"]), "established")
        self.assertTrue(self.db.target_has_history(self.TARGET))
        self.assertEqual(
            self.db.successful_snapshot_status(self.TARGET)["run_id"],
            str(run["id"]),
        )

    def test_notification_failure_is_partial_without_invalidating_complete_recon(self) -> None:
        code, _ = self._run(notification_failed=True)
        _run, target, lifecycle = self._latest_rows()

        self.assertEqual(code, 2)
        self.assertEqual(str(target["status"]), "partial")
        self.assertEqual(str(lifecycle["collection_status"]), "success")
        self.assertEqual(str(lifecycle["analysis_status"]), "success")
        self.assertEqual(str(lifecycle["notification_status"]), "failed")
        self.assertEqual(str(lifecycle["overall_status"]), "partial")
        self.assertEqual(str(lifecycle["baseline_state"]), "established")
        self.assertTrue(self.db.target_has_history(self.TARGET))

    def test_collection_failure_blocks_baseline_even_when_report_succeeds(self) -> None:
        code, orchestrator = self._run("dns")
        run, target, lifecycle = self._latest_rows()

        self.assertEqual(code, 2)
        self.assertEqual(str(target["status"]), "failed")
        self.assertEqual(str(run["status"]), "partial")
        self.assertIn("report", orchestrator.stage_calls)
        self.assertEqual(str(lifecycle["collection_status"]), "failed")
        self.assertEqual(str(lifecycle["report_status"]), "success")
        self.assertEqual(str(lifecycle["overall_status"]), "failed")
        self.assertFalse(bool(lifecycle["baseline_eligible"]))
        self.assertEqual(str(lifecycle["baseline_state"]), "blocked")
        self.assertFalse(self.db.target_has_history(self.TARGET))
        self.assertFalse(self.db.successful_snapshot_status(self.TARGET)["exists"])


if __name__ == "__main__":
    unittest.main()
