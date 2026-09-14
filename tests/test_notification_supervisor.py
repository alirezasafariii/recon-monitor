from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Config, Database, Logger
from finding_notification_operations import configure_finding_notification_worker
from notification_supervisor import (
    acquire_notification_supervisor_lease,
    configure_notification_supervisor,
    notification_supervisor_status,
    release_notification_supervisor_lease,
    run_notification_supervisor_cycle,
    watch_notification_supervisor,
)


class NotificationSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nTELEGRAM_ENABLED="no"\n', encoding="utf-8")
        self.config = Config(self.paths)
        self.logger = Logger(self.paths, verbose=False)
        self.db = Database(self.paths.db)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def test_single_instance_lease_and_restart_recovery(self) -> None:
        first = "2099-01-01T00:00:00Z"
        self.assertTrue(acquire_notification_supervisor_lease(self.db, owner_id="one", now=first, lease_seconds=60))
        self.assertFalse(acquire_notification_supervisor_lease(self.db, owner_id="two", now="2099-01-01T00:00:30Z", lease_seconds=60))
        self.assertTrue(acquire_notification_supervisor_lease(self.db, owner_id="two", now="2099-01-01T00:01:01Z", lease_seconds=60))
        status = notification_supervisor_status(self.db, now="2099-01-01T00:01:02Z")
        self.assertTrue(status["lease_active"])
        self.assertEqual(status["lease_owner"], "two")
        self.assertTrue(release_notification_supervisor_lease(self.db, owner_id="two", now="2099-01-01T00:01:03Z"))

    def test_failure_isolation_runs_second_worker(self) -> None:
        calls: list[str] = []

        def fail_finding(**kwargs):
            calls.append("finding")
            raise RuntimeError("finding transport exploded")

        def ok_recon(**kwargs):
            calls.append("recon_alert")
            return {"status": "success", "delivery": {"attempted": 0, "delivered": 0}}

        with patch("notification_supervisor.run_finding_notification_worker", side_effect=fail_finding), patch(
            "notification_supervisor.run_recon_alert_worker", side_effect=ok_recon
        ):
            result = run_notification_supervisor_cycle(
                config=self.config,
                logger=self.logger,
                db=self.db,
                owner_id="isolated",
                now="2099-02-01T00:00:00Z",
            )
        self.assertEqual(result["status"], "partial_failure")
        self.assertEqual(calls, ["finding", "recon_alert"])
        self.assertEqual(result["workers"]["finding"]["status"], "failed")
        self.assertEqual(result["workers"]["recon_alert"]["status"], "success")
        self.assertIn("slo", result)
        status = notification_supervisor_status(self.db, now="2099-02-01T00:00:01Z")
        self.assertEqual(status["last_status"], "partial_failure")
        self.assertEqual(status["worker_failure_count"], 1)
        self.assertIn("finding", status["last_error"])

    def test_disabled_worker_is_skipped_without_disabling_other_worker(self) -> None:
        configure_finding_notification_worker(self.db, enabled=False)
        result = run_notification_supervisor_cycle(
            config=self.config,
            logger=self.logger,
            db=self.db,
            owner_id="disabled-check",
            now="2099-03-01T00:00:00Z",
        )
        finding = result["workers"]["finding"]
        recon = result["workers"]["recon_alert"]
        self.assertEqual(finding["status"], "skipped")
        self.assertEqual(finding["reason"], "disabled")
        self.assertEqual(recon["status"], "success")
        status = notification_supervisor_status(self.db, now="2099-03-01T00:00:01Z")
        self.assertFalse(status["workers_due"]["finding"]["policy"]["enabled"])
        self.assertTrue(status["workers_due"]["recon_alert"]["policy"]["enabled"])

    def test_existing_lease_causes_safe_skip(self) -> None:
        self.assertTrue(
            acquire_notification_supervisor_lease(
                self.db,
                owner_id="primary",
                now="2099-04-01T00:00:00Z",
                lease_seconds=300,
            )
        )
        result = run_notification_supervisor_cycle(
            config=self.config,
            logger=self.logger,
            db=self.db,
            owner_id="secondary",
            now="2099-04-01T00:00:10Z",
        )
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "lease_held")

    def test_watch_holds_one_owner_and_stops_deterministically(self) -> None:
        sleeps: list[float] = []
        configure_notification_supervisor(self.db, poll_seconds=5, lease_seconds=60)
        with patch("notification_supervisor.run_finding_notification_worker", return_value={"status": "skipped", "reason": "interval_pending"}), patch(
            "notification_supervisor.run_recon_alert_worker", return_value={"status": "skipped", "reason": "interval_pending"}
        ):
            result = watch_notification_supervisor(
                config=self.config,
                logger=self.logger,
                db=self.db,
                owner_id="watcher",
                sleep=lambda seconds: sleeps.append(seconds),
                max_cycles=2,
            )
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(result["cycles"], 2)
        self.assertEqual(sleeps, [5])
        self.assertFalse(notification_supervisor_status(self.db)["lease_active"])


if __name__ == "__main__":
    unittest.main()
