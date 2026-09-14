from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Config, Database, Logger, utc_now
from recon_alert_operations import (
    configure_recon_alert_worker,
    drain_recon_alert_outbox,
    list_recon_alert_dead_letters,
    recon_alert_diagnostics,
    recon_alert_worker_due,
    retry_recon_alert_dead_letters,
    run_recon_alert_worker,
    watch_recon_alert_worker,
)
from recon_alert_outbox import enqueue_recon_alert_event, ensure_recon_alert_outbox_schema


class ReconAlertOperationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.config = Config(self.paths)
        self.logger = Logger(self.paths, verbose=False)
        self.db = Database(self.paths.db)
        ensure_recon_alert_outbox_schema(self.db)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    @staticmethod
    def _success(config, logger, message: str):
        return {"delivered": True, "channel": "fixture", "channels": ["fixture"], "error": ""}

    @staticmethod
    def _failure(config, logger, message: str):
        return {"delivered": False, "channel": "fixture", "channels": [], "error": "offline"}

    def _event(
        self,
        key: str,
        *,
        target: str = "example.test",
        run_id: str = "RUN-1",
        created_at: str = "2026-09-14T00:00:00Z",
    ) -> tuple[int, str]:
        cursor = self.db.execute(
            "INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,"
            "first_seen,last_seen,last_run_id,occurrences,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                target,
                key,
                "new_url",
                "HIGH",
                90,
                "High-value URL changed",
                f"https://{target}/{key}",
                "{}",
                created_at,
                created_at,
                run_id,
                1,
                "open",
            ),
        )
        alert_id = int(cursor.lastrowid)
        queued = enqueue_recon_alert_event(
            self.db,
            alert_id=alert_id,
            target=target,
            run_id=run_id,
            payload={
                "category": "new_url",
                "severity": "HIGH",
                "risk_score": 90,
                "title": "High-value URL changed",
                "item": f"https://{target}/{key}",
                "change_class": "asset",
                "confirmation_state": "confirmed",
            },
        )
        event_id = str(queued["event_id"])
        self.db.execute(
            "UPDATE recon_alert_notification_outbox SET next_attempt_at=?,created_at=?,updated_at=? WHERE event_id=?",
            (created_at, created_at, created_at, event_id),
        )
        return alert_id, event_id

    def test_scheduler_interval_skips_until_due(self) -> None:
        self._event("schedule")
        configure_recon_alert_worker(self.db, interval_seconds=300, batch_limit=25)
        first = run_recon_alert_worker(
            config=self.config,
            logger=self.logger,
            db=self.db,
            now="2026-09-14T01:00:00Z",
            transport=self._success,
        )
        self.assertEqual(first["status"], "success")
        second = run_recon_alert_worker(
            config=self.config,
            logger=self.logger,
            db=self.db,
            now="2026-09-14T01:01:00Z",
            transport=self._success,
        )
        self.assertEqual(second["status"], "skipped")
        self.assertEqual(second["reason"], "interval_pending")
        self.assertTrue(recon_alert_worker_due(self.db, now="2026-09-14T01:05:00Z")["due"])

    def test_policy_clamps_values_and_disable_blocks_scheduler(self) -> None:
        policy = configure_recon_alert_worker(
            self.db,
            enabled=False,
            interval_seconds=1,
            batch_limit=9999,
        )
        self.assertFalse(policy["enabled"])
        self.assertEqual(policy["interval_seconds"], 60)
        self.assertEqual(policy["batch_limit"], 500)
        due = recon_alert_worker_due(self.db, now="2026-09-14T01:00:00Z")
        self.assertFalse(due["due"])
        self.assertEqual(due["reason"], "disabled")

    def test_diagnostics_report_backlog_target_filter_and_oldest_age(self) -> None:
        self._event("old", target="example.test", created_at="2026-09-14T00:00:00Z")
        self._event("new", target="example.test", created_at="2026-09-14T00:30:00Z")
        self._event("other", target="other.test", created_at="2026-09-14T00:45:00Z")
        status = recon_alert_diagnostics(
            self.db,
            target="example.test",
            now="2026-09-14T01:00:00Z",
        )
        self.assertEqual(status["queue_depth"], 2)
        self.assertEqual(status["due_now"], 2)
        self.assertEqual(status["oldest_pending_at"], "2026-09-14T00:00:00Z")
        self.assertEqual(status["oldest_pending_age_seconds"], 3600)
        self.assertEqual(status["dead_letter_open"], 0)

    def test_terminal_failure_becomes_dead_letter_and_retry_resolves_it(self) -> None:
        alert_id, event_id = self._event("dead")
        self.db.execute(
            "UPDATE recon_alert_notification_outbox SET max_attempts=1 WHERE event_id=?",
            (event_id,),
        )
        failed = run_recon_alert_worker(
            config=self.config,
            logger=self.logger,
            db=self.db,
            force=True,
            now="2026-09-14T01:00:00Z",
            transport=self._failure,
        )
        self.assertEqual(failed["delivery"]["failed"], 1)
        self.assertFalse(self.db.one("SELECT last_notified FROM alerts WHERE id=?", (alert_id,))["last_notified"])
        dead = list_recon_alert_dead_letters(self.db)
        self.assertEqual(len(dead), 1)
        self.assertEqual(dead[0]["event_id"], event_id)
        self.assertEqual(dead[0]["alert_id"], alert_id)
        self.assertEqual(dead[0]["run_id"], "RUN-1")
        self.assertEqual(dead[0]["last_error"], "offline")
        self.assertEqual(recon_alert_diagnostics(self.db)["dead_letter_open"], 1)

        self.assertEqual(retry_recon_alert_dead_letters(self.db, event_id=event_id), 1)
        self.assertEqual(list_recon_alert_dead_letters(self.db), [])
        delivered = run_recon_alert_worker(
            config=self.config,
            logger=self.logger,
            db=self.db,
            force=True,
            now="2099-01-01T00:00:00Z",
            transport=self._success,
        )
        self.assertEqual(delivered["delivery"]["delivered"], 1)
        self.assertTrue(self.db.one("SELECT last_notified FROM alerts WHERE id=?", (alert_id,))["last_notified"])
        resolved = self.db.one("SELECT resolved_at,resolution FROM recon_alert_dead_letters WHERE event_id=?", (event_id,))
        self.assertTrue(resolved["resolved_at"])
        self.assertEqual(resolved["resolution"], "operator_retry")

    def test_drain_processes_multiple_batches_with_bound(self) -> None:
        for index in range(5):
            self._event(f"drain-{index}")
        result = drain_recon_alert_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            batch_limit=2,
            max_batches=10,
            transport=self._success,
        )
        self.assertEqual(result["delivered"], 5)
        self.assertEqual(result["diagnostics"]["queue_depth"], 0)
        self.assertGreaterEqual(result["batches"], 3)

        for index in range(3):
            self._event(f"bounded-{index}", run_id="RUN-2")
        bounded = drain_recon_alert_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            batch_limit=1,
            max_batches=2,
            transport=self._success,
        )
        self.assertEqual(bounded["batches"], 2)
        self.assertEqual(bounded["delivered"], 2)
        self.assertEqual(bounded["diagnostics"]["queue_depth"], 1)

    def test_watch_scheduler_executes_then_obeys_interval(self) -> None:
        self._event("watch", created_at=utc_now())
        configure_recon_alert_worker(self.db, interval_seconds=60)
        sleeps: list[float] = []
        result = watch_recon_alert_worker(
            config=self.config,
            logger=self.logger,
            db=self.db,
            sleep=lambda value: sleeps.append(value),
            max_cycles=2,
        )
        self.assertEqual(result["cycles"], 2)
        self.assertEqual(result["executed"], 1)
        self.assertEqual(sleeps, [60])


if __name__ == "__main__":
    unittest.main()
