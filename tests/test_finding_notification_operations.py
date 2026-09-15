from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Config, Database, Logger, json_dumps
from finding_notification_operations import (
    configure_finding_notification_worker,
    drain_finding_notification_outbox,
    finding_notification_diagnostics,
    list_dead_letters,
    retry_dead_letters,
    run_finding_notification_worker,
    watch_finding_notification_worker,
    worker_due,
)
from finding_notification_outbox import enqueue_finding_notification_event, ensure_finding_notification_outbox_schema


class FindingNotificationOperationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.config = Config(self.paths)
        self.logger = Logger(self.paths, verbose=False)
        self.db = Database(self.paths.db)
        ensure_finding_notification_outbox_schema(self.db)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _event(self, event_id: str, *, target: str = "example.test", mode: str = "immediate", created_at: str = "2026-09-14T00:00:00Z") -> None:
        self.db.execute(
            "INSERT INTO notification_events("
            "event_id,target,event_type,mode,score,fingerprint,payload_json,status,occurrences,created_at,last_seen_at"
            ") VALUES(?,?,?,?,80,?,?,'queued',1,?,?)",
            (
                event_id,
                target,
                "potential_finding",
                mode,
                f"fp-{event_id}",
                json_dumps({
                    "transition": "new",
                    "bug_family": "fixture",
                    "title": "Operational fixture",
                    "target": target,
                }),
                created_at,
                created_at,
            ),
        )
        enqueue_finding_notification_event(self.db, event_id)
        self.db.execute(
            "UPDATE finding_notification_outbox SET next_attempt_at=?,created_at=?,updated_at=? WHERE event_id=?",
            (created_at, created_at, created_at, event_id),
        )

    @staticmethod
    def _success(config, logger, message: str):
        return {"delivered": True, "channel": "fixture", "channels": ["fixture"], "error": ""}

    @staticmethod
    def _failure(config, logger, message: str):
        return {"delivered": False, "channel": "fixture", "channels": [], "error": "offline"}

    def test_scheduler_interval_skips_until_due(self) -> None:
        self._event("notify-schedule")
        configure_finding_notification_worker(self.db, interval_seconds=300, batch_limit=25)
        first = run_finding_notification_worker(
            config=self.config,
            logger=self.logger,
            db=self.db,
            now="2026-09-14T01:00:00Z",
            transport=self._success,
        )
        self.assertEqual(first["status"], "success")
        second = run_finding_notification_worker(
            config=self.config,
            logger=self.logger,
            db=self.db,
            now="2026-09-14T01:01:00Z",
            transport=self._success,
        )
        self.assertEqual(second["status"], "skipped")
        self.assertEqual(second["reason"], "interval_pending")
        due = worker_due(self.db, now="2026-09-14T01:05:00Z")
        self.assertTrue(due["due"])

    def test_diagnostics_report_backlog_and_oldest_age(self) -> None:
        self._event("notify-old", created_at="2026-09-14T00:00:00Z")
        self._event("notify-new", created_at="2026-09-14T00:30:00Z")
        status = finding_notification_diagnostics(self.db, now="2026-09-14T01:00:00Z")
        self.assertEqual(status["queue_depth"], 2)
        self.assertEqual(status["due_now"], 2)
        self.assertEqual(status["oldest_pending_at"], "2026-09-14T00:00:00Z")
        self.assertEqual(status["oldest_pending_age_seconds"], 3600)
        self.assertEqual(status["dead_letter_open"], 0)

    def test_legacy_failed_findings_are_quarantined(self):
        self._event("notify-dead")
        self.db.execute("UPDATE finding_notification_outbox SET status='failed' WHERE event_id='notify-dead'")
        result = run_finding_notification_worker(config=self.config, logger=self.logger, db=self.db, force=True,
            now="2099-01-01T00:00:00Z", transport=lambda *_: self.fail("Finding transport must never run"))
        self.assertEqual(result["delivery"]["delivered"], 0)
        self.assertEqual(self.db.one("SELECT status FROM finding_notification_outbox WHERE event_id='notify-dead'")[0], "suppressed")
        self.assertEqual(list_dead_letters(self.db), [])


    def test_drain_suppresses_legacy_finding_batches(self) -> None:
        for index in range(5):
            self._event(f"notify-drain-{index}")
        result = drain_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            batch_limit=2,
            max_batches=10,
            transport=self._success,
        )
        self.assertEqual(result["delivered"], 0)
        self.assertEqual(result["diagnostics"]["queue_depth"], 0)
        self.assertEqual(result["batches"], 1)

    def test_watch_scheduler_executes_then_obeys_interval(self) -> None:
        self._event("notify-watch")
        configure_finding_notification_worker(self.db, interval_seconds=60)
        sleeps: list[float] = []
        result = watch_finding_notification_worker(
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
