from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Database, utc_now
from recon_alert_outbox import (
    deliver_recon_alert_outbox,
    enqueue_recon_alert_event,
    ensure_recon_alert_outbox_schema,
    recon_alert_outbox_summary,
    requeue_failed_recon_alerts,
    unresolved_recon_alert_delivery,
)


class ReconAlertOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.db = Database(self.paths.db)
        ensure_recon_alert_outbox_schema(self.db)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def _alert(self, *, dedup_key: str = "change-1", run_id: str = "RUN-1") -> int:
        now = utc_now()
        cursor = self.db.execute(
            "INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,"
            "first_seen,last_seen,last_run_id,occurrences,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                dedup_key,
                "new_url",
                "HIGH",
                90,
                "High-value URL changed",
                "https://example.test/admin/export.csv",
                "{}",
                now,
                now,
                run_id,
                1,
                "open",
            ),
        )
        return int(cursor.lastrowid)

    @staticmethod
    def _payload() -> dict[str, object]:
        return {
            "category": "new_url",
            "severity": "HIGH",
            "risk_score": 90,
            "title": "High-value URL changed",
            "item": "https://example.test/admin/export.csv",
            "change_class": "asset",
            "confirmation_state": "confirmed",
        }

    def _enqueue(self, alert_id: int, run_id: str = "RUN-1") -> dict[str, object]:
        return enqueue_recon_alert_event(
            self.db,
            alert_id=alert_id,
            target="example.test",
            run_id=run_id,
            payload=self._payload(),
        )

    def test_enqueue_is_idempotent_per_alert_and_run(self):
        alert_id = self._alert()
        first = self._enqueue(alert_id)
        second = self._enqueue(alert_id)
        self.assertTrue(first["queued"])
        self.assertFalse(first["deduplicated"])
        self.assertTrue(second["deduplicated"])
        self.assertEqual(first["event_id"], second["event_id"])
        self.assertEqual(
            self.db.one("SELECT COUNT(*) AS n FROM recon_alert_notification_outbox")["n"],
            1,
        )

    def test_unresolved_delivery_blocks_duplicate_next_run(self):
        alert_id = self._alert()
        first = self._enqueue(alert_id, "RUN-1")
        second = self._enqueue(alert_id, "RUN-2")
        self.assertTrue(first["queued"])
        self.assertFalse(second["queued"])
        self.assertTrue(second["blocked_by_unresolved"])
        self.assertEqual(
            self.db.one("SELECT COUNT(*) AS n FROM recon_alert_notification_outbox")["n"],
            1,
        )

    def test_failure_retries_without_marking_alert_notified_then_success_finalizes(self):
        alert_id = self._alert()
        queued = self._enqueue(alert_id)
        failed = deliver_recon_alert_outbox(
            config=object(),
            logger=object(),
            db=self.db,
            transport=lambda *_: {"delivered": False, "channels": [], "error": "temporary failure"},
        )
        self.assertEqual(failed["retry_pending"], 1)
        row = self.db.one("SELECT last_notified FROM alerts WHERE id=?", (alert_id,))
        self.assertFalse(row["last_notified"])
        outbox = self.db.one(
            "SELECT status,attempt_count,last_error FROM recon_alert_notification_outbox WHERE event_id=?",
            (queued["event_id"],),
        )
        self.assertEqual(outbox["status"], "retry_pending")
        self.assertEqual(outbox["attempt_count"], 1)
        self.assertEqual(outbox["last_error"], "temporary failure")

        self.db.execute(
            "UPDATE recon_alert_notification_outbox SET next_attempt_at=? WHERE event_id=?",
            (utc_now(), queued["event_id"]),
        )
        delivered = deliver_recon_alert_outbox(
            config=object(),
            logger=object(),
            db=self.db,
            transport=lambda *_: {"delivered": True, "channels": ["notify"], "channel": "notify", "error": ""},
        )
        self.assertEqual(delivered["delivered"], 1)
        row = self.db.one("SELECT last_notified FROM alerts WHERE id=?", (alert_id,))
        self.assertTrue(row["last_notified"])
        outbox = self.db.one(
            "SELECT status,attempt_count,delivered_at FROM recon_alert_notification_outbox WHERE event_id=?",
            (queued["event_id"],),
        )
        self.assertEqual(outbox["status"], "delivered")
        self.assertEqual(outbox["attempt_count"], 2)
        self.assertTrue(outbox["delivered_at"])
        self.assertIsNone(unresolved_recon_alert_delivery(self.db, alert_id))

    def test_terminal_failure_can_be_explicitly_requeued(self):
        alert_id = self._alert()
        queued = self._enqueue(alert_id)
        self.db.execute(
            "UPDATE recon_alert_notification_outbox SET max_attempts=1 WHERE event_id=?",
            (queued["event_id"],),
        )
        result = deliver_recon_alert_outbox(
            config=object(),
            logger=object(),
            db=self.db,
            transport=lambda *_: {"delivered": False, "channels": [], "error": "terminal"},
        )
        self.assertEqual(result["failed"], 1)
        self.assertEqual(recon_alert_outbox_summary(self.db)["failed"], 1)
        self.assertFalse(self.db.one("SELECT last_notified FROM alerts WHERE id=?", (alert_id,))["last_notified"])

        self.assertEqual(requeue_failed_recon_alerts(self.db, event_id=str(queued["event_id"])), 1)
        row = self.db.one(
            "SELECT status,attempt_count,last_error FROM recon_alert_notification_outbox WHERE event_id=?",
            (queued["event_id"],),
        )
        self.assertEqual(row["status"], "retry_pending")
        self.assertEqual(row["attempt_count"], 0)
        self.assertEqual(row["last_error"], "")

    def test_lost_lease_cannot_mark_alert_notified(self):
        alert_id = self._alert(dedup_key="lease-loss-success")
        queued = self._enqueue(alert_id)

        def transport(_config, _logger, _message):
            self.db.execute(
                "UPDATE recon_alert_notification_outbox "
                "SET lease_id='another-worker' WHERE event_id=?",
                (queued["event_id"],),
            )
            return {
                "delivered": True,
                "channels": ["notify"],
                "channel": "notify",
                "error": "",
            }

        result = deliver_recon_alert_outbox(
            config=object(),
            logger=object(),
            db=self.db,
            transport=transport,
        )
        self.assertEqual(result["delivered"], 0)
        self.assertEqual(result["lease_lost"], 1)
        alert = self.db.one(
            "SELECT last_notified FROM alerts WHERE id=?",
            (alert_id,),
        )
        self.assertFalse(alert["last_notified"])
        outbox = self.db.one(
            "SELECT status,lease_id,attempt_count "
            "FROM recon_alert_notification_outbox WHERE event_id=?",
            (queued["event_id"],),
        )
        self.assertEqual(str(outbox["status"]), "delivering")
        self.assertEqual(str(outbox["lease_id"]), "another-worker")
        self.assertEqual(int(outbox["attempt_count"]), 0)

    def test_lost_lease_cannot_record_terminal_failure(self):
        alert_id = self._alert(dedup_key="lease-loss-failure")
        queued = self._enqueue(alert_id)
        self.db.execute(
            "UPDATE recon_alert_notification_outbox "
            "SET max_attempts=1 WHERE event_id=?",
            (queued["event_id"],),
        )

        def transport(_config, _logger, _message):
            self.db.execute(
                "UPDATE recon_alert_notification_outbox "
                "SET lease_id='another-worker' WHERE event_id=?",
                (queued["event_id"],),
            )
            return {
                "delivered": False,
                "channels": [],
                "channel": "fixture",
                "error": "transport_down",
            }

        result = deliver_recon_alert_outbox(
            config=object(),
            logger=object(),
            db=self.db,
            transport=transport,
        )
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["retry_pending"], 0)
        self.assertEqual(result["lease_lost"], 1)
        alert = self.db.one(
            "SELECT last_notified FROM alerts WHERE id=?",
            (alert_id,),
        )
        self.assertFalse(alert["last_notified"])

    def test_successful_batch_marks_all_alerts_notified(self):
        first_id = self._alert(dedup_key="change-a")
        second_id = self._alert(dedup_key="change-b")
        self._enqueue(first_id)
        self._enqueue(second_id)
        calls: list[str] = []

        def transport(_config, _logger, message: str):
            calls.append(message)
            return {"delivered": True, "channels": ["telegram"], "channel": "telegram", "error": ""}

        result = deliver_recon_alert_outbox(
            config=object(),
            logger=object(),
            db=self.db,
            target="example.test",
            run_id="RUN-1",
            transport=transport,
        )
        self.assertEqual(result["delivered"], 2)
        self.assertEqual(len(calls), 1)
        self.assertIn("High-priority changes: 2", calls[0])
        rows = self.db.all("SELECT last_notified FROM alerts ORDER BY id")
        self.assertTrue(all(row["last_notified"] for row in rows))


if __name__ == "__main__":
    unittest.main()
