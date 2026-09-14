from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Config, Database, Logger, ReconError, json_dumps, utc_now
from dashboard import DashboardHandler
from finding_notification_outbox import enqueue_finding_notification_event
from notification_operations_center import (
    combined_dead_letters,
    notification_delivery_action,
    notification_delivery_operations,
)
from product_platform import operations_center
from recon_alert_outbox import enqueue_recon_alert_event


class NotificationOperationsCenterTests(unittest.TestCase):
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

    def _finding_event(self, event_id: str = "finding-op") -> str:
        now = utc_now()
        self.db.execute(
            "INSERT INTO notification_events("
            "event_id,target,event_type,mode,score,fingerprint,payload_json,status,occurrences,created_at,last_seen_at"
            ") VALUES(?,?,?,?,80,?,?,'queued',1,?,?)",
            (
                event_id,
                "example.test",
                "potential_finding",
                "immediate",
                f"fp-{event_id}",
                json_dumps({"title": "Finding delivery fixture", "target": "example.test"}),
                now,
                now,
            ),
        )
        enqueue_finding_notification_event(self.db, event_id)
        return event_id

    def _recon_event(self, run_id: str = "RUN-OPS") -> str:
        now = utc_now()
        cursor = self.db.execute(
            "INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,"
            "first_seen,last_seen,last_run_id,occurrences,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "example.test",
                f"ops-{run_id}",
                "new_url",
                "HIGH",
                90,
                "Recon delivery fixture",
                "https://example.test/admin",
                "{}",
                now,
                now,
                run_id,
                1,
                "open",
            ),
        )
        result = enqueue_recon_alert_event(
            self.db,
            alert_id=int(cursor.lastrowid),
            target="example.test",
            run_id=run_id,
            payload={
                "category": "new_url",
                "severity": "HIGH",
                "risk_score": 90,
                "title": "Recon delivery fixture",
                "item": "https://example.test/admin",
            },
        )
        return str(result["event_id"])

    def test_unified_snapshot_keeps_two_worker_views(self) -> None:
        self._finding_event()
        self._recon_event()
        status = notification_delivery_operations(self.db, now="2099-01-01T00:00:00Z")
        self.assertEqual(set(status["workers"]), {"finding", "recon_alert"})
        self.assertIn("slo", status)
        self.assertIn("supervisor", status)
        self.assertEqual(status["supervisor"]["last_status"], "never_run")
        self.assertEqual(status["queue_depth"], 2)
        self.assertEqual(status["due_now"], 2)
        self.assertEqual(status["workers"]["finding"]["queue_depth"], 1)
        self.assertEqual(status["workers"]["recon_alert"]["queue_depth"], 1)

    def test_configure_changes_only_selected_worker(self) -> None:
        baseline = notification_delivery_operations(self.db)
        finding_before = dict(baseline["workers"]["finding"]["policy"])
        result = notification_delivery_action(
            worker="recon_alert",
            action="configure",
            config=self.config,
            logger=self.logger,
            db=self.db,
            enabled=False,
            interval_seconds=300,
            batch_limit=17,
        )
        recon = result["operations"]["workers"]["recon_alert"]["policy"]
        finding = result["operations"]["workers"]["finding"]["policy"]
        self.assertFalse(recon["enabled"])
        self.assertEqual(recon["interval_seconds"], 300)
        self.assertEqual(recon["batch_limit"], 17)
        self.assertEqual(finding["enabled"], finding_before["enabled"])
        self.assertEqual(finding["interval_seconds"], finding_before["interval_seconds"])
        self.assertEqual(finding["batch_limit"], finding_before["batch_limit"])

    def test_combined_dead_letters_preserve_worker_identity_and_retry_scope(self) -> None:
        finding_id = self._finding_event("finding-dead")
        recon_id = self._recon_event("RUN-DEAD")
        self.db.execute(
            "UPDATE finding_notification_outbox SET status='failed',attempt_count=8,last_error='finding offline' "
            "WHERE event_id=?",
            (finding_id,),
        )
        self.db.execute(
            "UPDATE recon_alert_notification_outbox SET status='failed',attempt_count=8,last_error='recon offline' "
            "WHERE event_id=?",
            (recon_id,),
        )
        status = notification_delivery_operations(self.db)
        self.assertEqual(status["dead_letter_open"], 2)
        dead = combined_dead_letters(self.db)
        self.assertEqual({row["worker"] for row in dead}, {"finding", "recon_alert"})

        result = notification_delivery_action(
            worker="finding",
            action="retry",
            config=self.config,
            logger=self.logger,
            db=self.db,
            event_id=finding_id,
        )
        self.assertEqual(result["result"]["requeued"], 1)
        remaining = combined_dead_letters(self.db)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["worker"], "recon_alert")
        self.assertEqual(remaining[0]["event_id"], recon_id)

    def test_product_operations_payload_embeds_delivery_workers(self) -> None:
        self._finding_event()
        self._recon_event()
        status = operations_center(self.paths, self.db, refresh=True, deep_check=False)
        delivery = status["delivery_workers"]
        self.assertEqual(set(delivery["workers"]), {"finding", "recon_alert"})
        self.assertIn("slo", delivery)
        self.assertEqual(delivery["queue_depth"], 2)

    def test_dashboard_operations_page_renders_both_workers(self) -> None:
        self._finding_event()
        self._recon_event()
        handler = object.__new__(DashboardHandler)
        handler.paths = self.paths
        handler.db_path = self.paths.db
        handler.query = lambda: {}
        captured: dict[str, object] = {}
        handler.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
        handler.operations_center_page()
        body = str(captured["body"])
        self.assertEqual(captured["title"], "Operations center")
        self.assertIn("Delivery workers", body)
        self.assertIn("Notification supervisor", body)
        self.assertIn("Delivery SLOs", body)
        self.assertIn("Finding delivery", body)
        self.assertIn("Recon Alert delivery", body)
        self.assertIn("Dead-letter", body)
        self.assertIn("/notification-workers/action", body)

    def test_invalid_dispatch_is_rejected(self) -> None:
        with self.assertRaises(ReconError):
            notification_delivery_action(
                worker="unknown",
                action="run",
                config=self.config,
                logger=self.logger,
                db=self.db,
            )
        with self.assertRaises(ReconError):
            notification_delivery_action(
                worker="finding",
                action="delete",
                config=self.config,
                logger=self.logger,
                db=self.db,
            )


if __name__ == "__main__":
    unittest.main()
