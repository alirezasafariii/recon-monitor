from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import notification_transports
import reporting
from core import APP_VERSION, AppPaths, Config, Database, Logger, TargetPolicy, json_dumps, utc_now
from reporting import create_alerts_and_notify, send_daily_digest


class ReconAlertTransportConsolidationTests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-TRANSPORT',?,'success',?,?,?,1)",
            (APP_VERSION, now, now, "example.test"),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-TRANSPORT','example.test','policy','success','report',?,?,?,0)",
            (now, now, str(paths.output / "RUN-TRANSPORT")),
        )
        policy = TargetPolicy.from_dict(
            {
                "name": "example.test",
                "roots": ["example.test"],
                "alert": {"minimum_score": 0, "cooldown_hours": 24},
            }
        )
        run_dir = paths.output / "RUN-TRANSPORT" / "example.test"
        run_dir.mkdir(parents=True, exist_ok=True)
        ctx = SimpleNamespace(
            events_path=run_dir / "changes" / "events.jsonl",
            policy=policy,
            config=Config(paths),
            db=db,
            run_id="RUN-TRANSPORT",
            logger=Logger(paths, verbose=False),
        )
        ctx.events_path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "target": "example.test",
            "dedup_key": "transport-event",
            "category": "new_url",
            "severity": "HIGH",
            "risk_score": 90,
            "title": "High-value URL changed",
            "item": "https://example.test/admin/export.csv",
            "details": {},
            "confirmation_state": "confirmed",
        }
        ctx.events_path.write_text(json_dumps(event) + "\n", encoding="utf-8")
        return temp, paths, db, ctx

    def test_immediate_alert_uses_shared_transport_and_marks_notified(self):
        temp, _paths, db, ctx = self.project()
        try:
            delivery = {
                "delivered": True,
                "channels": ["notify"],
                "channel": "notify",
                "error": "",
            }
            with patch.object(reporting, "deliver_notification_message", return_value=delivery) as send:
                result = create_alerts_and_notify(ctx, baseline=False)

            self.assertTrue(result["notified"])
            self.assertEqual(result["immediate"], 1)
            send.assert_called_once()
            row = db.one("SELECT last_notified FROM alerts WHERE target='example.test'")
            self.assertIsNotNone(row)
            self.assertTrue(row["last_notified"])

            with patch.object(reporting, "deliver_notification_message", return_value=delivery) as replay_send:
                replay = create_alerts_and_notify(ctx, baseline=False)
            self.assertEqual(replay["immediate"], 0)
            self.assertFalse(replay["notified"])
            replay_send.assert_not_called()
        finally:
            db.close()
            temp.cleanup()

    def test_total_transport_failure_does_not_mark_alert_notified(self):
        temp, _paths, db, ctx = self.project()
        try:
            failed = {
                "delivered": False,
                "channels": [],
                "channel": "",
                "error": "delivery failed",
            }
            with patch.object(reporting, "deliver_notification_message", return_value=failed) as send:
                result = create_alerts_and_notify(ctx, baseline=False)
            self.assertFalse(result["notified"])
            self.assertEqual(result["immediate"], 1)
            send.assert_called_once()
            row = db.one("SELECT last_notified FROM alerts WHERE target='example.test'")
            self.assertIsNotNone(row)
            self.assertFalse(row["last_notified"])

            with patch.object(reporting, "deliver_notification_message", return_value=failed) as retry_send:
                retry = create_alerts_and_notify(ctx, baseline=False)
            self.assertEqual(retry["immediate"], 1)
            retry_send.assert_called_once()
        finally:
            db.close()
            temp.cleanup()

    def test_partial_transport_success_counts_as_delivery(self):
        temp, _paths, db, ctx = self.project()
        try:
            partial = {
                "delivered": True,
                "channels": ["telegram"],
                "channel": "telegram",
                "error": "notify transport failed",
            }
            with patch.object(reporting, "deliver_notification_message", return_value=partial):
                result = create_alerts_and_notify(ctx, baseline=False)
            self.assertTrue(result["notified"])
            row = db.one("SELECT last_notified FROM alerts WHERE target='example.test'")
            self.assertTrue(row["last_notified"])
        finally:
            db.close()
            temp.cleanup()

    def test_baseline_never_calls_transport(self):
        temp, _paths, db, ctx = self.project()
        try:
            with patch.object(reporting, "deliver_notification_message") as send:
                result = create_alerts_and_notify(ctx, baseline=True)
            self.assertFalse(result["notified"])
            self.assertTrue(result["baseline_suppressed"])
            send.assert_not_called()
            self.assertEqual(db.one("SELECT COUNT(*) count FROM alerts")["count"], 0)
        finally:
            db.close()
            temp.cleanup()

    def test_daily_digest_uses_shared_transport(self):
        temp, paths, db, ctx = self.project()
        try:
            now = utc_now()
            db.execute(
                "INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,first_seen,last_seen,last_run_id,occurrences,status) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "example.test",
                    "digest-event",
                    "new_url",
                    "HIGH",
                    90,
                    "Digest URL",
                    "https://example.test/digest",
                    "{}",
                    now,
                    now,
                    "RUN-TRANSPORT",
                    1,
                    "open",
                ),
            )
            delivery = {
                "delivered": True,
                "channels": ["telegram"],
                "channel": "telegram",
                "error": "",
            }
            with patch.object(reporting, "deliver_notification_message", return_value=delivery) as send:
                result = send_daily_digest(paths, ctx.config, db, ctx.logger, hours=24)
            self.assertTrue(result["sent"])
            self.assertEqual(result["alerts"], 1)
            send.assert_called_once()
        finally:
            db.close()
            temp.cleanup()

    def test_transport_interface_channel_semantics(self):
        cases = [
            ((True, ""), (False, "notify failed"), True, ["telegram"]),
            ((False, "telegram failed"), (True, ""), True, ["notify"]),
            ((True, ""), (True, ""), True, ["telegram", "notify"]),
            ((False, "telegram failed"), (False, "notify failed"), False, []),
            ((False, "telegram_not_configured"), (False, "notify_not_configured"), False, []),
        ]
        for telegram_result, notify_result, delivered, channels in cases:
            with self.subTest(telegram=telegram_result, notify=notify_result):
                with patch.object(notification_transports, "send_telegram", return_value=telegram_result), patch.object(
                    notification_transports, "send_notify_cli", return_value=notify_result
                ):
                    result = notification_transports.deliver_notification_message(object(), SimpleNamespace(warn=lambda *a, **k: None), "message")
                self.assertEqual(result["delivered"], delivered)
                self.assertEqual(result["channels"], channels)
                if telegram_result[1] == "telegram_not_configured" and notify_result[1] == "notify_not_configured":
                    self.assertIn("no_configured_notification_transport", result["error"])

    def test_reporting_source_has_no_transport_implementation(self):
        source = (ROOT / "app" / "reporting.py").read_text(encoding="utf-8")
        self.assertIn("from notification_transports import deliver_notification_message", source)
        self.assertNotIn("TelegramNotifier", source)
        self.assertNotIn("_send_notify_cli", source)
        self.assertNotIn("subprocess.run", source)
        self.assertNotIn('tool_path("notify")', source)


if __name__ == "__main__":
    unittest.main()
