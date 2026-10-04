from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from core import AppPaths, Database
from finding_notification_outbox import deliver_finding_notification_outbox, ensure_finding_notification_outbox_schema
from finding_notification_operations import run_finding_notification_worker


class FindingNotificationBatchDeliveryTests(unittest.TestCase):
    NOW = "2099-01-01T00:00:00Z"

    def setUp(self):
        for name in ("subprocess.Popen", "socket.getaddrinfo", "socket.socket.connect", "urllib.request.urlopen"):
            guard = patch(name, side_effect=AssertionError("offline test attempted I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        paths = AppPaths.from_root(Path(tmp.name))
        paths.ensure()
        self.db = Database(paths.db)
        self.addCleanup(self.db.close)
        ensure_finding_notification_outbox_schema(self.db)
        self.config = SimpleNamespace()
        self.logger = SimpleNamespace(warn=lambda *args, **kwargs: None)

    def event(self, index, *, title_size=580, target="example.test", mode="immediate"):
        event_id = f"notify-F12-{index:03}"
        payload = {"title": f"START-{index:03} " + "x" * title_size,
                   "endpoint": f"https://{target}/END-{index:03}", "bug_family": "fixture", "transition": "new"}
        self.db.execute(
            "INSERT INTO notification_events(event_id,target,event_type,mode,score,fingerprint,payload_json,created_at,last_seen_at) "
            "VALUES(?,?,'potential_finding',?,80,?,?,?,?)",
            (event_id, target, mode, event_id, json.dumps(payload), "2098-01-01T00:00:00Z", "2098-01-01T00:00:00Z"),
        )
        return event_id

    def deliver(self, transport, **kwargs):
        return deliver_finding_notification_outbox(config=self.config, logger=self.logger, db=self.db,
                                                   now=kwargs.pop("now", self.NOW), transport=transport, **kwargs)

    def states(self):
        return {row["event_id"]: row["status"] for row in self.db.all("SELECT event_id,status FROM notification_events")}

    @staticmethod
    def success():
        return {"delivered": True, "channel": "fixture", "channels": ["fixture"], "error": ""}

    def test_fifty_long_events_are_all_present_in_bounded_sent_messages(self):
        for i in range(50):
            self.event(i)
        messages = []

        def send(_config, _logger, text):
            messages.append(text)
            return self.success()

        result = self.deliver(send)
        self.assertEqual(result["delivered"], 50)
        self.assertGreater(len(messages), 1)
        self.assertTrue(all(len(message) <= 15000 for message in messages))
        self.assertEqual(sorted(re.findall(r"END-(\d{3})", "\n".join(messages))), [f"{i:03}" for i in range(50)])
        self.assertEqual(set(self.states().values()), {"delivered"})

    def test_failed_submessage_only_retries_its_own_events(self):
        for i in range(50):
            self.event(i)
        sent, failed_ids = [], set()

        def send(_config, _logger, text):
            sent.append(text)
            if len(sent) == 2:
                failed_ids.update("notify-F12-" + value for value in re.findall(r"END-(\d{3})", text))
                return {"delivered": False, "error": "fixture transport failure", "channel": "fixture"}
            return self.success()

        result = self.deliver(send)
        self.assertGreater(len(sent), 1)
        self.assertTrue(failed_ids)
        self.assertEqual(result["retry_pending"], len(failed_ids))
        self.assertEqual({event_id for event_id, status in self.states().items() if status == "queued"}, failed_ids)
        retried = []
        self.deliver(lambda _config, _logger, text: retried.append(text) or self.success(), now="2099-01-01T00:01:00Z")
        self.assertEqual({"notify-F12-" + value for value in re.findall(r"END-(\d{3})", "\n".join(retried))}, failed_ids)
        self.assertEqual(set(self.states().values()), {"delivered"})

    def test_batch_metadata_matches_each_message_and_delivery_record(self):
        for i in range(50):
            self.event(i)
        sent = []
        result = self.deliver(lambda _config, _logger, text: sent.append(text) or self.success())
        self.assertEqual(len(result["batches"]), len(sent))
        for message, batch in zip(sent, result["batches"]):
            event_ids = {"notify-F12-" + value for value in re.findall(r"END-(\d{3})", message)}
            self.assertEqual(set(batch["event_ids"]), event_ids)
            self.assertEqual(batch["events"], len(event_ids))
            self.assertEqual(batch["message_lengths"], [len(message)])
            self.assertEqual(batch["sent_parts"], 1)
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM notification_deliveries WHERE status='delivered'")[0], 50)
        self.assertEqual(set(row[0] for row in self.db.all("SELECT attempt_count FROM finding_notification_outbox")), {1})

    def test_exact_character_limit_includes_header_and_never_cuts_next_event(self):
        self.event(0, title_size=0)
        seed = []
        self.deliver(lambda _config, _logger, text: seed.append(text) or self.success())
        self.event(1, title_size=15000 - len(seed[0]))
        self.event(2, title_size=0)
        messages = []
        result = self.deliver(lambda _config, _logger, text: messages.append(text) or self.success())
        self.assertEqual(result["delivered"], 2)
        self.assertEqual(len(messages), 2)
        self.assertEqual(len(messages[0]), 15000)
        self.assertTrue(messages[0].endswith("END-001"))
        self.assertTrue(messages[1].endswith("END-002"))

    def test_one_oversized_event_delivers_all_parts_and_is_acknowledged_once(self):
        event_id = self.event(0, title_size=40000)
        messages = []
        result = self.deliver(lambda _config, _logger, text: messages.append(text) or self.success())
        self.assertEqual(len(messages), 3)
        self.assertTrue(all(len(message) <= 15000 for message in messages))
        joined = "".join(messages)
        self.assertIn("START-000 " + "x" * 40000, joined)
        self.assertTrue(joined.endswith("END-000"))
        self.assertEqual(result["delivered"], 1)
        self.assertEqual(result["batches"][0]["message_parts"], 3)
        self.assertEqual(result["batches"][0]["events"], 1)
        self.assertEqual(self.db.one("SELECT attempt_count FROM finding_notification_outbox WHERE event_id=?", (event_id,))[0], 1)
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM notification_deliveries WHERE event_id=?", (event_id,))[0], 1)

    def test_part_failure_never_acknowledges_oversized_event_and_keeps_other_batch(self):
        oversized = self.event(0, title_size=40000)
        other = self.event(1, title_size=10)
        parts = []

        def send(_config, _logger, text):
            parts.append(text)
            if len(parts) == 2:
                return {"delivered": False, "channel": "fixture", "error": "part failed"}
            return self.success()

        result = self.deliver(send)
        self.assertEqual(len(parts), 3)
        self.assertEqual(result["delivered"], 1)
        self.assertEqual(result["retry_pending"], 1)
        self.assertEqual(self.states(), {oversized: "queued", other: "delivered"})
        self.assertEqual(result["batches"][0]["sent_parts"], 2)
        retry = []
        second = self.deliver(lambda _config, _logger, text: retry.append(text) or self.success(), now="2099-01-01T00:01:00Z")
        self.assertEqual(second["delivered"], 1)
        self.assertEqual(len(retry), 3)
        self.assertIn("START-000 " + "x" * 40000, "".join(retry))
        self.assertNotIn("END-001", "".join(retry))

    def test_all_parts_need_a_shared_successful_channel(self):
        event_id = self.event(0, title_size=40000)
        results = iter([
            {"delivered": True, "channels": ["telegram"], "channel": "telegram"},
            {"delivered": True, "channels": ["notify"], "channel": "notify"},
        ])
        result = self.deliver(lambda *_args: next(results))
        self.assertEqual(result["delivered"], 0)
        self.assertEqual(result["retry_pending"], 1)
        self.assertEqual(self.states()[event_id], "queued")
        self.assertEqual(result["batches"][0]["sent_parts"], 2)
        self.assertIn("no_complete_channel", result["batches"][0]["error"])

    def test_common_channel_can_deliver_all_parts_despite_other_channel_failures(self):
        self.event(0, title_size=40000)
        channels = iter([["telegram", "notify"], ["telegram"], ["telegram", "notify"]])
        result = self.deliver(lambda *_args: {"delivered": True, "channels": next(channels), "error": "notify unavailable"})
        self.assertEqual(result["delivered"], 1)
        self.assertEqual(result["batches"][0]["channel"], "telegram")
        self.assertEqual(set(self.states().values()), {"delivered"})

    def test_unicode_and_newlines_in_long_event_are_preserved(self):
        event_id = self.event(0, title_size=0)
        title = "سلام 🚀\n" * 4000
        self.db.execute("UPDATE notification_events SET payload_json=? WHERE event_id=?",
                        (json.dumps({"title": title, "endpoint": "https://example.test/END-000"}), event_id))
        messages = []
        result = self.deliver(lambda _config, _logger, text: messages.append(text) or self.success())
        self.assertEqual(result["delivered"], 1)
        self.assertIn(title, "".join(messages))
        self.assertTrue(all(len(message) <= 15000 for message in messages))

    def test_target_and_mode_groups_never_mix_even_when_split(self):
        for i, (target, mode) in enumerate([
            ("first.test", "immediate"), ("first.test", "digest"),
            ("second.test", "immediate"), ("second.test", "system_warning"),
        ]):
            self.event(i, title_size=10000, target=target, mode=mode)
        messages = []
        result = self.deliver(lambda _config, _logger, text: messages.append(text) or self.success())
        self.assertEqual(result["delivered"], 4)
        for text, batch in zip(messages, result["batches"]):
            self.assertIn("Target: " + batch["target"], text)
            self.assertIn("Mode: " + batch["mode"], text)
            self.assertEqual(len(re.findall(r"END-\d{3}", text)), 1)

    def test_event_limit_and_priority_order_remain_enforced(self):
        low = self.event(0, title_size=10000)
        high = self.event(1, title_size=10000)
        self.db.execute("UPDATE notification_events SET score=100 WHERE event_id=?", (high,))
        messages = []
        first = self.deliver(lambda _config, _logger, text: messages.append(text) or self.success(), limit=1)
        self.assertEqual(first["due"], 1)
        self.assertIn("END-001", messages[0])
        self.assertEqual(self.states(), {low: "queued", high: "delivered"})

    def test_terminal_failure_only_changes_events_in_failed_message(self):
        for i in range(4):
            self.event(i, title_size=10000)
        ensure_finding_notification_outbox_schema(self.db)
        self.db.execute("UPDATE finding_notification_outbox SET max_attempts=1")
        failed_ids = set()

        def send(_config, _logger, text):
            if "END-001" in text:
                failed_ids.add("notify-F12-001")
                return {"delivered": False, "error": "terminal fixture failure"}
            return self.success()

        result = self.deliver(send)
        self.assertEqual(result["delivered"], 3)
        self.assertEqual(result["failed"], 1)
        self.assertEqual({event_id for event_id, status in self.states().items() if status == "failed"}, failed_ids)

    def test_transport_exception_is_local_to_one_message(self):
        for i in range(3):
            self.event(i, title_size=10000)

        def send(_config, _logger, text):
            if "END-001" in text:
                raise TimeoutError("fixture timeout")
            return self.success()

        result = self.deliver(send)
        self.assertEqual(result["delivered"], 2)
        self.assertEqual(result["retry_pending"], 1)
        self.assertEqual(self.db.one("SELECT last_error FROM finding_notification_outbox WHERE event_id='notify-F12-001'")[0], "fixture timeout")

    def test_replaced_lease_stops_later_parts_and_cannot_acknowledge_event(self):
        event_id = self.event(0, title_size=40000)
        sent = []

        def send(_config, _logger, text):
            sent.append(text)
            self.db.execute("UPDATE finding_notification_outbox SET lease_id='replacement' WHERE event_id=?", (event_id,))
            return self.success()

        result = self.deliver(send)
        self.assertEqual(len(sent), 1)
        self.assertEqual(result["delivered"], 0)
        self.assertEqual(self.states()[event_id], "queued")
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM notification_deliveries")[0], 0)
        self.assertEqual(result["batches"][0]["error"], "notification_batch_lease_lost")

    def test_remaining_batches_renew_lease_and_backoff_uses_failure_time(self):
        for i in range(3):
            self.event(i, title_size=10000)
        clock = {"now": self.NOW}
        observed_expiries = []

        def send(_config, _logger, text):
            observed_expiries.append(self.db.one("SELECT lease_expires_at FROM finding_notification_outbox WHERE event_id='notify-F12-002'")[0])
            if "END-000" in text:
                clock["now"] = "2099-01-01T00:06:00Z"
                return self.success()
            return {"delivered": False, "error": "fixture failure after time elapsed"}

        with patch("finding_notification_outbox.utc_now", side_effect=lambda: clock["now"]):
            result = self.deliver(send, now="")
        self.assertEqual(result["retry_pending"], 2)
        self.assertTrue(observed_expiries[1].startswith("2099-01-01T00:11:00"))
        self.assertTrue(self.db.one("SELECT next_attempt_at FROM finding_notification_outbox WHERE event_id='notify-F12-001'")[0].startswith("2099-01-01T00:07:00"))

    def test_worker_operations_records_split_delivery_counts(self):
        for i in range(50):
            self.event(i)
        messages = []
        result = run_finding_notification_worker(config=self.config, logger=self.logger, db=self.db, force=True,
                                                now=self.NOW, limit=50, transport=lambda _config, _logger, text: messages.append(text) or self.success())
        self.assertEqual(result["delivery"]["delivered"], 50)
        self.assertGreater(len(messages), 1)
        worker = self.db.one("SELECT attempted,delivered,retry_pending,failed FROM finding_notification_worker_runs WHERE worker_run_id=?", (result["worker_run_id"],))
        self.assertEqual(tuple(worker), (50, 50, 0, 0))

    def test_live_worker_renews_remaining_batches_with_current_time(self):
        for i in range(3):
            self.event(i, title_size=10000)
        clock = {"now": self.NOW}
        expiries = []

        def send(_config, _logger, text):
            expiries.append(self.db.one("SELECT lease_expires_at FROM finding_notification_outbox WHERE event_id='notify-F12-002'")[0])
            if "END-000" in text:
                clock["now"] = "2099-01-01T00:06:00Z"
                return self.success()
            return {"delivered": False, "error": "fixture failure after time elapsed"}

        with patch("finding_notification_outbox.utc_now", side_effect=lambda: clock["now"]), \
             patch("finding_notification_operations.utc_now", side_effect=lambda: clock["now"]):
            result = run_finding_notification_worker(config=self.config, logger=self.logger, db=self.db,
                                                    force=True, transport=send)
        self.assertEqual(result["delivery"]["retry_pending"], 2)
        self.assertTrue(expiries[1].startswith("2099-01-01T00:11:00"))
        self.assertTrue(self.db.one("SELECT next_attempt_at FROM finding_notification_outbox WHERE event_id='notify-F12-001'")[0].startswith("2099-01-01T00:07:00"))
        worker = self.db.one("SELECT finished_at FROM finding_notification_worker_runs WHERE worker_run_id=?", (result["worker_run_id"],))
        self.assertEqual(worker[0], clock["now"])


if __name__ == "__main__":
    unittest.main()
