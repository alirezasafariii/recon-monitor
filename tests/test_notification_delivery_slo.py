from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import AppPaths, Database, json_dumps
from finding_notification_operations import finding_notification_diagnostics
from finding_notification_outbox import enqueue_finding_notification_event
from notification_delivery_slo import (
    configure_notification_delivery_slo,
    evaluate_notification_delivery_slo,
    list_notification_delivery_slo_breaches,
    list_notification_delivery_slo_events,
)
from notification_supervisor import ensure_notification_supervisor_schema, notification_supervisor_status
from recon_alert_operations import recon_alert_diagnostics


class NotificationDeliverySLOTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.db = Database(self.paths.db)
        finding_notification_diagnostics(self.db)
        recon_alert_diagnostics(self.db)
        ensure_notification_supervisor_schema(self.db)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _finding_event(self, event_id: str, created_at: str = "2026-09-14T00:00:00Z") -> str:
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
                json_dumps({"title": "SLO fixture", "target": "example.test"}),
                created_at,
                created_at,
            ),
        )
        enqueue_finding_notification_event(self.db, event_id)
        self.db.execute(
            "UPDATE finding_notification_outbox SET next_attempt_at=?,created_at=?,updated_at=? WHERE event_id=?",
            (created_at, created_at, created_at, event_id),
        )
        return event_id

    def _snapshot(self, now: str) -> dict[str, object]:
        workers = {
            "finding": finding_notification_diagnostics(self.db, now=now),
            "recon_alert": recon_alert_diagnostics(self.db, now=now),
        }
        supervisor = notification_supervisor_status(self.db, now=now)
        return evaluate_notification_delivery_slo(self.db, workers=workers, supervisor=supervisor, now=now)

    def test_pending_age_crossing_opens_and_resolves_breach(self) -> None:
        configure_notification_delivery_slo(
            self.db,
            pending_warning_seconds=300,
            pending_critical_seconds=600,
            backlog_warning=100,
            backlog_critical=200,
            failure_warning_count=50,
            failure_critical_count=100,
        )
        event_id = self._finding_event("slo-pending")
        status = self._snapshot("2026-09-14T00:20:00Z")
        self.assertEqual(status["state"], "critical")
        open_rows = {row["breach_key"]: row for row in status["open_breaches"]}
        self.assertEqual(open_rows["finding:pending_age_seconds"]["severity"], "critical")
        self.assertEqual(open_rows["finding:pending_age_seconds"]["value"], 1200)
        self.assertEqual(status["emitted_events"][0]["transition"], "opened")

        self.db.execute(
            "UPDATE finding_notification_outbox SET status='delivered',updated_at=? WHERE event_id=?",
            ("2026-09-14T00:21:00Z", event_id),
        )
        resolved = self._snapshot("2026-09-14T00:21:00Z")
        self.assertEqual(resolved["state"], "healthy")
        rows = {row["breach_key"]: row for row in list_notification_delivery_slo_breaches(self.db)}
        self.assertEqual(rows["finding:pending_age_seconds"]["status"], "resolved")
        self.assertEqual(rows["finding:pending_age_seconds"]["duration_seconds"], 60)
        self.assertIn("resolved", {row["transition"] for row in list_notification_delivery_slo_events(self.db)})

    def test_repeated_breach_is_deduplicated_and_reopen_respects_cooldown(self) -> None:
        configure_notification_delivery_slo(
            self.db,
            pending_warning_seconds=60,
            pending_critical_seconds=120,
            backlog_warning=100,
            backlog_critical=200,
            cooldown_seconds=600,
            failure_warning_count=50,
            failure_critical_count=100,
        )
        event_id = self._finding_event("slo-dedup")
        first = self._snapshot("2026-09-14T00:10:00Z")
        second = self._snapshot("2026-09-14T00:11:00Z")
        self.assertEqual(len(first["emitted_events"]), 1)
        self.assertEqual(second["emitted_events"], [])

        self.db.execute("UPDATE finding_notification_outbox SET status='delivered' WHERE event_id=?", (event_id,))
        resolved = self._snapshot("2026-09-14T00:12:00Z")
        self.assertEqual({e["transition"] for e in resolved["emitted_events"]}, {"resolved"})
        self.db.execute(
            "UPDATE finding_notification_outbox SET status='queued',next_attempt_at=?,created_at=?,updated_at=? WHERE event_id=?",
            ("2026-09-14T00:00:00Z", "2026-09-14T00:00:00Z", "2026-09-14T00:13:00Z", event_id),
        )
        reopened = self._snapshot("2026-09-14T00:13:00Z")
        self.assertEqual(reopened["emitted_events"], [])
        row = next(row for row in reopened["open_breaches"] if row["breach_key"] == "finding:pending_age_seconds")
        self.assertEqual(row["occurrences"], 2)
        transitions = [row["transition"] for row in list_notification_delivery_slo_events(self.db)]
        self.assertEqual(transitions.count("opened"), 1)
        self.assertEqual(transitions.count("reopened"), 0)

    def test_supervisor_stale_heartbeat_is_critical_only_when_supervision_is_relevant(self) -> None:
        configure_notification_delivery_slo(
            self.db,
            heartbeat_warning_seconds=60,
            heartbeat_critical_seconds=120,
            backlog_warning=100,
            backlog_critical=200,
            pending_warning_seconds=7200,
            pending_critical_seconds=21600,
            failure_warning_count=50,
            failure_critical_count=100,
        )
        self._finding_event("slo-heartbeat", "2026-09-14T00:09:30Z")
        self.db.execute(
            "UPDATE notification_supervisor_state SET heartbeat_at=?,last_status='success' WHERE singleton=1",
            ("2026-09-14T00:00:00Z",),
        )
        status = self._snapshot("2026-09-14T00:10:00Z")
        row = next(row for row in status["open_breaches"] if row["breach_key"] == "supervisor:heartbeat_age_seconds")
        self.assertEqual(row["severity"], "critical")
        self.assertEqual(row["value"], 600)

        self.db.execute("UPDATE finding_notification_outbox SET status='delivered'")
        clear = self._snapshot("2026-09-14T00:11:00Z")
        self.assertFalse(any(row["breach_key"] == "supervisor:heartbeat_age_seconds" for row in clear["open_breaches"]))

    def test_consecutive_worker_failures_warn_then_escalate(self) -> None:
        configure_notification_delivery_slo(
            self.db,
            failure_warning_count=2,
            failure_critical_count=3,
            cooldown_seconds=0,
            backlog_warning=100,
            backlog_critical=200,
            pending_warning_seconds=7200,
            pending_critical_seconds=21600,
        )
        for index in (1, 2):
            stamp = f"2026-09-14T00:0{index}:00Z"
            self.db.execute(
                "INSERT INTO finding_notification_worker_runs("
                "worker_run_id,trigger,status,error,started_at,finished_at"
                ") VALUES(?,?,'failed','offline',?,?)",
                (f"FWR-{index}", "test", stamp, stamp),
            )
        warning = self._snapshot("2026-09-14T00:03:00Z")
        row = next(row for row in warning["open_breaches"] if row["breach_key"] == "finding:consecutive_failures")
        self.assertEqual(row["severity"], "warning")

        self.db.execute(
            "INSERT INTO finding_notification_worker_runs("
            "worker_run_id,trigger,status,error,started_at,finished_at"
            ") VALUES('FWR-3','test','failed','offline','2026-09-14T00:04:00Z','2026-09-14T00:04:00Z')"
        )
        critical = self._snapshot("2026-09-14T00:05:00Z")
        row = next(row for row in critical["open_breaches"] if row["breach_key"] == "finding:consecutive_failures")
        self.assertEqual(row["severity"], "critical")
        self.assertIn("escalated", {event["transition"] for event in critical["emitted_events"]})

    def test_configuration_never_allows_critical_below_warning(self) -> None:
        policy = configure_notification_delivery_slo(
            self.db,
            backlog_warning=100,
            backlog_critical=10,
            pending_warning_seconds=500,
            pending_critical_seconds=100,
        )
        self.assertEqual(policy["backlog_critical"], 100)
        self.assertEqual(policy["pending_critical_seconds"], 500)


if __name__ == "__main__":
    unittest.main()
