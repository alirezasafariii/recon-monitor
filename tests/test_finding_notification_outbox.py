from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import APP_VERSION, AppPaths, Config, Database, Logger, utc_now
from finding_notification_outbox import (
    deliver_finding_notification_outbox,
    requeue_failed_finding_notifications,
)
from finding_notifications import ensure_finding_notification_schema, process_finding_notifications


class FindingNotificationOutboxTests(unittest.TestCase):
    TARGET = "example.test"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.config = Config(self.paths)
        self.db = Database(self.paths.db)
        # Production initializes notification reference/outbox state before a new
        # Candidate can be created. Preserve that ordering in this direct fixture.
        ensure_finding_notification_schema(self.db)
        self.logger = Logger(self.paths, verbose=False)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _ctx(self, run_id: str):
        return SimpleNamespace(
            paths=self.paths,
            config=self.config,
            db=self.db,
            logger=self.logger,
            run_id=run_id,
            policy=SimpleNamespace(name=self.TARGET),
        )

    def _analysis_candidate(
        self,
        tag: str,
        *,
        fingerprint: str | None = None,
        state: str = "plausible",
        score: int = 80,
    ) -> tuple[str, str, str]:
        run_id = f"RUN-OUTBOX-{tag}"
        analysis_id = f"AN-OUTBOX-{tag}"
        candidate_id = f"C-OUTBOX-{tag}"
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES(?,?,'success',?,?,?,1)",
            (run_id, APP_VERSION, now, now, self.TARGET),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES(?,?,?,'outbox-test','outbox-test','automatic','success',?,?, '{}')",
            (analysis_id, run_id, self.TARGET, now, now),
        )
        support = [
            {
                "type": "reviewed_evidence",
                "source": "fixture",
                "source_group": f"fixture:{tag}",
                "weight": 50,
                "text": "Stored fixture evidence.",
            }
        ]
        self.db.execute(
            "INSERT INTO bug_candidates("
            "candidate_id,candidate_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,"
            "bug_family,bug_variant,title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,"
            "candidate_state,lifecycle_state,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,"
            "safe_next_action,rule_ids_json,rule_version,analyst_decision,analyst_note,created_at,updated_at,"
            "calibrated_likelihood,exploitability_confidence,evidence_coverage,novelty_score,unknowns_json,investigation_value"
            ") VALUES(?,?,?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                candidate_id,
                fingerprint or f"fp-{tag}",
                analysis_id,
                run_id,
                self.TARGET,
                self.TARGET,
                f"https://example.test/{tag}",
                "fixture",
                "graphql_data_exposure",
                "fixture",
                "Potential Finding fixture",
                "Outbox delivery fixture.",
                80,
                75,
                80,
                score,
                state,
                "observed",
                json.dumps(support),
                "[]",
                "[]",
                "Review stored evidence.",
                "[]",
                "test",
                "unreviewed",
                "",
                now,
                now,
                80,
                70,
                75,
                80,
                "[]",
                score,
            ),
        )
        return run_id, analysis_id, candidate_id

    def _set_policy(self, mode: str, minimum_score: int = 0) -> None:
        now = utc_now()
        self.db.execute(
            "INSERT INTO notification_policies(target,event_type,mode,minimum_score,enabled,created_at,updated_at) "
            "VALUES(?,?,?, ?,1,?,?) "
            "ON CONFLICT(target,event_type) DO UPDATE SET mode=excluded.mode,minimum_score=excluded.minimum_score,enabled=1,updated_at=excluded.updated_at",
            (self.TARGET, "potential_finding", mode, minimum_score, now, now),
        )

    def _queue(self, tag: str, *, mode: str = "immediate") -> tuple[str, str]:
        self._set_policy(mode)
        run_id, analysis_id, candidate_id = self._analysis_candidate(tag)
        result = process_finding_notifications(
            self._ctx(run_id), {"analysis_id": analysis_id, "status": "success"}
        )
        self.assertEqual(result["queued"], 1)
        self.assertTrue(result["delivery"]["deferred"])
        self.assertEqual(result["delivery"]["delivered"], 0)
        event_id = str(result["transitions"][0]["event_id"])
        return event_id, candidate_id

    @staticmethod
    def _success_transport(config, logger, message: str):
        return {"delivered": True, "channel": "fixture", "channels": ["fixture"], "error": ""}

    @staticmethod
    def _failure_transport(config, logger, message: str):
        return {"delivered": False, "channel": "fixture", "channels": [], "error": "transport_down"}

    def test_queue_is_durable_and_worker_delivers_exactly_once(self) -> None:
        event_id, _candidate_id = self._queue("success")
        event = self.db.one("SELECT status FROM notification_events WHERE event_id=?", (event_id,))
        outbox = self.db.one("SELECT status,attempt_count FROM finding_notification_outbox WHERE event_id=?", (event_id,))
        deliveries = self.db.one("SELECT COUNT(*) AS n FROM notification_deliveries WHERE event_id=?", (event_id,))
        self.assertEqual(str(event["status"]), "queued")
        self.assertEqual(str(outbox["status"]), "queued")
        self.assertEqual(int(outbox["attempt_count"]), 0)
        self.assertEqual(int(deliveries["n"]), 0)

        first = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            target=self.TARGET,
            transport=self._success_transport,
            now="2099-01-01T00:00:00Z",
        )
        self.assertEqual(first["delivered"], 1)
        second = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            target=self.TARGET,
            transport=self._success_transport,
            now="2099-01-01T00:10:00Z",
        )
        self.assertEqual(second["due"], 0)
        event = self.db.one("SELECT status FROM notification_events WHERE event_id=?", (event_id,))
        outbox = self.db.one("SELECT status,attempt_count FROM finding_notification_outbox WHERE event_id=?", (event_id,))
        deliveries = self.db.one("SELECT COUNT(*) AS n FROM notification_deliveries WHERE event_id=?", (event_id,))
        self.assertEqual(str(event["status"]), "delivered")
        self.assertEqual(str(outbox["status"]), "delivered")
        self.assertEqual(int(outbox["attempt_count"]), 1)
        self.assertEqual(int(deliveries["n"]), 1)

    def test_stale_worker_cannot_finalize_after_lease_is_replaced(self) -> None:
        event_id, _candidate_id = self._queue("stale-lease")

        def replace_lease_then_succeed(config, logger, message: str):
            self.db.execute(
                "UPDATE finding_notification_outbox "
                "SET lease_id='FNW-replacement',lease_expires_at='2099-01-01T00:10:00Z' "
                "WHERE event_id=? AND status='delivering'",
                (event_id,),
            )
            return {
                "delivered": True,
                "channel": "fixture",
                "channels": ["fixture"],
                "error": "",
            }

        result = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            target=self.TARGET,
            transport=replace_lease_then_succeed,
            now="2099-01-01T00:00:00Z",
        )

        self.assertEqual(result["attempted"], 1)
        self.assertEqual(result["delivered"], 0)
        self.assertEqual(result["retry_pending"], 0)
        self.assertEqual(result["failed"], 0)

        outbox = self.db.one(
            "SELECT status,attempt_count,lease_id FROM finding_notification_outbox WHERE event_id=?",
            (event_id,),
        )
        event = self.db.one(
            "SELECT status,delivered_at FROM notification_events WHERE event_id=?",
            (event_id,),
        )
        deliveries = self.db.one(
            "SELECT COUNT(*) AS n FROM notification_deliveries WHERE event_id=?",
            (event_id,),
        )
        self.assertEqual(str(outbox["status"]), "delivering")
        self.assertEqual(int(outbox["attempt_count"]), 0)
        self.assertEqual(str(outbox["lease_id"]), "FNW-replacement")
        self.assertEqual(str(event["status"]), "queued")
        self.assertIsNone(event["delivered_at"])
        self.assertEqual(int(deliveries["n"]), 0)

    def test_failure_uses_backoff_then_retry_without_candidate_rollback(self) -> None:
        event_id, candidate_id = self._queue("retry")
        first = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            transport=self._failure_transport,
            now="2099-01-01T00:00:00Z",
        )
        self.assertEqual(first["retry_pending"], 1)
        outbox = self.db.one(
            "SELECT status,attempt_count,next_attempt_at,last_error FROM finding_notification_outbox WHERE event_id=?",
            (event_id,),
        )
        self.assertEqual(str(outbox["status"]), "retry_pending")
        self.assertEqual(int(outbox["attempt_count"]), 1)
        self.assertEqual(str(outbox["next_attempt_at"]), "2099-01-01T00:01:00Z")
        self.assertEqual(str(outbox["last_error"]), "transport_down")
        event = self.db.one("SELECT status FROM notification_events WHERE event_id=?", (event_id,))
        candidate = self.db.one("SELECT candidate_id FROM bug_candidates WHERE candidate_id=?", (candidate_id,))
        self.assertEqual(str(event["status"]), "queued")
        self.assertIsNotNone(candidate)

        too_soon = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            transport=self._success_transport,
            now="2099-01-01T00:00:30Z",
        )
        self.assertEqual(too_soon["due"], 0)
        retried = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            transport=self._success_transport,
            now="2099-01-01T00:01:00Z",
        )
        self.assertEqual(retried["delivered"], 1)
        outbox = self.db.one("SELECT status,attempt_count FROM finding_notification_outbox WHERE event_id=?", (event_id,))
        deliveries = self.db.all(
            "SELECT status FROM notification_deliveries WHERE event_id=? ORDER BY id",
            (event_id,),
        )
        self.assertEqual(str(outbox["status"]), "delivered")
        self.assertEqual(int(outbox["attempt_count"]), 2)
        self.assertEqual([str(row["status"]) for row in deliveries], ["failed", "delivered"])

    def test_terminal_failure_can_be_manually_requeued(self) -> None:
        event_id, _candidate_id = self._queue("terminal")
        self.db.execute(
            "UPDATE finding_notification_outbox SET max_attempts=1 WHERE event_id=?",
            (event_id,),
        )
        failed = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            transport=self._failure_transport,
            now="2099-01-01T00:00:00Z",
        )
        self.assertEqual(failed["failed"], 1)
        event = self.db.one("SELECT status FROM notification_events WHERE event_id=?", (event_id,))
        self.assertEqual(str(event["status"]), "failed")

        self.assertEqual(requeue_failed_finding_notifications(self.db, event_id=event_id), 1)
        delivered = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            transport=self._success_transport,
            now="2099-01-01T00:10:00Z",
        )
        self.assertEqual(delivered["delivered"], 1)
        event = self.db.one("SELECT status FROM notification_events WHERE event_id=?", (event_id,))
        self.assertEqual(str(event["status"]), "delivered")

    def test_digest_and_system_warning_are_worker_modes(self) -> None:
        digest_id, _ = self._queue("digest", mode="digest")
        digest = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            mode="digest",
            transport=self._success_transport,
            now="2099-01-01T00:00:00Z",
        )
        self.assertEqual(digest["delivered"], 1)
        self.assertEqual(str(self.db.one("SELECT status FROM notification_events WHERE event_id=?", (digest_id,))["status"]), "delivered")

        warning_id, _ = self._queue("warning", mode="system_warning")
        warning = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            mode="system_warning",
            transport=self._success_transport,
            now="2099-01-01T00:00:00Z",
        )
        self.assertEqual(warning["delivered"], 1)
        self.assertEqual(str(self.db.one("SELECT status FROM notification_events WHERE event_id=?", (warning_id,))["status"]), "delivered")

    def test_silent_policy_creates_no_event_or_outbox_row(self) -> None:
        self._set_policy("silent")
        run_id, analysis_id, _ = self._analysis_candidate("silent")
        result = process_finding_notifications(self._ctx(run_id), {"analysis_id": analysis_id})
        self.assertEqual(result["queued"], 0)
        self.assertEqual(result["skipped_policy"], 1)
        self.assertEqual(int(self.db.one("SELECT COUNT(*) AS n FROM notification_events")["n"]), 0)
        self.assertEqual(int(self.db.one("SELECT COUNT(*) AS n FROM finding_notification_outbox")["n"]), 0)

    def test_finding_pipeline_has_no_inline_transport_dependency(self) -> None:
        source = (ROOT / "app/finding_notifications.py").read_text(encoding="utf-8")
        self.assertNotIn("TelegramNotifier", source)
        self.assertNotIn("_send_notify_cli", source)
        self.assertNotIn("subprocess.run", source)
        self.assertIn("enqueue_finding_notification_event", source)


if __name__ == "__main__":
    unittest.main()
