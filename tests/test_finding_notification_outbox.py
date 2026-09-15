from __future__ import annotations

import json
import sys
import tempfile
import unittest
from unittest.mock import patch
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

    def test_immediate_cannot_enable_finding_delivery(self):
        self._set_policy('immediate')
        run_id, analysis_id, candidate_id = self._analysis_candidate('immediate')
        result = process_finding_notifications(self._ctx(run_id), {"analysis_id": analysis_id})
        self.assertEqual(result["queued"], 0)
        self.assertEqual(result["transitions"], [])
        with patch("finding_notification_outbox.deliver_notification_message") as send:
            delivered = deliver_finding_notification_outbox(config=self.config, logger=self.logger, db=self.db, mode='immediate')
            send.assert_not_called()
        self.assertEqual(delivered["delivered"], 0)
        self.assertIsNotNone(self.db.one("SELECT candidate_id FROM bug_candidates WHERE candidate_id=?", (candidate_id,)))


    def test_digest_cannot_enable_finding_delivery(self):
        self._set_policy('digest')
        run_id, analysis_id, candidate_id = self._analysis_candidate('digest')
        result = process_finding_notifications(self._ctx(run_id), {"analysis_id": analysis_id})
        self.assertEqual(result["queued"], 0)
        self.assertEqual(result["transitions"], [])
        with patch("finding_notification_outbox.deliver_notification_message") as send:
            delivered = deliver_finding_notification_outbox(config=self.config, logger=self.logger, db=self.db, mode='digest')
            send.assert_not_called()
        self.assertEqual(delivered["delivered"], 0)
        self.assertIsNotNone(self.db.one("SELECT candidate_id FROM bug_candidates WHERE candidate_id=?", (candidate_id,)))


    def test_system_warning_cannot_enable_finding_delivery(self):
        self._set_policy('system_warning')
        run_id, analysis_id, candidate_id = self._analysis_candidate('system_warning')
        result = process_finding_notifications(self._ctx(run_id), {"analysis_id": analysis_id})
        self.assertEqual(result["queued"], 0)
        self.assertEqual(result["transitions"], [])
        with patch("finding_notification_outbox.deliver_notification_message") as send:
            delivered = deliver_finding_notification_outbox(config=self.config, logger=self.logger, db=self.db, mode='system_warning')
            send.assert_not_called()
        self.assertEqual(delivered["delivered"], 0)
        self.assertIsNotNone(self.db.one("SELECT candidate_id FROM bug_candidates WHERE candidate_id=?", (candidate_id,)))


    def test_silent_cannot_enable_finding_delivery(self):
        self._set_policy('silent')
        run_id, analysis_id, candidate_id = self._analysis_candidate('silent')
        result = process_finding_notifications(self._ctx(run_id), {"analysis_id": analysis_id})
        self.assertEqual(result["queued"], 0)
        self.assertEqual(result["transitions"], [])
        with patch("finding_notification_outbox.deliver_notification_message") as send:
            delivered = deliver_finding_notification_outbox(config=self.config, logger=self.logger, db=self.db, mode='silent')
            send.assert_not_called()
        self.assertEqual(delivered["delivered"], 0)
        self.assertIsNotNone(self.db.one("SELECT candidate_id FROM bug_candidates WHERE candidate_id=?", (candidate_id,)))


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
