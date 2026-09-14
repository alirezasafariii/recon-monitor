from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import subprocess

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

# Exercise the production import path. Importing successful_snapshot directly
# before recon_monitor_core is an artificial order that bypasses the runtime
# loader responsible for installing the reliability guards.
import recon_monitor_core
from core import APP_VERSION, AppPaths, Config, Database, Logger, utc_now
from finding_notifications import (
    ensure_finding_notification_schema,
    install_finding_notification_pipeline,
    process_finding_notifications,
)


class FindingNotificationTests(unittest.TestCase):
    TARGET = "example.test"
    FP = "candidate-fingerprint-1"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.config = Config(self.paths)
        self.db = recon_monitor_core.Database(self.paths.db)
        self.logger = Logger(self.paths, verbose=False)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _analysis(self, analysis_id: str, run_id: str) -> None:
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES(?,?,'success',?,?,?,1)",
            (run_id, APP_VERSION, now, now, self.TARGET),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES(?,?,?,'test','test','automatic','success',?,?, '{}')",
            (analysis_id, run_id, self.TARGET, now, now),
        )

    def _candidate(
        self,
        analysis_id: str,
        run_id: str,
        candidate_id: str,
        *,
        state: str = "plausible",
        likelihood: int = 70,
        evidence: int = 60,
        investigation: int = 74,
        support_count: int = 2,
        lifecycle: str = "observed",
        decision: str = "unreviewed",
        fingerprint: str | None = None,
    ) -> None:
        now = utc_now()
        support = [
            {
                "type": f"evidence-{index}",
                "source": f"source-{index}",
                "source_group": f"group-{index}",
                "weight": 15,
                "text": f"evidence {index}",
            }
            for index in range(support_count)
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
                fingerprint or self.FP,
                analysis_id,
                run_id,
                self.TARGET,
                self.TARGET,
                "https://example.test/api/orders/{orderId}",
                "fixture",
                "broken_object_authorization",
                "object_scope",
                "Possible object authorization issue",
                "Stored evidence supports investigation of an authorization boundary.",
                likelihood,
                evidence,
                88,
                investigation,
                state,
                lifecycle,
                json.dumps(support),
                "[]",
                "[]",
                "Review stored evidence with authorized test identities.",
                json.dumps(["test-rule"]),
                "test",
                decision,
                "",
                now,
                now,
                likelihood,
                60,
                65,
                90,
                "[]",
                investigation,
            ),
        )

    def _ctx(self, run_id: str):
        return SimpleNamespace(
            paths=self.paths,
            config=self.config,
            db=self.db,
            logger=self.logger,
            run_id=run_id,
            policy=SimpleNamespace(name=self.TARGET),
        )

    def test_new_promoted_and_stronger_findings_never_notify(self) -> None:
        cases = [("possible", 40), ("plausible", 70), ("strong_candidate", 90), ("confirmed_by_analyst", 100)]
        with patch("finding_notifications.TelegramNotifier") as telegram, patch("reporting._send_notify_cli") as notify:
            for index, (state, score) in enumerate(cases):
                run_id, analysis_id = f"RUN-{index}", f"AN-{index}"
                self._analysis(analysis_id, run_id)
                self._candidate(analysis_id, run_id, f"C-{index}", state=state, likelihood=score, investigation=score)
                result = process_finding_notifications(self._ctx(run_id), {"analysis_id": analysis_id}, baseline=index == 0)
                self.assertEqual(result["queued"], 0)
                self.assertEqual(result["delivery"]["delivered"], 0)
                self.assertTrue(result["baseline_suppresses_findings"])
            telegram.assert_not_called()
            notify.assert_not_called()
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM notification_events")["n"], 0)
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM bug_candidates")["n"], 4)

    def test_baseline_plausible_finding_stays_silent(self) -> None:
        self._analysis("AN-1", "RUN-1")
        self._candidate("AN-1", "RUN-1", "C-1")
        result = process_finding_notifications(self._ctx("RUN-1"), {"analysis_id": "AN-1"}, baseline=True)
        self.assertEqual(result["queued"], 0)
        self.assertEqual(result["skipped_policy"], 1)
        self.assertIsNotNone(self.db.one("SELECT candidate_id FROM bug_candidates WHERE candidate_id='C-1'"))

    def test_existing_immediate_policy_cannot_enable_finding_delivery(self) -> None:
        from finding_notifications import _policy
        from platform_v6 import queue_notification
        now = utc_now()
        self.db.execute("INSERT INTO notification_policies(target,event_type,mode,minimum_score,enabled,created_at,updated_at) VALUES(?,?,'immediate',0,1,?,?)", (self.TARGET, 'potential_finding', now, now))
        self.assertEqual(_policy(self.db, self.TARGET)[0], 'silent')
        for event_type in ('potential_finding', 'high_value_case', 'nuclei_finding'):
            result = queue_notification(self.db, {'event_type': event_type, 'title': 'Finding', 'score': 100}, target=self.TARGET)
            self.assertEqual(result['mode'], 'silent')

    def test_legacy_queued_findings_cannot_be_delivered(self) -> None:
        from finding_notifications import _deliver_pending
        from platform_v6 import queue_notification, deliver_notifications
        from core import json_dumps
        self._analysis('AN-1', 'RUN-1')
        queued = queue_notification(self.db, {'event_type': 'potential_finding', 'score': 100, 'title': 'Finding'}, target=self.TARGET)
        self.db.execute("UPDATE notification_events SET mode='immediate' WHERE event_id=?", (queued['event_id'],))
        # Even legacy finding rows at the front of the queue must not block
        # delivery of legitimate operational messages after the LIMIT.
        queue_notification(self.db, {'event_type': 'run_failure', 'title': 'run failure', 'score': 90}, target=self.TARGET)
        self.db.execute("UPDATE notification_events SET mode='immediate' WHERE event_type='run_failure'")
        with patch('finding_notifications.TelegramNotifier') as telegram, patch('reporting._send_notify_cli') as notify:
            self.assertEqual(_deliver_pending(self._ctx('RUN-1'))['delivered'], 0)
            telegram.assert_not_called(); notify.assert_not_called()
        preview = deliver_notifications(self.paths, self.config, self.db, mode='immediate', limit=1, dry_run=True)
        self.assertEqual(preview['queued'], 1)
        self.assertNotIn('Finding', preview['message'])

    def test_nuclei_events_are_not_change_alerts_even_from_legacy_files(self) -> None:
        import stages
        from reporting import create_alerts_and_notify, send_daily_digest
        from core import TargetPolicy, json_dumps
        self._analysis('AN-1', 'RUN-1')
        ctx = self._ctx('RUN-1')
        ctx.policy = TargetPolicy.from_dict({'name': self.TARGET, 'roots': [self.TARGET], 'alert': {'minimum_score': 0}})
        ctx.events_path = self.paths.output / 'events.jsonl'
        stages.emit_event(ctx, 'nuclei_finding', self.TARGET, 'Finding', {})
        self.assertFalse(ctx.events_path.exists())
        event = {'dedup_key': 'legacy-finding', 'category': 'nuclei_finding', 'risk_score': 100, 'severity': 'CRITICAL', 'title': 'Finding', 'item': self.TARGET, 'details': {}}
        ctx.events_path.write_text(json_dumps(event) + '\n')
        self.assertEqual(create_alerts_and_notify(ctx, False)['new_alerts'], 0)
        self.db.upsert_alert(self.TARGET, 'legacy', 'nuclei_finding', 'CRITICAL', 100, 'Finding', self.TARGET, {}, 'RUN-1')
        with patch('reporting._send_notify_cli') as notify:
            self.assertFalse(send_daily_digest(self.paths, self.config, self.db, self.logger)['sent'])
            notify.assert_not_called()

    def test_unchanged_endpoint_is_not_a_second_scan_change(self) -> None:
        from core import TargetPolicy, Progress
        from stages import StageContext, stage_endpoint_validation
        self._analysis('AN-1', 'RUN-1')
        self._analysis('AN-2', 'RUN-2')
        endpoint = 'https://example.test/api/items'
        policy = TargetPolicy.from_dict({'name': self.TARGET, 'roots': [self.TARGET], 'modules': {'endpoint_validation': True}})
        self.db.upsert_endpoint_intelligence(self.TARGET, endpoint, 'url', {}, 'test', 'RUN-1')
        result = {'endpoint': endpoint, 'resolved_url': endpoint, 'method': 'HEAD', 'status_code': 200, 'content_type': 'application/json', 'reachable': True}
        contexts = []
        with patch('stages._safe_validate_endpoint', return_value=result):
            for run in ('RUN-1', 'RUN-2'):
                ctx = StageContext(self.paths, self.config, policy, self.db, self.logger, None, Progress(False), run, self.paths.output / run, False)
                stage_endpoint_validation(ctx)
                contexts.append(ctx)
        self.assertTrue(contexts[0].events_path.exists())
        self.assertFalse(contexts[1].events_path.exists())

    def test_guard_installation_is_independent_of_import_order(self) -> None:
        for imports in ('import successful_snapshot; import recon_monitor_core', 'import recon_monitor_core; import successful_snapshot'):
            code = "import sys; sys.path.insert(0, 'app'); " + imports + "; import stages; assert stages._STABLE_CONFIRMATION_INSTALLED; assert recon_monitor_core.Orchestrator.run._strict_lifecycle_status"
            result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_upgrade_bootstrap_does_not_realert_existing_candidate(self) -> None:
        temp = tempfile.TemporaryDirectory()
        try:
            paths = AppPaths.from_root(Path(temp.name))
            paths.ensure()
            paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
            db = Database(paths.db)
            now = utc_now()
            db.execute(
                "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
                "VALUES('RUN-OLD',?,'success',?,?,?,1)",
                (APP_VERSION, now, now, self.TARGET),
            )
            db.execute(
                "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
                "VALUES('AN-OLD','RUN-OLD',?,'test','test','automatic','success',?,?, '{}')",
                (self.TARGET, now, now),
            )
            db.execute(
                "INSERT INTO bug_candidates("
                "candidate_id,candidate_fingerprint,analysis_id,source_run_id,target,asset,endpoint,source_ref,bug_family,bug_variant,"
                "title,summary,likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,"
                "supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,safe_next_action,rule_ids_json,rule_version,"
                "analyst_decision,analyst_note,created_at,updated_at,calibrated_likelihood,investigation_value"
                ") VALUES('C-OLD',?,'AN-OLD','RUN-OLD',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    self.FP,
                    self.TARGET,
                    self.TARGET,
                    "https://example.test/api/orders/{orderId}",
                    "fixture",
                    "broken_object_authorization",
                    "object_scope",
                    "Existing candidate",
                    "Existing candidate before upgrade",
                    70,
                    60,
                    88,
                    74,
                    "plausible",
                    "[]",
                    "[]",
                    "[]",
                    "Review",
                    "[]",
                    "test",
                    "unreviewed",
                    "",
                    now,
                    now,
                    70,
                    74,
                ),
            )
            ensure_finding_notification_schema(db)
            state = db.one(
                "SELECT reference_reason FROM finding_notification_state WHERE target=? AND candidate_fingerprint=?",
                (self.TARGET, self.FP),
            )
            self.assertEqual(str(state["reference_reason"]), "bootstrap")
            ctx = SimpleNamespace(
                paths=paths,
                config=Config(paths),
                db=db,
                logger=Logger(paths, verbose=False),
                run_id="RUN-OLD",
                policy=SimpleNamespace(name=self.TARGET),
            )
            result = process_finding_notifications(ctx, {"analysis_id": "AN-OLD"})
            self.assertEqual(result["queued"], 0)
            self.assertEqual(result["skipped_policy"], 1)
            count = db.one("SELECT COUNT(*) count FROM notification_events WHERE event_type='potential_finding'")
            self.assertEqual(int(count["count"]), 0)
            db.close()
        finally:
            temp.cleanup()

    def test_runtime_report_hook_installs(self) -> None:
        import reporting

        install_finding_notification_pipeline()
        self.assertTrue(getattr(reporting, "_FINDING_NOTIFICATION_PIPELINE_INSTALLED", False))
        self.assertEqual(reporting.stage_report.__module__, "finding_notifications")


if __name__ == "__main__":
    unittest.main()
