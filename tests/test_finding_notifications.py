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
from finding_notifications import (
    ensure_finding_notification_schema,
    install_finding_notification_pipeline,
    process_finding_notifications,
)
from successful_snapshot import SuccessfulSnapshotDatabase


class FindingNotificationTests(unittest.TestCase):
    TARGET = "example.test"
    FP = "candidate-fingerprint-1"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.config = Config(self.paths)
        self.db = SuccessfulSnapshotDatabase(self.paths.db)
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

    def test_baseline_allows_new_potential_finding_notification(self) -> None:
        self._analysis("AN-1", "RUN-1")
        self._candidate("AN-1", "RUN-1", "C-1")

        result = process_finding_notifications(
            self._ctx("RUN-1"),
            {"analysis_id": "AN-1", "status": "success"},
            baseline=True,
        )

        self.assertEqual(result["queued"], 1)
        self.assertTrue(result["baseline"])
        self.assertFalse(result["baseline_suppresses_findings"])
        self.assertEqual(result["transitions"][0]["transition"], "new")
        row = self.db.one("SELECT * FROM notification_events WHERE event_type='potential_finding'")
        self.assertIsNotNone(row)
        self.assertEqual(str(row["mode"]), "immediate")
        self.assertEqual(str(row["status"]), "queued")

    def test_same_finding_on_later_analysis_is_exactly_once(self) -> None:
        self._analysis("AN-1", "RUN-1")
        self._candidate("AN-1", "RUN-1", "C-1")
        first = process_finding_notifications(
            self._ctx("RUN-1"), {"analysis_id": "AN-1"}
        )
        self.assertEqual(first["queued"], 1)

        self._analysis("AN-2", "RUN-2")
        self._candidate("AN-2", "RUN-2", "C-2")
        second = process_finding_notifications(
            self._ctx("RUN-2"), {"analysis_id": "AN-2"}
        )

        self.assertEqual(second["queued"], 0)
        self.assertEqual(second["skipped_unchanged"], 1)
        count = self.db.one(
            "SELECT COUNT(*) count FROM notification_events WHERE event_type='potential_finding'"
        )
        self.assertEqual(int(count["count"]), 1)

    def test_material_confidence_increase_creates_second_transition(self) -> None:
        self._analysis("AN-1", "RUN-1")
        self._candidate("AN-1", "RUN-1", "C-1", likelihood=62, investigation=65)
        process_finding_notifications(self._ctx("RUN-1"), {"analysis_id": "AN-1"})

        self._analysis("AN-2", "RUN-2")
        self._candidate("AN-2", "RUN-2", "C-2", likelihood=74, investigation=77)
        result = process_finding_notifications(
            self._ctx("RUN-2"), {"analysis_id": "AN-2"}
        )

        self.assertEqual(result["queued"], 1)
        self.assertEqual(result["transitions"][0]["transition"], "confidence_increased")
        rows = self.db.all(
            "SELECT transition_type FROM finding_notification_transitions "
            "WHERE target=? AND candidate_fingerprint=? ORDER BY created_at,rowid",
            (self.TARGET, self.FP),
        )
        self.assertEqual([str(row["transition_type"]) for row in rows], ["new", "confidence_increased"])

    def test_ineligible_possible_candidate_notifies_when_promoted(self) -> None:
        self._analysis("AN-1", "RUN-1")
        self._candidate(
            "AN-1", "RUN-1", "C-1", state="possible", likelihood=45, evidence=35, investigation=52
        )
        first = process_finding_notifications(
            self._ctx("RUN-1"), {"analysis_id": "AN-1"}
        )
        self.assertEqual(first["queued"], 0)
        self.assertEqual(first["skipped_ineligible"], 1)

        self._analysis("AN-2", "RUN-2")
        self._candidate(
            "AN-2", "RUN-2", "C-2", state="plausible", likelihood=62, evidence=50, investigation=66
        )
        second = process_finding_notifications(
            self._ctx("RUN-2"), {"analysis_id": "AN-2"}
        )
        self.assertEqual(second["queued"], 1)
        self.assertEqual(second["transitions"][0]["transition"], "promoted")

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
            self.assertEqual(result["skipped_unchanged"], 1)
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
