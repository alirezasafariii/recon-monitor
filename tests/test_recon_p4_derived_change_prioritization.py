from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import APP_VERSION, AppPaths, TargetPolicy, utc_now, write_jsonl
from derived_change_advisory import (
    EXPECTED_COLLECTION_STAGES,
    derived_change_advisory_context,
)
from hypothesis_admission import assess_admission, record_hypothesis
from meta_ranker import rank_bug_proximity
from successful_snapshot import SuccessfulSnapshotDatabase


class ReconP4DerivedChangePrioritizationTests(unittest.TestCase):
    TARGET = "example.test"
    RUN = "RUN-P4"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.from_root(Path(self.temp.name))
        self.paths.ensure()
        self.db = SuccessfulSnapshotDatabase(self.paths.db)
        self.policy = TargetPolicy.from_dict(
            {"name": self.TARGET, "roots": [self.TARGET]}
        )
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,target_selector,target_count) "
            "VALUES(?,?,?,?,?,1)",
            (self.RUN, APP_VERSION, "running", now, self.TARGET),
        )
        self.run_dir = self.paths.output / self.TARGET / "runs" / self.RUN
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "changes").mkdir(parents=True, exist_ok=True)
        self.db.create_run_target(self.RUN, self.policy, self.run_dir, False)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _finish_collection(self, *, failed_stage: str = "") -> None:
        for stage in EXPECTED_COLLECTION_STAGES:
            self.db.stage_begin(self.RUN, self.TARGET, stage, 1)
            status = "failed" if stage == failed_stage else "success"
            self.db.stage_finish(
                self.RUN,
                self.TARGET,
                stage,
                status,
                metrics={"fixture": True},
                exit_code=1 if status == "failed" else 0,
                error="fixture failure" if status == "failed" else None,
            )

    def _write_change(
        self,
        *,
        item: str = "src/admin/orders.ts",
        js_url: str = "https://example.test/static/app.js",
        signal_type: str = "source_map_source_changed",
    ) -> None:
        state_type, change = signal_type.rsplit("_", 1)
        write_jsonl(
            self.run_dir / "changes" / "recon-derived-differentials.jsonl",
            [
                {
                    "signal_type": signal_type,
                    "state_type": state_type,
                    "change": change,
                    "item_key": "map:orders",
                    "item": item,
                    "baseline_run_id": "RUN-PREV",
                    "run_id": self.RUN,
                    "target": self.TARGET,
                    "before": {
                        "js_url": js_url,
                        "source_name": item,
                        "semantic_hash": "sem-old",
                        "content_hash": "raw-old",
                    },
                    "after": {
                        "js_url": js_url,
                        "source_name": item,
                        "semantic_hash": "sem-new",
                        "content_hash": "raw-new",
                    },
                }
            ],
        )

    def test_collection_incomplete_fails_closed(self) -> None:
        self._finish_collection(failed_stage="fingerprint")
        self._write_change()
        context = derived_change_advisory_context(
            self.db,
            source_run_id=self.RUN,
            target=self.TARGET,
            family="broken_object_authorization",
            endpoint="/api/admin/orders/{id}",
            source_ref="https://example.test/static/app.js",
        )
        self.assertFalse(context["eligible"])
        self.assertFalse(context["available"])
        self.assertIsNone(context["score"])
        self.assertEqual(context["family_scores"], {})
        self.assertIn("fingerprint", context["incomplete_collection_stages"])

    def test_matching_source_change_produces_advisory_score_only(self) -> None:
        self._finish_collection()
        self._write_change()
        context = derived_change_advisory_context(
            self.db,
            source_run_id=self.RUN,
            target=self.TARGET,
            family="broken_object_authorization",
            endpoint="/api/admin/orders/{id}",
            source_ref="https://example.test/static/app.js",
        )
        self.assertTrue(context["eligible"])
        self.assertTrue(context["available"])
        self.assertGreaterEqual(int(context["score"]), 90)
        self.assertEqual(
            context["family_scores"]["broken_object_authorization"],
            context["score"],
        )
        self.assertGreaterEqual(context["matched_signal_count"], 1)
        self.assertFalse(context["safety"]["counts_as_target_evidence"])
        self.assertFalse(context["safety"]["can_satisfy_admission"])
        self.assertFalse(context["safety"]["network_requests"])

    def test_unrelated_change_does_not_create_family_prior(self) -> None:
        self._finish_collection()
        self._write_change(
            item="src/admin/users.ts",
            js_url="https://example.test/static/admin.js",
        )
        context = derived_change_advisory_context(
            self.db,
            source_run_id=self.RUN,
            target=self.TARGET,
            family="file_upload",
            endpoint="/media/avatar",
            source_ref="https://example.test/static/profile.js",
            summary="multipart attachment workflow",
        )
        self.assertTrue(context["available"])
        self.assertIsNone(context["score"])
        self.assertEqual(context["family_scores"], {})
        self.assertEqual(context["matched_signal_count"], 0)

    def test_meta_ranker_change_prior_changes_proximity_not_evidence(self) -> None:
        support = [{"type": "object_identifier", "source_group": "semantic_js"}]
        ranking = {
            "family": "broken_object_authorization",
            "label": "BOLA / IDOR",
            "score": 60,
            "matched": {
                "strong": [],
                "medium": ["object_identifier"],
                "weak": [],
                "text": [],
            },
            "contradictions": [],
            "taxonomy": {},
            "tags": [],
        }
        baseline = rank_bug_proximity(support, [], [ranking], [])
        changed = rank_bug_proximity(
            support,
            [],
            [ranking],
            [],
            derived_change_scores={"broken_object_authorization": 100},
        )
        self.assertEqual(
            baseline["primary"]["target_evidence_confidence"],
            changed["primary"]["target_evidence_confidence"],
        )
        self.assertGreater(
            changed["primary"]["bug_proximity_score"],
            baseline["primary"]["bug_proximity_score"],
        )
        self.assertEqual(changed["primary"]["components"]["derived_change"], 100)
        self.assertTrue(changed["safety"]["derived_change_is_advisory_only"])
        self.assertTrue(
            changed["safety"]["derived_change_cannot_change_target_evidence_or_admission"]
        )

        zero = rank_bug_proximity(
            [],
            [],
            [
                {
                    **ranking,
                    "score": 0,
                    "matched": {
                        "strong": [],
                        "medium": [],
                        "weak": [],
                        "text": [],
                    },
                }
            ],
            [],
            derived_change_scores={"broken_object_authorization": 100},
        )
        self.assertEqual(zero["primary"]["target_evidence_confidence"], 0)
        self.assertLessEqual(zero["primary"]["bug_proximity_score"], 35)

    def test_record_hypothesis_persists_change_context_after_admission(self) -> None:
        self._finish_collection()
        self._write_change()
        now = utc_now()
        self.db.execute(
            "INSERT INTO analysis_runs("
            "id,source_run_id,target,engine_version,rule_version,mode,status,"
            "started_at,finished_at,summary_json"
            ") VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "AN-P4",
                self.RUN,
                self.TARGET,
                "fixture",
                "fixture",
                "analysis",
                "success",
                now,
                now,
                "{}",
            ),
        )
        support = [{"type": "object_identifier", "source_group": "semantic_js"}]
        baseline_assessment = assess_admission(
            "broken_object_authorization",
            support,
            [],
        )
        result = record_hypothesis(
            self.db,
            analysis_id="AN-P4",
            source_run_id=self.RUN,
            target=self.TARGET,
            alert_id=None,
            asset=self.TARGET,
            endpoint="/api/admin/orders/{id}",
            source_ref="https://example.test/static/app.js",
            family="broken_object_authorization",
            variant="object-id-surface",
            support=support,
            contradict=[],
            missing=["authorization differential"],
            rule_ids=["fixture"],
            summary="object identifier surfaced by changed admin client code",
        )
        assessment = result["assessment"]
        self.assertEqual(
            bool(assessment["admitted"]),
            bool(baseline_assessment["admitted"]),
        )
        self.assertFalse(assessment["admitted"])
        advisory = assessment["derived_change_advisory"]
        self.assertGreaterEqual(int(advisory["score"]), 90)
        context = assessment["knowledge_context"]
        self.assertEqual(
            context["derived_change_context"]["score"],
            advisory["score"],
        )
        family_ranking = next(
            row
            for row in context["meta_ranker"]["rankings"]
            if row["family"] == "broken_object_authorization"
        )
        baseline_ranking = next(
            row
            for row in baseline_assessment["knowledge_context"]["meta_ranker"]["rankings"]
            if row["family"] == "broken_object_authorization"
        )
        self.assertEqual(
            family_ranking["target_evidence_confidence"],
            baseline_ranking["target_evidence_confidence"],
        )
        self.assertEqual(
            family_ranking["components"]["derived_change"],
            advisory["score"],
        )


if __name__ == "__main__":
    unittest.main()
