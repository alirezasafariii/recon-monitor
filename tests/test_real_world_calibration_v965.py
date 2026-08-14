from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from real_world_calibration import (
    build_real_world_calibration_report,
    deterministic_holdout_split,
    extended_confusion_metrics,
    mine_shadow_feedback,
)
from recon_monitor import build_parser, real_world_calibration_cli_payload


GOOD_QUALITY = {
    "reliability": 0.95,
    "specificity": 0.90,
    "directness": 0.95,
    "freshness": 0.90,
    "independence": 0.90,
    "reproducibility": 0.85,
    "uncertainty": 0.10,
}

LOW_QUALITY = {
    "reliability": 0.25,
    "specificity": 0.25,
    "directness": 0.20,
    "freshness": 0.30,
    "independence": 0.20,
    "reproducibility": 0.25,
    "uncertainty": 0.70,
}


def verified_record(
    index: int,
    *,
    label: bool,
    score: int,
    family: str = "broken_object_authorization",
    origin: str | None = None,
    snapshot: str | None = None,
    reviewer: str | None = None,
    quality: dict | None = None,
    signals: list[str] | None = None,
    contradictions: list[str] | None = None,
    provenance: str = "human_verified_replay",
) -> dict:
    return {
        "id": f"verified-{index}",
        "family": family,
        "label": label,
        "decision_readiness_score": score,
        "bug_proximity_score": score,
        "target_evidence_confidence": score,
        "signals": list(signals or ["object_identifier", "object_operation"]),
        "contradictions": list(contradictions or []),
        "provenance": provenance,
        "human_verified": True,
        "label_source": "analyst_case_review",
        "reviewer_id": reviewer or f"reviewer-{index % 3}",
        "reviewed_at": f"2026-08-14T{index % 24:02d}:00:00Z",
        "case_origin_id": origin or f"case-origin-{index}",
        "evidence_snapshot_id": snapshot or f"snapshot-{index}",
        "evidence_quality": dict(quality or GOOD_QUALITY),
    }


class RealWorldCalibrationV965Tests(unittest.TestCase):
    def test_empty_corpus_fails_closed_and_never_activates(self):
        report = build_real_world_calibration_report([])
        self.assertEqual(report["status"], "shadow_only_collect_more_verified_data")
        self.assertEqual(report["activation"], "shadow_only")
        self.assertFalse(report["automatic_activation"])
        self.assertFalse(report["deployment_review"]["ready"])
        self.assertEqual(report["corpus_health"]["trusted_evaluation_records"], 0)
        self.assertEqual(report["global_evaluation"]["holdout_support"], 0)
        self.assertTrue(report["safety"]["production_activation_is_never_automatic"])
        self.assertTrue(report["safety"]["holdout_never_selects_threshold"])

    def test_split_is_label_blind_order_stable_and_keeps_case_origin_together(self):
        rows = [
            verified_record(1, label=True, score=80, origin="same-origin", snapshot="same-1"),
            verified_record(2, label=False, score=30, origin="same-origin", snapshot="same-2"),
        ]
        rows.extend(
            verified_record(i, label=i % 2 == 0, score=80 if i % 2 == 0 else 25)
            for i in range(3, 15)
        )
        first = deterministic_holdout_split(rows, holdout_percent=30)
        second = deterministic_holdout_split(list(reversed(rows)), holdout_percent=30)

        first_train = {_row["case_origin_id"] for _row in first["train"]}
        first_holdout = {_row["case_origin_id"] for _row in first["holdout"]}
        second_train = {_row["case_origin_id"] for _row in second["train"]}
        second_holdout = {_row["case_origin_id"] for _row in second["holdout"]}
        self.assertEqual(first_train, second_train)
        self.assertEqual(first_holdout, second_holdout)
        self.assertFalse(first_train & first_holdout)
        self.assertEqual(first["origin_leakage_count"], 0)
        self.assertTrue(("same-origin" in first_train) ^ ("same-origin" in first_holdout))

        flipped = [dict(row, label=not bool(row["label"])) for row in rows]
        third = deterministic_holdout_split(flipped, holdout_percent=30)
        self.assertEqual(first_train, {_row["case_origin_id"] for _row in third["train"]})
        self.assertEqual(first_holdout, {_row["case_origin_id"] for _row in third["holdout"]})
        self.assertTrue(first["safety"]["partition_is_label_blind"])

    def test_low_quality_human_labels_are_accepted_but_excluded_from_evaluation(self):
        rows = [
            verified_record(1, label=True, score=90, quality=GOOD_QUALITY),
            verified_record(2, label=False, score=10, quality=LOW_QUALITY),
            verified_record(3, label=False, score=15, quality=GOOD_QUALITY),
        ]
        split = deterministic_holdout_split(rows, min_evidence_quality=60, holdout_percent=30)
        self.assertEqual(split["accepted_count"], 3)
        self.assertEqual(split["quality_excluded_count"], 1)
        self.assertEqual(split["evaluation_eligible_count"], 2)
        self.assertEqual(split["quality_excluded"][0]["id"], "verified-2")
        self.assertLess(split["quality_excluded"][0]["evidence_quality_score"], 60)

    def test_untrusted_synthetic_provenance_cannot_enter_real_world_evaluation(self):
        rows = [
            verified_record(1, label=True, score=90),
            verified_record(2, label=False, score=10, provenance="golden_seed"),
        ]
        split = deterministic_holdout_split(rows)
        self.assertEqual(split["accepted_count"], 1)
        self.assertEqual(split["rejected_count"], 1)
        self.assertIn("untrusted_provenance", split["rejected"][0]["errors"])

    def test_extended_metrics_include_false_negative_and_balanced_accuracy(self):
        rows = [
            {"decision_readiness_score": 90, "label": True},
            {"decision_readiness_score": 80, "label": False},
            {"decision_readiness_score": 20, "label": True},
            {"decision_readiness_score": 10, "label": False},
        ]
        metrics = extended_confusion_metrics(rows, threshold=70)
        self.assertEqual(metrics["tp"], 1)
        self.assertEqual(metrics["fp"], 1)
        self.assertEqual(metrics["tn"], 1)
        self.assertEqual(metrics["fn"], 1)
        self.assertEqual(metrics["false_negative_rate"], 0.5)
        self.assertEqual(metrics["negative_predictive_value"], 0.5)
        self.assertEqual(metrics["balanced_accuracy"], 0.5)

    def test_threshold_is_learned_from_train_and_measured_on_holdout(self):
        rows = []
        for index in range(60):
            positive = index % 2 == 0
            rows.append(
                verified_record(
                    index,
                    label=positive,
                    score=65 if positive else 35,
                    reviewer=f"reviewer-{index % 4}",
                )
            )
        report = build_real_world_calibration_report(
            rows,
            holdout_percent=25,
            min_train=10,
            min_holdout=4,
            min_train_positive=3,
            min_train_negative=3,
            min_global_verified=10_000,
        )
        evaluation = report["global_evaluation"]
        self.assertTrue(evaluation["train_ready"])
        self.assertTrue(evaluation["candidate_learned_from_train"])
        self.assertLessEqual(evaluation["candidate_threshold"], 65)
        self.assertGreater(evaluation["holdout_support"], 0)
        self.assertEqual(evaluation["candidate_holdout_metrics"]["fp"], 0)
        self.assertEqual(evaluation["candidate_holdout_metrics"]["fn"], 0)
        self.assertEqual(evaluation["candidate_holdout_metrics"]["precision"], 1.0)
        self.assertEqual(evaluation["candidate_holdout_metrics"]["recall"], 1.0)

    def test_shadow_feedback_mines_repeated_fp_fn_and_contradiction_patterns_without_applying_them(self):
        rows = [
            {
                "family": "broken_object_authorization",
                "label": False,
                "decision_readiness_score": 85,
                "signals": ["weak_surface_signal"],
                "contradictions": ["cross_context_denied"],
            },
            {
                "family": "broken_object_authorization",
                "label": False,
                "decision_readiness_score": 80,
                "signals": ["weak_surface_signal"],
                "contradictions": ["cross_context_denied"],
            },
            {
                "family": "broken_object_authorization",
                "label": True,
                "decision_readiness_score": 45,
                "signals": ["verified_direct_signal"],
                "contradictions": [],
            },
            {
                "family": "broken_object_authorization",
                "label": True,
                "decision_readiness_score": 50,
                "signals": ["verified_direct_signal"],
                "contradictions": [],
            },
        ]
        feedback = mine_shadow_feedback(rows, threshold=70, min_error_support=2)
        kinds = {item["kind"] for item in feedback["recommendations"]}
        tokens = {item["token"] for item in feedback["recommendations"]}
        self.assertIn("precision_noise_signal_review", kinds)
        self.assertIn("recall_gap_signal_review", kinds)
        self.assertIn("contradiction_suppression_review", kinds)
        self.assertIn("weak_surface_signal", tokens)
        self.assertIn("verified_direct_signal", tokens)
        self.assertIn("cross_context_denied", tokens)
        self.assertTrue(feedback["safety"]["shadow_only"])
        self.assertTrue(feedback["safety"]["recommendations_do_not_edit_weights"])
        self.assertTrue(feedback["safety"]["recommendations_require_human_review"])

    def test_ready_corpus_still_requires_manual_policy_review_and_never_auto_activates(self):
        rows = []
        for index in range(80):
            positive = index % 2 == 0
            rows.append(
                verified_record(
                    index,
                    label=positive,
                    score=85 if positive else 15,
                    reviewer=f"reviewer-{index % 4}",
                )
            )
        report = build_real_world_calibration_report(
            rows,
            holdout_percent=25,
            min_train=10,
            min_holdout=4,
            min_train_positive=3,
            min_train_negative=3,
            min_global_verified=20,
            min_verified_families=1,
            min_reviewers=3,
            min_global_holdout=4,
            min_holdout_precision=0.90,
            min_holdout_recall=0.90,
            max_holdout_fpr=0.05,
        )
        self.assertTrue(report["deployment_review"]["ready"])
        self.assertEqual(report["status"], "ready_for_manual_policy_review")
        self.assertEqual(report["activation"], "shadow_only")
        self.assertFalse(report["automatic_activation"])
        self.assertTrue(report["deployment_review"]["required_manual_policy_change"])
        self.assertTrue(report["safety"]["feedback_cannot_change_admission"])

    def test_cli_accepts_multiple_verified_corpus_files_and_empty_payload_is_safe(self):
        parser = build_parser()
        args = parser.parse_args([
            "analysis",
            "real-world-calibration",
            "--verified-corpus",
            "one.jsonl",
            "--verified-corpus",
            "two.jsonl",
        ])
        self.assertEqual(args.action, "real-world-calibration")
        self.assertEqual(args.verified_corpus, ["one.jsonl", "two.jsonl"])

        payload = real_world_calibration_cli_payload([])
        self.assertEqual(payload["action"], "real-world-calibration")
        self.assertEqual(payload["ingestion"]["accepted_count"], 0)
        self.assertEqual(payload["report"]["activation"], "shadow_only")
        self.assertFalse(payload["report"]["automatic_activation"])
        self.assertTrue(payload["operator_guidance"]["manual_policy_review_required_even_when_ready"])

    def test_cli_ingests_valid_jsonl_record(self):
        row = verified_record(900, label=True, score=88)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "verified.jsonl"
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            payload = real_world_calibration_cli_payload([str(path)])
        self.assertEqual(payload["ingestion"]["source_files"], 1)
        self.assertEqual(payload["ingestion"]["accepted_count"], 1)
        self.assertEqual(payload["ingestion"]["rejected_count"], 0)
        self.assertEqual(payload["report"]["corpus_health"]["trusted_evaluation_records"], 1)
        self.assertTrue(payload["operator_guidance"]["candidate_thresholds_are_learned_from_train_only"])


if __name__ == "__main__":
    unittest.main()
