from __future__ import annotations

import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import benchmark_report, load_golden_cases, replay_golden_cases
from calibration_engine import build_calibration_profile, calibration_bins, confusion_metrics, select_threshold
from meta_ranker import rank_bug_proximity


class CalibrationBenchmarkV910Tests(unittest.TestCase):
    def test_confusion_metrics_and_threshold_selection_are_deterministic(self):
        records = [
            {"family": "x", "label": True, "score": 92},
            {"family": "x", "label": True, "score": 84},
            {"family": "x", "label": True, "score": 76},
            {"family": "x", "label": False, "score": 62},
            {"family": "x", "label": False, "score": 41},
            {"family": "x", "label": False, "score": 18},
        ]
        metrics = confusion_metrics(records, threshold=70)
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]), (3, 0, 3, 0))
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)
        selected = select_threshold(records)
        self.assertTrue(selected["learned"])
        self.assertEqual(selected["metrics"]["f1"], 1.0)

    def test_calibration_bins_match_reported_boundaries(self):
        records = [
            {"family": "x", "label": False, "score": score}
            for score in range(101)
        ]
        buckets = calibration_bins(records, bins=10)
        self.assertEqual(
            [(bucket["low"], bucket["high"], bucket["support"]) for bucket in buckets],
            [
                (0, 9, 10),
                (10, 19, 10),
                (20, 29, 10),
                (30, 39, 10),
                (40, 49, 10),
                (50, 59, 10),
                (60, 69, 10),
                (70, 79, 10),
                (80, 89, 10),
                (90, 100, 11),
            ],
        )

    def test_family_thresholds_fail_closed_when_family_support_is_too_small(self):
        records = []
        for family in ("a", "b"):
            records.extend([
                {"family": family, "label": True, "score": 90},
                {"family": family, "label": False, "score": 20},
            ])
        profile = build_calibration_profile(records, min_global_cases=4)
        self.assertTrue(profile["global"]["ready"])
        self.assertFalse(profile["families"]["a"]["ready"])
        self.assertFalse(profile["families"]["b"]["ready"])
        self.assertEqual(profile["families"]["a"]["threshold_source"], "global_fallback")
        self.assertTrue(profile["safety"]["shadow_only_by_default"])
        self.assertFalse(profile["safety"]["may_satisfy_admission"])

    def test_meta_ranker_calibration_is_shadow_only_and_cannot_change_evidence(self):
        support = [
            {"type": "object_identifier", "source_group": "schema"},
            {"type": "object_operation", "source_group": "contract"},
            {"type": "authorization_response_differential", "source_group": "behavioral"},
        ]
        ranking = {
            "family": "broken_object_authorization",
            "label": "BOLA / IDOR",
            "score": 92,
            "matched": {
                "strong": ["authorization_response_differential"],
                "medium": ["object_identifier", "object_operation"],
                "weak": [],
                "text": [],
            },
            "contradictions": [],
            "taxonomy": {},
            "tags": [],
        }
        baseline = rank_bug_proximity(support, [], [ranking], [])
        profile = {
            "activation": "shadow_only",
            "global": {"ready": True, "threshold": 88, "diagnostics": {"bins": []}},
            "families": {},
        }
        calibrated = rank_bug_proximity(support, [], [ranking], [], calibration_profile=profile)
        self.assertEqual(
            baseline["primary"]["bug_proximity_score"],
            calibrated["primary"]["bug_proximity_score"],
        )
        self.assertEqual(
            baseline["primary"]["target_evidence_confidence"],
            calibrated["primary"]["target_evidence_confidence"],
        )
        self.assertTrue(calibrated["primary"]["calibration"]["available"])
        self.assertEqual(calibrated["calibration_mode"], "shadow_only")
        self.assertTrue(calibrated["safety"]["calibration_cannot_change_evidence_or_admission"])

    def test_meta_ranker_queries_calibration_with_decision_readiness_score(self):
        support = [{"type": "object_identifier", "source_group": "schema"}]
        ranking = {
            "family": "broken_object_authorization",
            "label": "BOLA / IDOR",
            "score": 91,
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
        captured = []

        def fake_calibration(family, score, profile):
            captured.append((family, int(score)))
            return {"available": False, "raw_score": int(score)}

        readiness = {
            "score": 17,
            "matched_decisive_signals": [],
            "blocking_contradictions": [],
        }
        with patch("meta_ranker.decision_readiness", return_value=readiness):
            with patch("meta_ranker.calibration_for_score", side_effect=fake_calibration):
                result = rank_bug_proximity(
                    support,
                    [],
                    [ranking],
                    [],
                    calibration_profile={"activation": "shadow_only"},
                )

        self.assertEqual(captured, [("broken_object_authorization", 17)])
        self.assertEqual(result["primary"]["decision_readiness_score"], 17)
        self.assertEqual(
            result["primary"]["calibration"]["score_semantics"],
            "decision_readiness_score",
        )

    def test_full_golden_replay_covers_all_74_families_and_148_labeled_records(self):
        cases = load_golden_cases([
            ROOT / "tests" / "fixtures" / "vulnerability_intelligence_golden_v1.json",
            ROOT / "tests" / "fixtures" / "vulnerability_intelligence_phase2_golden_v2.json",
        ])
        self.assertEqual(len(cases), 74)
        records = replay_golden_cases(cases)
        report = benchmark_report(records)
        self.assertEqual(report["coverage"]["families"], 74)
        self.assertEqual(report["coverage"]["records"], 148)
        self.assertEqual(report["coverage"]["positive"], 74)
        self.assertEqual(report["coverage"]["negative"], 74)
        self.assertTrue(report["calibration_profile"]["global"]["ready"])
        self.assertTrue(report["safety"]["offline_only"])
        self.assertFalse(report["safety"]["network_requests"])
        self.assertTrue(report["safety"]["calibration_is_advisory_only"])
        self.assertEqual(
            [family for family, value in report["calibration_profile"]["families"].items() if value["ready"]],
            [],
        )

        positive_without_target_evidence = sorted(
            record["family"]
            for record in records
            if record["label"] and int(record["target_evidence_confidence"]) <= 0
        )
        self.assertEqual(positive_without_target_evidence, [])

        by_family = {}
        for record in records:
            by_family.setdefault(record["family"], {})[bool(record["label"])] = record
        non_separating = sorted(
            family
            for family, pair in by_family.items()
            if int(pair[True]["score"]) <= int(pair[False]["score"])
        )
        self.assertEqual(non_separating, [])


if __name__ == "__main__":
    unittest.main()
