from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import benchmark_report, load_golden_cases, replay_golden_cases
from calibration_engine import build_calibration_profile, confusion_metrics, select_threshold
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


if __name__ == "__main__":
    unittest.main()
