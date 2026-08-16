from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import load_golden_cases, replay_golden_cases
from decision_readiness import decision_readiness
from meta_ranker import rank_bug_proximity
from vulnerability_knowledge import rank_families, retrieve_writeups


class DecisionReadinessV930Tests(unittest.TestCase):
    def test_structural_evidence_can_remain_hunt_worthy_but_not_decision_ready(self):
        support = [
            {"type": "file_input", "source_group": "schema"},
            {"type": "upload_operation", "source_group": "endpoint"},
        ]
        family_rankings = rank_families(support, [], endpoint="/upload", summary="upload surface", limit=100)
        writeups = retrieve_writeups(support, [], endpoint="/upload", summary="upload surface", family="file_upload", limit=5)
        ranked = rank_bug_proximity(support, [], family_rankings, writeups, limit=100)
        item = next(row for row in ranked["rankings"] if row["family"] == "file_upload")
        self.assertGreaterEqual(item["bug_proximity_score"], 35)
        self.assertLessEqual(item["decision_readiness_score"], 30)
        self.assertEqual(item["decision_readiness"]["band"], "investigation_only")
        self.assertTrue(item["decision_readiness"]["advisory_only"])

    def test_full_decisive_contract_scores_above_surface_only(self):
        reasoning = {
            "demo": {
                "confirmation_required": (("direct_observation",),),
                "blocking_contradictions": ("control_enforced",),
            }
        }
        surface = decision_readiness(
            "demo",
            [{"type": "surface_marker"}],
            [],
            target_evidence_confidence=45,
            reasoning=reasoning,
        )
        decisive = decision_readiness(
            "demo",
            [{"type": "surface_marker"}, {"type": "direct_observation"}],
            [],
            target_evidence_confidence=82,
            reasoning=reasoning,
        )
        self.assertLessEqual(surface["score"], 30)
        self.assertGreater(decisive["score"], surface["score"])
        self.assertEqual(decisive["confirmation_coverage"], 1.0)
        self.assertIn("direct_observation", decisive["matched_decisive_signals"])

    def test_observed_control_blocks_readiness_without_erasing_hunt_context(self):
        reasoning = {
            "demo": {
                "confirmation_required": (("direct_observation",),),
                "blocking_contradictions": ("control_enforced",),
            }
        }
        unblocked = decision_readiness(
            "demo",
            [{"type": "direct_observation"}],
            [],
            target_evidence_confidence=90,
            reasoning=reasoning,
        )
        blocked = decision_readiness(
            "demo",
            [{"type": "direct_observation"}],
            [{"type": "control_enforced"}],
            target_evidence_confidence=90,
            reasoning=reasoning,
        )
        self.assertGreater(unblocked["score"], blocked["score"])
        self.assertLessEqual(blocked["score"], 25)
        self.assertEqual(blocked["band"], "blocked_by_control")
        self.assertIn("control_enforced", blocked["blocking_contradictions"])

    def test_all_74_golden_positive_readiness_scores_above_paired_negative(self):
        cases = load_golden_cases([
            ROOT / "tests" / "fixtures" / "vulnerability_intelligence_golden_v1.json",
            ROOT / "tests" / "fixtures" / "vulnerability_intelligence_phase2_golden_v2.json",
        ])
        records = replay_golden_cases(cases)
        by_family = {}
        for row in records:
            by_family.setdefault(row["family"], {})[bool(row["label"])] = row
        self.assertEqual(len(by_family), 74)
        failures = sorted(
            family for family, pair in by_family.items()
            if int(pair[True]["decision_readiness_score"]) <= int(pair[False]["decision_readiness_score"])
        )
        self.assertEqual(failures, [])

    def test_meta_ranker_readiness_never_changes_hunting_order_or_hard_gates(self):
        support = [
            {"type": "object_identifier", "source_group": "schema"},
            {"type": "object_operation", "source_group": "contract"},
            {"type": "authorization_response_differential", "source_group": "behavior"},
        ]
        family_rankings = rank_families(support, [], endpoint="/objects/1", summary="authz replay", limit=100)
        writeups = retrieve_writeups(support, [], endpoint="/objects/1", summary="authz replay", family="broken_object_authorization", limit=5)
        ranked = rank_bug_proximity(support, [], family_rankings, writeups, limit=100)
        self.assertTrue(ranked["safety"]["decision_readiness_is_advisory_only"])
        self.assertTrue(ranked["safety"]["decision_readiness_cannot_satisfy_admission_or_confirmation"])
        item = next(row for row in ranked["rankings"] if row["family"] == "broken_object_authorization")
        self.assertFalse(item["decision_readiness"]["may_satisfy_admission"])
        self.assertFalse(item["decision_readiness"]["may_satisfy_confirmation"])
        self.assertFalse(item["decision_readiness"]["may_create_target_evidence"])


if __name__ == "__main__":
    unittest.main()
