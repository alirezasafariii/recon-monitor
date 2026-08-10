from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from meta_ranker import rank_bug_proximity, target_evidence_confidence


class MetaRankerV861Tests(unittest.TestCase):
    def test_target_evidence_is_separate_from_writeup_similarity(self):
        rankings = [{
            "family": "broken_object_authorization",
            "label": "BOLA / IDOR",
            "score": 0,
            "matched": {"strong": [], "medium": [], "weak": [], "text": []},
            "contradictions": [],
            "taxonomy": {},
            "tags": [],
        }]
        result = rank_bug_proximity(
            [],
            [],
            rankings,
            [{"family": "broken_object_authorization", "retrieval_score": 100}],
        )
        primary = result["primary"]
        self.assertIsNotNone(primary)
        self.assertEqual(primary["target_evidence_confidence"], 0)
        self.assertLessEqual(primary["bug_proximity_score"], 35)
        self.assertEqual(primary["status"], "proximity_only_not_confirmed")

    def test_family_specific_target_evidence_drives_confidence(self):
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
            "taxonomy": {"cwe": ["CWE-639"]},
            "tags": ["near:idor"],
        }
        evidence, explanation = target_evidence_confidence(ranking, support)
        self.assertGreaterEqual(evidence, 60)
        self.assertEqual(explanation["independent_target_source_groups"], 3)

        result = rank_bug_proximity(
            support,
            [],
            [ranking],
            [{"family": "broken_object_authorization", "retrieval_score": 96}],
        )
        self.assertEqual(result["primary"]["family"], "broken_object_authorization")
        self.assertGreaterEqual(result["primary"]["bug_proximity_score"], 75)
        self.assertEqual(result["primary"]["hunt_priority"], "HIGH")

    def test_llm_advisory_cannot_change_target_evidence_confidence(self):
        support = [{"type": "object_identifier", "source_group": "schema"}]
        ranking = {
            "family": "broken_object_authorization",
            "label": "BOLA / IDOR",
            "score": 30,
            "matched": {"strong": [], "medium": ["object_identifier"], "weak": [], "text": []},
            "contradictions": [],
            "taxonomy": {},
            "tags": [],
        }
        without_llm = rank_bug_proximity(support, [], [ranking], [])
        with_llm = rank_bug_proximity(
            support,
            [],
            [ranking],
            [],
            llm_advisory_scores={"broken_object_authorization": 100},
        )
        self.assertEqual(
            without_llm["primary"]["target_evidence_confidence"],
            with_llm["primary"]["target_evidence_confidence"],
        )
        self.assertLessEqual(with_llm["primary"]["bug_proximity_score"], 55)

    def test_contradiction_penalizes_both_evidence_and_proximity(self):
        support = [
            {"type": "object_identifier", "source_group": "schema"},
            {"type": "object_operation", "source_group": "contract"},
            {"type": "authorization_response_differential", "source_group": "behavioral"},
        ]
        clean = {
            "family": "broken_object_authorization",
            "label": "BOLA / IDOR",
            "score": 90,
            "matched": {"strong": ["authorization_response_differential"], "medium": ["object_identifier", "object_operation"], "weak": [], "text": []},
            "contradictions": [],
            "taxonomy": {},
            "tags": [],
        }
        contradicted = dict(clean)
        contradicted["contradictions"] = ["cross_context_denied"]
        clean_result = rank_bug_proximity(support, [], [clean], [])
        contradicted_result = rank_bug_proximity(support, [], [contradicted], [])
        self.assertLess(
            contradicted_result["primary"]["target_evidence_confidence"],
            clean_result["primary"]["target_evidence_confidence"],
        )
        self.assertLess(
            contradicted_result["primary"]["bug_proximity_score"],
            clean_result["primary"]["bug_proximity_score"],
        )

    def test_top_three_is_multi_label_and_sorted(self):
        rankings = [
            {"family": "a", "label": "A", "score": 80, "matched": {"strong": ["s1"], "medium": [], "weak": [], "text": []}, "contradictions": [], "taxonomy": {}, "tags": []},
            {"family": "b", "label": "B", "score": 60, "matched": {"strong": [], "medium": ["s2"], "weak": [], "text": []}, "contradictions": [], "taxonomy": {}, "tags": []},
            {"family": "c", "label": "C", "score": 40, "matched": {"strong": [], "medium": [], "weak": ["s3"], "text": []}, "contradictions": [], "taxonomy": {}, "tags": []},
            {"family": "d", "label": "D", "score": 20, "matched": {"strong": [], "medium": [], "weak": ["s4"], "text": []}, "contradictions": [], "taxonomy": {}, "tags": []},
        ]
        support = [
            {"type": "s1", "source_group": "one"},
            {"type": "s2", "source_group": "two"},
            {"type": "s3", "source_group": "three"},
            {"type": "s4", "source_group": "four"},
        ]
        result = rank_bug_proximity(support, [], rankings, [], limit=3)
        self.assertEqual(len(result["rankings"]), 3)
        scores = [item["bug_proximity_score"] for item in result["rankings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))


if __name__ == "__main__":
    unittest.main()
