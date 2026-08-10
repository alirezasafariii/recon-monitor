from __future__ import annotations

import unittest

from analysis_postfreeze_build import build_and_validate, build_root_cases
from analysis_postfreeze_sources import load_source_registry
from hypothesis_admission import assess_admission


class AnalysisPostFreezeBuild660Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = build_and_validate()
        cls.roots = load_source_registry()

    def test_builds_exact_preregistered_case_shape(self) -> None:
        report = self.report
        self.assertEqual(report["source_root_count"], 50)
        self.assertEqual(report["case_count"], 200)
        self.assertEqual(report["positive_count"], 50)
        self.assertEqual(report["near_miss_count"], 50)
        self.assertEqual(report["secure_negative_count"], 50)
        self.assertEqual(report["sparse_noisy_count"], 50)
        self.assertEqual(report["rank_required_count"], 150)
        self.assertTrue(report["corpus_validation"]["passed"], report["corpus_validation"]["errors"])

    def test_positive_adjudication_establishes_frozen_condition(self) -> None:
        for root in self.roots:
            positive, _, _, _ = build_root_cases(root)
            assessment = assess_admission(positive["family"], positive["support"], positive["contradict"])
            self.assertTrue(
                assessment["admitted"],
                f"{positive['source_root']} / {positive['family']}: {assessment['reason']}",
            )

    def test_near_miss_never_establishes_frozen_condition(self) -> None:
        for root in self.roots:
            _, near_miss, _, _ = build_root_cases(root)
            assessment = assess_admission(near_miss["family"], near_miss["support"], near_miss["contradict"])
            self.assertFalse(assessment["admitted"], near_miss["source_root"])
            self.assertIn(assessment["state"], {"shadow_partial", "shadow_signal"})

    def test_secure_negative_is_blocked_by_real_family_control(self) -> None:
        for root in self.roots:
            _, _, secure_negative, _ = build_root_cases(root)
            assessment = assess_admission(
                secure_negative["family"],
                secure_negative["support"],
                secure_negative["contradict"],
            )
            self.assertFalse(assessment["admitted"], secure_negative["source_root"])
            self.assertEqual(assessment["state"], "shadow_contradicted", secure_negative["source_root"])
            self.assertTrue(assessment["blocking_contradictions"], secure_negative["source_root"])

    def test_sparse_noisy_is_abstention_only_not_forced_family_ranking(self) -> None:
        for root in self.roots:
            _, _, _, sparse = build_root_cases(root)
            assessment = assess_admission(sparse["family"], sparse["support"], sparse["contradict"])
            self.assertFalse(assessment["admitted"], sparse["source_root"])
            self.assertFalse(sparse["rank_required"])
            self.assertEqual(sparse["case_kind"], "sparse_noisy")

    def test_generated_target_evidence_never_uses_external_knowledge_sources(self) -> None:
        forbidden = {
            "knowledge", "external_writeup", "owasp", "owasp_wstg", "wstg",
            "mitre_cwe", "cwe", "standards", "provenance",
        }
        for root in self.roots:
            for case in build_root_cases(root):
                for item in [*case["support"], *case["contradict"]]:
                    self.assertNotIn(str(item.get("source", "")).lower(), forbidden)
                    self.assertNotIn(str(item.get("source_group", "")).lower(), forbidden)


if __name__ == "__main__":
    unittest.main()
