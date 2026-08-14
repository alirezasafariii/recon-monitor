from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_control_design as design


def source(root: str, family: str = "ssrf") -> dict:
    return {
        "source_root": root,
        "source_project": "owner/project",
        "family_target": family,
        "target_cwe": "CWE-918",
        "advisory_cwes": ["CWE-918"],
        "source_taxonomy_match": {
            "status": "exact_target_cwe_match",
            "target_cwe_present": True,
        },
    }


def case(root: str, variant: str) -> dict:
    return {
        "case_id": f"case-{variant}",
        "case_origin_id": f"origin-{root}",
        "source_root": root,
        "source_project": "owner/project",
        "variant": variant,
        "capture_design_status": "control_design_required" if variant == "near_miss" else "ready_to_collect",
        "review": {"label": None, "human_verified": False},
        "scoring_executed": False,
        "target_contact_performed": False,
    }


class RealWorldCorpusV1ControlDesignTests(unittest.TestCase):
    def test_exact_family_design_uses_canonical_reasoning_contract(self):
        result = design.design_near_miss(case("GHSA-aaaa-bbbb-cccc", "near_miss"), source("GHSA-aaaa-bbbb-cccc"))
        self.assertEqual(result["family_basis"], "exact_target_cwe")
        self.assertEqual(result["control_family"], "ssrf")
        self.assertTrue(result["selected_family_contract"]["promotion_required_groups"])
        self.assertTrue(result["required_observation_contract"]["leave_at_least_one_promotion_group_unsatisfied"])
        self.assertEqual(result["reclassification_rules"]["if_blocking_security_control_observed"], "secure_negative_candidate_requires_review")
        self.assertEqual(result["design_status"], "ready_for_controlled_source_observation")

    def test_design_never_creates_final_label_or_target_access(self):
        result = design.design_near_miss(case("GHSA-aaaa-bbbb-cccc", "near_miss"), source("GHSA-aaaa-bbbb-cccc"))
        self.assertFalse(result["family_label_is_final"])
        self.assertFalse(result["safety"]["vulnerability_target_network_access"])
        self.assertFalse(result["safety"]["credential_use"])
        self.assertFalse(result["safety"]["exploit_payload_generation"])
        self.assertFalse(result["safety"]["human_label_created"])
        self.assertFalse(result["safety"]["analysis_scoring_executed"])

    def test_full_plan_moves_all_100_near_misses_to_ready(self):
        sources = []
        cases = []
        for i in range(100):
            root = f"GHSA-{i:04d}-aaaa-bbbb"
            sources.append(source(root))
            for variant in ("positive", "near_miss", "secure_negative", "sparse_noisy"):
                row = case(root, variant)
                row["case_id"] = f"{root}-{variant}"
                cases.append(row)
        result = design.build_ready_plan(cases, sources)
        self.assertTrue(result["passed"])
        self.assertEqual(result["case_count"], 400)
        self.assertEqual(result["near_miss_control_count"], 100)
        self.assertEqual(result["ready_to_collect_count"], 400)
        self.assertEqual(result["family_basis_counts"], {"exact_target_cwe": 100})

    def test_generic_source_still_gets_safe_nonlabel_control_contract(self):
        generic = source("GHSA-aaaa-bbbb-cccc", family="")
        generic["target_cwe"] = None
        generic["advisory_cwes"] = []
        generic["source_taxonomy_match"] = {"status": "not_applicable_general_source"}
        result = design.design_near_miss(case("GHSA-aaaa-bbbb-cccc", "near_miss"), generic)
        self.assertEqual(result["family_basis"], "generic_source_control")
        self.assertIsNone(result["control_family"])
        self.assertFalse(result["candidate_families"])
        self.assertTrue(result["review_requirements"]["source_family_adjudication_required_before_final_label"])
        self.assertEqual(result["design_status"], "ready_for_controlled_source_observation")


if __name__ == "__main__":
    unittest.main()
