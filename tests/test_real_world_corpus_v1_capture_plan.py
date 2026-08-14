from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_capture_plan as plan


def sources():
    rows = []
    for i in range(100):
        feasibility = (
            "strong_revision_boundary"
            if i < 77
            else "version_boundary_available"
            if i < 96
            else "source_reference_available"
            if i < 99
            else "manual_source_research_required"
        )
        rows.append({
            "source_root": f"GHSA-{i:04d}-aaaa-bbbb",
            "source_project": f"owner/project-{i:04d}",
            "family_target": f"family_{i:04d}" if i < 60 else None,
            "target_cwe": "CWE-918" if i < 60 else None,
            "capture_feasibility": feasibility,
            "variant_feasibility": {
                "positive": "candidate",
                "secure_negative": "candidate",
                "near_miss": "manual_control_design_required",
                "sparse_noisy": "candidate_from_minimal_source_metadata",
            },
            "source_taxonomy_match": {
                "family_target": f"family_{i:04d}" if i < 60 else None,
                "target_cwe": "CWE-918" if i < 60 else None,
                "target_cwe_present": i < 60,
                "final_family_assigned": False,
            },
            "version_boundaries": [],
            "reference_inventory": {},
        })
    return rows


class RealWorldCorpusV1CapturePlanTests(unittest.TestCase):
    def test_builds_exact_400_cases_and_four_per_origin(self):
        result = plan.build_capture_plan(sources())
        validation = result["validation"]
        self.assertTrue(validation["passed"])
        self.assertEqual(validation["case_count"], 400)
        self.assertEqual(validation["source_origin_count"], 100)
        self.assertEqual(validation["unique_source_root_count"], 100)
        self.assertEqual(validation["unique_source_project_count"], 100)
        self.assertEqual(validation["family_target_count"], 60)

    def test_plan_contains_no_labels_or_final_families(self):
        result = plan.build_capture_plan(sources())
        for case in result["cases"]:
            self.assertIsNone(case["review"]["label"])
            self.assertIsNone(case["review"]["final_family"])
            self.assertFalse(case["review"]["human_verified"])
            self.assertFalse(case["family_assignment_is_final"])
            self.assertFalse(case["scoring_executed"])

    def test_plan_forbids_target_network_and_credentials(self):
        result = plan.build_capture_plan(sources())
        for case in result["cases"]:
            self.assertFalse(case["vulnerability_target_network_access_allowed"])
            self.assertFalse(case["credential_use_allowed"])
            self.assertFalse(case["state_mutation_allowed"])
            self.assertFalse(case["payload_generation_allowed"])
            self.assertFalse(case["target_contact_performed"])

    def test_expected_design_status_distribution(self):
        result = plan.build_capture_plan(sources())
        counts = result["validation"]["design_status_counts"]
        self.assertEqual(counts["blocked"], 4)
        self.assertEqual(counts["control_design_required"], 99)
        self.assertEqual(counts["source_research_required"], 6)
        self.assertEqual(counts["ready_to_collect"], 291)

    def test_all_quality_dimensions_are_unfilled_review_fields(self):
        case = plan.build_capture_plan(sources())["cases"][0]
        self.assertEqual(set(case["review"]["evidence_quality"]), set(plan.QUALITY_DIMENSIONS))
        self.assertTrue(all(value is None for value in case["review"]["evidence_quality"].values()))

    def test_plan_is_order_stable(self):
        a = plan.build_capture_plan(sources())
        b = plan.build_capture_plan(list(reversed(sources())))
        self.assertEqual(a["plan_sha256"], b["plan_sha256"])


if __name__ == "__main__":
    unittest.main()
