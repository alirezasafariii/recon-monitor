from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import real_world_corpus_v1_shortlist as shortlist


def targeted_rows(count: int = 60):
    return [
        {
            "source_root": f"GHSA-t{i:03d}-aaaa-bbbb",
            "source_project": f"targeted/project-{i:03d}",
            "family_target": f"family_{i:03d}",
            "human_verified": False,
            "scoring_executed": False,
        }
        for i in range(count)
    ]


def general_rows(count: int = 100):
    return [
        {
            "source_root": f"GHSA-g{i:03d}-cccc-dddd",
            "source_project": f"general/project-{i:03d}",
            "human_verified": False,
            "scoring_executed": False,
        }
        for i in range(count)
    ]


class RealWorldCorpusV1ShortlistTests(unittest.TestCase):
    def test_builds_exact_100_with_60_targeted_and_40_general(self):
        result = shortlist.build_shortlist(targeted_rows(), general_rows())
        self.assertEqual(result["validation"]["source_count"], 100)
        self.assertEqual(result["validation"]["unique_source_root_count"], 100)
        self.assertEqual(result["validation"]["unique_source_project_count"], 100)
        self.assertEqual(result["validation"]["family_target_count"], 60)
        self.assertEqual(result["selected_family_targeted_count"], 60)
        self.assertEqual(result["selected_general_fresh_count"], 40)

    def test_shortlist_never_creates_final_family_or_human_verification(self):
        result = shortlist.build_shortlist(targeted_rows(), general_rows())
        for row in result["sources"]:
            self.assertIsNone(row["final_family"])
            self.assertFalse(row["family_label_adjudicated"])
            self.assertFalse(row["human_verified"])
            self.assertFalse(row["scoring_executed"])
            self.assertFalse(row["target_contact_performed"])
            self.assertEqual(row["source_feasibility_status"], "pending_review")

    def test_rejects_family_target_coverage_below_floor(self):
        with self.assertRaisesRegex(ValueError, "insufficient_distinct_family_targets"):
            shortlist.build_shortlist(targeted_rows(49), general_rows(100))

    def test_deduplicates_root_and_project_across_pools(self):
        targeted = targeted_rows()
        general = general_rows(100)
        general[0]["source_root"] = targeted[0]["source_root"]
        general[1]["source_project"] = targeted[1]["source_project"]
        result = shortlist.build_shortlist(targeted, general)
        roots = [row["source_root"] for row in result["sources"]]
        projects = [row["source_project"] for row in result["sources"]]
        self.assertEqual(len(roots), len(set(roots)))
        self.assertEqual(len(projects), len(set(projects)))

    def test_validation_rejects_final_family_leakage(self):
        rows = [
            {
                "source_root": f"R{i}",
                "source_project": f"p/{i}",
                "family_target": f"f{i}",
                "final_family": None,
                "human_verified": False,
                "scoring_executed": False,
            }
            for i in range(100)
        ]
        rows[0]["final_family"] = "ssrf"
        validation = shortlist.validate_shortlist(rows, target_roots=100, min_family_targets=50)
        self.assertFalse(validation["passed"])
        self.assertIn("pre_adjudication_shortlist_must_not_set_final_family", validation["errors"])

    def test_shortlist_hash_is_order_stable(self):
        a = shortlist.build_shortlist(targeted_rows(), general_rows())
        b = shortlist.build_shortlist(list(reversed(targeted_rows())), list(reversed(general_rows())))
        self.assertEqual(a["shortlist_sha256"], b["shortlist_sha256"])


if __name__ == "__main__":
    unittest.main()
