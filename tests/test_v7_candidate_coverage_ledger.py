from __future__ import annotations

import unittest

import v7_candidate_coverage_ledger as module


class V7CandidateCoverageLedgerTests(unittest.TestCase):
    def test_collect_ready_only_collects_review_ready_rows(self) -> None:
        doc = {
            "items": [
                {
                    "capture_id": "a",
                    "family": "x",
                    "case_kind": "near_miss",
                    "source_root": "GHSA-a",
                    "source_project": "o/r",
                    "candidate_count": 2,
                    "resolution_status": "candidate_material_available_for_human_review",
                },
                {
                    "capture_id": "b",
                    "family": "y",
                    "case_kind": "positive",
                    "source_root": "GHSA-b",
                    "source_project": "o/r2",
                    "candidate_count": 0,
                    "resolution_status": "still_unresolved_after_third_pass",
                },
            ]
        }
        rows = module.collect_ready(doc, "test_stage")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["capture_id"], "a")
        self.assertFalse(rows[0]["semantic_adjudicated"])

    def test_expected_coverage_kind_contract(self) -> None:
        self.assertEqual(module.VERSION, "1.0.0")
        self.assertIn("coverage-ledger", module.RULE_VERSION)
        self.assertIn("v7_missing_literal_source_worklist.json", str(module.WORKLIST))

    def test_outputs_are_metadata_not_evidence(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertIn("benchmarks/raw/sources", str(module.REPORT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))


if __name__ == "__main__":
    unittest.main()
