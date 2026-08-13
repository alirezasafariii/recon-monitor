from __future__ import annotations

import json
import unittest
from pathlib import Path

from analysis_630_open_redirect_calibration import DATASET, evaluate
from family_detectors.execution import EXECUTION_ENGINE_VERSION, EXECUTION_RULE_VERSION
from family_detectors.open_redirect import SPEC


class Analysis630OpenRedirectCalibrationTest(unittest.TestCase):
    def test_calibration_set_is_independent_and_complete(self) -> None:
        data = json.loads(DATASET.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], "1.0.0")
        self.assertFalse(data["source_policy"]["v5_source_overlap_allowed"])
        self.assertFalse(data["source_policy"]["detector_grounding_source_used_as_target_evidence"])
        self.assertEqual(len(data["cases"]), 8)
        positive_roots = {row["source_root"] for row in data["cases"] if row["expected_admitted"]}
        self.assertEqual(positive_roots, {"CVE-2024-53995", "CVE-2025-4143", "CVE-2025-62595"})
        v5 = [json.loads(line) for line in Path("benchmarks/raw/analysis_raw_v5.jsonl").read_text().splitlines() if line.strip()]
        v5_roots = {str(row.get("source_root") or "") for row in v5}
        self.assertFalse(positive_roots & v5_roots)
        grounding_urls = {ref.url for ref in SPEC.writeups}
        positive_urls = {row["source_url"] for row in data["cases"] if row["expected_admitted"]}
        self.assertFalse(positive_urls & grounding_urls)

    def test_execution_version_is_analysis_630(self) -> None:
        self.assertEqual(EXECUTION_ENGINE_VERSION, "1.4.0")
        self.assertEqual(EXECUTION_RULE_VERSION, "2026.08.13.6.30")

    def test_all_pre_registered_calibration_cases_pass(self) -> None:
        result = evaluate()
        self.assertTrue(result["all_passed"], [row for row in result["cases"] if not row["passed"]])
        self.assertEqual(result["case_count"], 8)
        self.assertEqual(result["failed_count"], 0)


if __name__ == "__main__":
    unittest.main()
