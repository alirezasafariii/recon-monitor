from __future__ import annotations

import unittest

import v7_residual_worklist as module


class V7ResidualWorklistTests(unittest.TestCase):
    def test_output_is_planning_metadata_only(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))
        self.assertIn("residual", module.RULE_VERSION)

    def test_expected_version(self) -> None:
        self.assertEqual(module.VERSION, "1.0.0")


if __name__ == "__main__":
    unittest.main()
