from __future__ import annotations

import unittest

import v7_final_residual_control_capture as module


class V7FinalResidualControlCaptureTests(unittest.TestCase):
    def test_only_expected_two_families_are_allowed(self) -> None:
        self.assertEqual(set(module.EXPECTED), {"command_injection", "cors_misconfiguration"})
        self.assertTrue(all(cfg["source_root"].startswith("GHSA-") for cfg in module.EXPECTED.values()))

    def test_systeminformation_candidate_is_sanitized_sibling_path(self) -> None:
        cfg = module.EXPECTED["command_injection"]
        self.assertIn("sanitizeString", cfg["anchor"])
        self.assertEqual(cfg["file"], "lib/network.js")
        self.assertIn("sibling", cfg["candidate_role"])

    def test_joro_candidate_is_same_origin_guard_path(self) -> None:
        cfg = module.EXPECTED["cors_misconfiguration"]
        self.assertIn("same-origin", cfg["anchor"])
        self.assertEqual(cfg["file"], "internal/api/originguard.go")
        self.assertIn("cross_origin_guard", cfg["candidate_role"])

    def test_output_is_candidate_only(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))
        self.assertIn("final-residual-control", module.RULE_VERSION)


if __name__ == "__main__":
    unittest.main()
