from __future__ import annotations

import unittest

import v7_third_pass_deep_acquisition as module


class V7ThirdPassDeepAcquisitionTests(unittest.TestCase):
    def test_significant_terms_are_bounded_and_pre_registered(self) -> None:
        packet = {
            "blocking_controls_vocabulary": ["ownership validation", "deny unauthorized access"],
            "condition_signals_vocabulary": ["object identifier mismatch"],
            "override_signals_vocabulary": [],
        }
        terms = module.significant_terms(packet, "broken_object_authorization")
        self.assertLessEqual(len(terms), 8)
        self.assertIn("ownership validation", terms)
        self.assertIn("deny unauthorized access", terms)

    def test_parse_time_accepts_utc_z(self) -> None:
        value = module.parse_time("2026-08-01T12:00:00Z")
        self.assertIsNotNone(value)
        self.assertEqual(value.utcoffset().total_seconds(), 0)

    def test_output_is_candidate_metadata_not_evidence(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))
        self.assertIn("third-pass", module.RULE_VERSION)


if __name__ == "__main__":
    unittest.main()
