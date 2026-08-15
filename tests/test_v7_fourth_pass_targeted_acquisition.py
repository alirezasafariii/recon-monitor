from __future__ import annotations

import unittest

import v7_fourth_pass_targeted_acquisition as module


class V7FourthPassTargetedAcquisitionTests(unittest.TestCase):
    def test_lexical_terms_are_single_bounded_tokens(self) -> None:
        packet = {
            "blocking_controls_vocabulary": ["ownership validation", "deny unauthorized access"],
            "condition_signals_vocabulary": ["object identifier mismatch"],
            "override_signals_vocabulary": [],
        }
        terms = module.lexical_terms(packet, "broken_object_authorization")
        self.assertLessEqual(len(terms), 10)
        self.assertTrue(all(" " not in term for term in terms))
        self.assertIn("ownership", terms)
        self.assertIn("validation", terms)

    def test_test_path_guard_rejects_docs(self) -> None:
        self.assertTrue(module.TEST_PATH.search("tests/security/test_auth.py"))
        self.assertFalse(module.TEST_PATH.search("docs/test-plan.md"))

    def test_output_is_candidate_only(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))
        self.assertIn("fourth-pass.targeted", module.RULE_VERSION)


if __name__ == "__main__":
    unittest.main()
