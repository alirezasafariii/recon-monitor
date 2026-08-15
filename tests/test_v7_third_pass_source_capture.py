from __future__ import annotations

import unittest

import v7_third_pass_source_capture as module


class V7ThirdPassSourceCaptureTests(unittest.TestCase):
    def test_test_path_guard_is_strict(self) -> None:
        self.assertTrue(module.TEST_PATH.search("tests/security/test_auth.py"))
        self.assertFalse(module.TEST_PATH.search("src/security/auth.py"))
        self.assertFalse(module.TEST_PATH.search("docs/test-plan.md"))

    def test_priority_uses_frozen_breadcrumbs_only(self) -> None:
        strong = {"commit_sha": "b", "matched_identifiers": ["CVE-X"], "matched_terms": [], "security_word_match": False}
        weak = {"commit_sha": "a", "matched_identifiers": [], "matched_terms": [], "security_word_match": True}
        self.assertLess(module.priority(strong), module.priority(weak))

    def test_output_is_candidate_metadata_not_evidence(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))
        self.assertIn("third-pass.capture", module.RULE_VERSION)


if __name__ == "__main__":
    unittest.main()
