from __future__ import annotations

import unittest

import v7_fifth_pass_source_specific_acquisition as module


class V7FifthPassSourceSpecificAcquisitionTests(unittest.TestCase):
    def test_semver_parsing_is_bounded(self) -> None:
        self.assertEqual(module.semver("v2.15.1"), (2, 15, 1))
        self.assertEqual(module.semver("release-3.1.4"), (3, 1, 4))
        self.assertIsNone(module.semver("main"))

    def test_source_specific_terms_are_tokens_not_phrases(self) -> None:
        research = {
            "snapshot_payload": {
                "summary": "Deprecated SendPasswordResetEmailPayload.user field exposes users",
                "description": "Validation around account lookup",
            }
        }
        deep = {
            "revision_candidates": [
                {"files": [{"filename": "src/graphql/password_reset_resolver.ts"}]}
            ]
        }
        terms = module.source_specific_terms(research, deep, "account_enumeration")
        self.assertLessEqual(len(terms), 12)
        self.assertTrue(all(" " not in term for term in terms))
        self.assertIn("password_reset_resolver", terms)

    def test_test_path_guard_rejects_docs(self) -> None:
        self.assertTrue(module.TEST_PATH.search("tests/security/test_auth.py"))
        self.assertFalse(module.TEST_PATH.search("docs/test-plan.md"))

    def test_output_is_candidate_only(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))
        self.assertIn("fifth-pass.source-specific", module.RULE_VERSION)


if __name__ == "__main__":
    unittest.main()
