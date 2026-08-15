from __future__ import annotations

import unittest

import v7_sixth_pass_reference_tree_acquisition as module


class V7SixthPassReferenceTreeAcquisitionTests(unittest.TestCase):
    def test_release_reference_is_same_project_only(self) -> None:
        research = {
            "snapshot_payload": {
                "references": [
                    "https://github.com/wp-graphql/wp-graphql/releases/tag/wp-graphql/v2.15.1",
                    "https://github.com/other/repo/releases/tag/v9.9.9",
                ]
            }
        }
        self.assertEqual(
            module.frozen_release_tags(research, "wp-graphql/wp-graphql"),
            ["wp-graphql/v2.15.1"],
        )

    def test_path_score_prefers_module_matches(self) -> None:
        terms = ["graphql", "password_reset"]
        strong = module.path_score("tests/graphql/password_reset_test.php", terms)
        weak = module.path_score("tests/unrelated/foo_test.php", terms)
        self.assertLess(strong, weak)

    def test_test_case_regex_covers_common_frameworks(self) -> None:
        samples = [
            "def test_auth():",
            "public function testAuth() {",
            "func TestAuth(t *testing.T) {",
            "test('auth', () => {",
            "#[test]",
            "Scenario: invalid auth",
        ]
        for sample in samples:
            self.assertIsNotNone(module.TEST_CASE_RE.search(sample), sample)

    def test_output_is_candidate_metadata_only(self) -> None:
        self.assertIn("benchmarks/raw/sources", str(module.OUTPUT))
        self.assertNotIn("v7_capture_evidence", str(module.OUTPUT))
        self.assertIn("sixth-pass.reference-tree", module.RULE_VERSION)


if __name__ == "__main__":
    unittest.main()
