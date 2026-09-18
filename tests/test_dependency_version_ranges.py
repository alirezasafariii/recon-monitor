from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from dependency_advisory_matcher import catalog_status
from dependency_version_ranges import (
    range_expression_capability,
    range_expression_supported,
    version_matches_range,
)


class DependencyVersionRangeTests(unittest.TestCase):
    def test_generic_numeric_comparators_accept_single_and_long_release_segments(self):
        self.assertTrue(version_matches_range("1.2.3", ">= 0", "npm"))
        self.assertTrue(version_matches_range("2024.1.2.3", "< 2025.0.0.0", "maven"))
        self.assertFalse(version_matches_range("2.0.0", "< 2", "npm"))
        self.assertTrue(range_expression_supported(">= 0, < 2", "npm"))

    def test_semver_prerelease_boundary_keeps_stable_observation_exact(self):
        self.assertTrue(
            version_matches_range("1.2.3", "> 1.2.3-rc.1", "npm")
        )
        self.assertFalse(
            version_matches_range("1.2.3", "< 1.2.3-rc.1", "npm")
        )
        self.assertTrue(
            version_matches_range(
                "0.0.1",
                "> 0.0.1-0.20260918-abcdef",
                "go",
            )
        )
        self.assertTrue(
            range_expression_supported("< 2.0.0-beta.2", "nuget")
        )

    def test_semver_shorthand_and_union_are_bounded(self):
        self.assertTrue(version_matches_range("1.8.4", "^1.2.3", "npm"))
        self.assertFalse(version_matches_range("2.0.0", "^1.2.3", "npm"))
        self.assertTrue(version_matches_range("1.2.8", "~1.2.3", "composer"))
        self.assertFalse(version_matches_range("1.3.0", "~1.2.3", "composer"))
        self.assertTrue(version_matches_range("1.2.9", "1.2.x", "rust"))
        self.assertFalse(version_matches_range("1.3.0", "1.2.x", "rust"))
        self.assertTrue(
            version_matches_range("1.5.0", "1.0.0 - 2.0.0", "pub")
        )
        self.assertTrue(
            version_matches_range(
                "3.2.0",
                ">= 1.0.0, < 2.0.0 || >= 3.0.0, < 4.0.0",
                "npm",
            )
        )

    def test_partial_union_can_positive_match_only_under_fully_understood_branch(self):
        expression = ">= 1.0.0, < 2.0.0 || bananas"
        self.assertEqual(
            range_expression_capability(expression, "npm"),
            "partial",
        )
        self.assertFalse(range_expression_supported(expression, "npm"))
        self.assertTrue(version_matches_range("1.5.0", expression, "npm"))
        self.assertFalse(version_matches_range("9.9.9", expression, "npm"))

    def test_pep440_boundaries_and_compatible_release(self):
        self.assertTrue(version_matches_range("2.0.0", "> 2.0.0rc1", "pip"))
        self.assertFalse(version_matches_range("2.0.0", "> 2.0.0.post1", "pip"))
        self.assertTrue(version_matches_range("1.4.8", "~= 1.4.5", "pip"))
        self.assertFalse(version_matches_range("1.5.0", "~= 1.4.5", "pip"))
        self.assertTrue(
            range_expression_supported(">= 1.0.dev1, < 2.0", "pip")
        )

    def test_rubygems_prerelease_and_pessimistic_operator(self):
        self.assertTrue(
            version_matches_range("3.1.0", "> 3.1.0.rc1", "rubygems")
        )
        self.assertTrue(
            version_matches_range("2.2.8", "~> 2.2.0", "rubygems")
        )
        self.assertFalse(
            version_matches_range("2.3.0", "~> 2.2.0", "rubygems")
        )

    def test_maven_qualifiers_and_interval_notation(self):
        self.assertTrue(
            version_matches_range("2.0.0", "> 2.0.0-RC1", "maven")
        )
        self.assertFalse(
            version_matches_range("2.0.0", "> 2.0.0-sp1", "maven")
        )
        self.assertTrue(
            version_matches_range("1.5.0", "[1.0.0,2.0.0)", "maven")
        )
        self.assertFalse(
            version_matches_range("2.0.0", "[1.0.0,2.0.0)", "maven")
        )

    def test_unknown_ecosystem_or_unrecognized_suffix_fails_closed(self):
        self.assertFalse(
            range_expression_supported("< 1.2.3-rc1", "unknown")
        )
        self.assertFalse(
            version_matches_range("1.2.3", "< latest", "npm")
        )
        self.assertFalse(
            version_matches_range("1.2.3", "workspace:*", "npm")
        )

    def test_full_snapshot_reports_range_coverage_without_claiming_safety(self):
        status = catalog_status()
        total = (
            int(status["supported_range_count"])
            + int(status["partially_supported_range_count"])
            + int(status["unsupported_range_count"])
        )
        self.assertGreater(total, 0)
        ratio = (
            int(status["supported_range_count"])
            + int(status["partially_supported_range_count"])
        ) / total
        self.assertGreater(ratio, 0.90)
        self.assertFalse(status["catalog_is_exhaustive"])
        self.assertFalse(status["absence_of_match_means_safe"])
        print(
            "DEPENDENCY_RANGE_COVERAGE "
            + json.dumps(
                {
                    "full": status["supported_range_count"],
                    "partial": status["partially_supported_range_count"],
                    "none": status["unsupported_range_count"],
                    "ratio": round(ratio, 6),
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    unittest.main()
