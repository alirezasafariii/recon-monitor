from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from dependency_range_coverage import (
    audit_catalog,
    classify_range_syntax,
    unsupported_reason,
)


class DependencyRangeCoverageTests(unittest.TestCase):
    def test_syntax_classification_is_deterministic(self):
        self.assertEqual(classify_range_syntax("^1.2.3", "npm"), "caret")
        self.assertEqual(classify_range_syntax("~= 1.4.5", "pip"), "pep440_compatible")
        self.assertEqual(classify_range_syntax("~> 2.2.0", "rubygems"), "rubygems_pessimistic")
        self.assertEqual(classify_range_syntax("[1.0,2.0)", "maven"), "maven_interval")
        self.assertEqual(classify_range_syntax(">=1,<2 || >=3,<4", "npm"), "union")

    def test_unsupported_reason_identifies_noncanonical_boundaries(self):
        self.assertEqual(
            unsupported_reason("< 0.8.3ubuntu7.5", "pip"),
            "distro_revision_outside_pep440",
        )
        self.assertEqual(
            unsupported_reason("< 2020-09-14", "composer"),
            "date_version_outside_canonical_ecosystem_grammar",
        )
        self.assertEqual(
            unsupported_reason("<= 2024.92.x-dev", "composer"),
            "composer_branch_alias",
        )

    def test_audit_preserves_partial_and_none_counts(self):
        payload = {
            "advisories": [
                {
                    "ecosystem": "npm",
                    "affected_ranges": [
                        ">= 1.0.0, < 2.0.0",
                        ">= 1.0.0, < 2.0.0 || bananas",
                        "workspace:*",
                    ],
                }
            ]
        }
        report = audit_catalog(payload, top=10)
        self.assertEqual(report["total_range_count"], 3)
        self.assertEqual(report["full_count"], 1)
        self.assertEqual(report["partial_count"], 1)
        self.assertEqual(report["none_count"], 1)
        self.assertTrue(report["fail_closed"])
        self.assertFalse(report["catalog_miss_means_safe"])


if __name__ == "__main__":
    unittest.main()
