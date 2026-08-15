from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import v7_literal_source_research as research


class V7LiteralSourceResearchTests(unittest.TestCase):
    def test_frozen_alias_does_not_override_exact_root_identity(self) -> None:
        row = {
            "source_root": "GHSA-xcvf-46f4-xwxf",
            "canonical_advisory_url": "https://github.com/go-chi/chi/security/advisories/GHSA-vrw8-fxc6-2r93",
            "references": [
                "https://github.com/advisories/GHSA-xcvf-46f4-xwxf",
                "https://github.com/advisories/GHSA-vrw8-fxc6-2r93",
            ],
        }
        with self.assertRaisesRegex(RuntimeError, "GHSA source identity drift"):
            research._validate_observed_ghsa(
                row,
                row["source_root"],
                "GHSA-vrw8-fxc6-2r93",
                family="open_redirect",
            )

    def test_unfrozen_alias_is_rejected_fail_closed(self) -> None:
        row = {
            "source_root": "GHSA-xcvf-46f4-xwxf",
            "canonical_advisory_url": "https://github.com/advisories/GHSA-xcvf-46f4-xwxf",
            "references": [],
        }
        with self.assertRaisesRegex(RuntimeError, "GHSA source identity drift"):
            research._validate_observed_ghsa(
                row,
                row["source_root"],
                "GHSA-vrw8-fxc6-2r93",
                family="open_redirect",
            )

    def test_same_root_is_exact_match_and_not_alias_resolution(self) -> None:
        row = {
            "source_root": "GHSA-aaaa-bbbb-cccc",
            "canonical_advisory_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        }
        result = research._validate_observed_ghsa(
            row,
            row["source_root"],
            "GHSA-aaaa-bbbb-cccc",
            family="example",
        )
        self.assertFalse(result["alias_used"])
        self.assertTrue(result["exact_frozen_root_match"])
        self.assertEqual(result["observed_ghsa_id"], "GHSA-aaaa-bbbb-cccc")

    def test_frozen_ghsa_root_is_authoritative_over_canonical_reference(self) -> None:
        root = "GHSA-xcvf-46f4-xwxf"
        wrong_reference = "https://github.com/advisories/GHSA-vrw8-fxc6-2r93"
        self.assertEqual(
            f"https://api.github.com/advisories/{root}",
            f"https://api.github.com/advisories/{root}" if research.GHSA_RE.fullmatch(root) else research._api_url(wrong_reference),
        )


if __name__ == "__main__":
    unittest.main()
