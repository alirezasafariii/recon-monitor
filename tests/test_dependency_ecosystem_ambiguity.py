from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from dependency_advisory_matcher import (
    advisories_sha256,
    catalog_status,
    match_technologies,
    match_versioned_technology,
)


def _entry(
    advisory_id: str,
    *,
    product: str,
    ecosystem: str,
    affected: str = "< 2.0.0",
) -> dict:
    return {
        "id": advisory_id,
        "cve": "",
        "product": product,
        "ecosystem": ecosystem,
        "aliases": [product],
        "source_type": "github_reviewed_advisory",
        "review_status": "reviewed",
        "source_url": f"https://github.com/advisories/{advisory_id}",
        "severity": "high",
        "published_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "affected_ranges": [affected],
        "patched_versions": ["2.0.0"],
        "withdrawn_at": "",
    }


class DependencyEcosystemAmbiguityTests(unittest.TestCase):
    def _catalog(self, root: Path) -> Path:
        advisories = [
            _entry(
                "GHSA-2345-6789-cfgh",
                product="shared-lib",
                ecosystem="npm",
            ),
            _entry(
                "GHSA-3456-789c-fghj",
                product="shared-lib",
                ecosystem="pip",
            ),
            _entry(
                "GHSA-4567-89cf-ghjm",
                product="solo-lib",
                ecosystem="npm",
            ),
        ]
        payload = {
            "version": "2.0.0",
            "generated_at": "2026-09-18T00:00:00Z",
            "completeness": "test_snapshot",
            "runtime_role": "positive_match_only",
            "source_snapshot": {
                "sync_complete": True,
                "scope": "test",
                "page_count": 1,
                "source_advisory_count": 3,
            },
            "advisories": advisories,
            "integrity": {
                "algorithm": "sha256",
                "advisories_sha256": advisories_sha256(advisories),
            },
        }
        path = root / "catalog.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_ambiguous_alias_without_ecosystem_hint_abstains(self):
        with tempfile.TemporaryDirectory() as td:
            catalog = self._catalog(Path(td))
            outcome = match_versioned_technology(
                "shared-lib:1.5.0",
                catalog_path=catalog,
            )
            self.assertTrue(outcome["version_exact"])
            self.assertTrue(outcome["identity_ambiguous"])
            self.assertTrue(
                outcome["abstained_due_to_ecosystem_ambiguity"]
            )
            self.assertEqual(
                outcome["candidate_ecosystems"],
                ["npm", "pip"],
            )
            self.assertEqual(outcome["matches"], [])

    def test_explicit_ecosystem_hint_filters_to_one_identity(self):
        with tempfile.TemporaryDirectory() as td:
            catalog = self._catalog(Path(td))
            outcome = match_versioned_technology(
                "shared-lib:1.5.0",
                catalog_path=catalog,
                ecosystem_hint="npm",
            )
            self.assertFalse(outcome["identity_ambiguous"])
            self.assertFalse(
                outcome["abstained_due_to_ecosystem_ambiguity"]
            )
            self.assertEqual(len(outcome["matches"]), 1)
            self.assertEqual(outcome["matches"][0]["ecosystem"], "npm")
            self.assertEqual(
                outcome["matches"][0]["advisory_id"],
                "GHSA-2345-6789-CFGH",
            )

    def test_explicit_default_alias_registry_can_resolve_known_fingerprint(self):
        outcome = match_versioned_technology("jQuery:3.4.1")
        self.assertFalse(outcome["identity_ambiguous"])
        self.assertEqual(
            outcome["ecosystem_resolved_by_alias_registry"],
            "npm",
        )
        self.assertIn(
            "GHSA-GXR4-XJJ5-5PX2",
            {row["advisory_id"] for row in outcome["matches"]},
        )

    def test_mapping_observation_can_carry_ecosystem_hint(self):
        with tempfile.TemporaryDirectory() as td:
            catalog = self._catalog(Path(td))
            outcome = match_technologies(
                [
                    {
                        "technology": "shared-lib:1.5.0",
                        "ecosystem": "pip",
                    }
                ],
                catalog_path=catalog,
            )
            self.assertEqual(outcome["match_count"], 1)
            self.assertEqual(
                outcome["ecosystem_ambiguity_abstention_count"],
                0,
            )
            self.assertEqual(outcome["matches"][0]["ecosystem"], "pip")
            self.assertEqual(
                outcome["versioned_components"][0]["ecosystem_hint"],
                "pip",
            )

    def test_plain_ambiguous_observation_is_reported_as_abstention(self):
        with tempfile.TemporaryDirectory() as td:
            catalog = self._catalog(Path(td))
            outcome = match_technologies(
                ["shared-lib:1.5.0"],
                catalog_path=catalog,
            )
            self.assertEqual(outcome["match_count"], 0)
            self.assertEqual(
                outcome["ecosystem_ambiguity_abstention_count"],
                1,
            )
            abstention = outcome["ecosystem_ambiguity_abstentions"][0]
            self.assertEqual(
                abstention["candidate_ecosystems"],
                ["npm", "pip"],
            )

    def test_unambiguous_alias_retains_existing_positive_matching(self):
        with tempfile.TemporaryDirectory() as td:
            catalog = self._catalog(Path(td))
            outcome = match_versioned_technology(
                "solo-lib:1.5.0",
                catalog_path=catalog,
            )
            self.assertFalse(outcome["identity_ambiguous"])
            self.assertEqual(outcome["candidate_ecosystems"], ["npm"])
            self.assertEqual(len(outcome["matches"]), 1)
            self.assertEqual(outcome["matches"][0]["ecosystem"], "npm")

    def test_catalog_status_exposes_cross_ecosystem_alias_pressure(self):
        with tempfile.TemporaryDirectory() as td:
            catalog = self._catalog(Path(td))
            status = catalog_status(catalog)
            self.assertEqual(
                status["cross_ecosystem_ambiguous_alias_count"],
                1,
            )
            self.assertIn(
                "shared lib",
                status["cross_ecosystem_ambiguous_alias_sample"],
            )
            self.assertFalse(status["catalog_is_exhaustive"])
            self.assertFalse(status["absence_of_match_means_safe"])


if __name__ == "__main__":
    unittest.main()
