from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_evidence_scope import scope_family_evidence
from family_specs.registry import (
    MIGRATED_FAMILIES,
    get_detection_spec,
    validate_family_spec_registry,
)
from family_specs.taxonomy_attribution import evaluate_taxonomy_attribution
from researcher_logic import researcher_logic_for_family, validate_researcher_logic


EXPECTED_FROZEN_FAMILIES = (
    "broken_object_authorization",
    "broken_function_authorization",
    "mass_assignment",
    "ssrf",
    "file_upload",
    "path_traversal",
    "sql_injection",
    "dom_xss",
    "cors_misconfiguration",
    "authentication_session",
    "open_redirect",
    "postmessage_trust",
    "graphql_authorization",
    "account_enumeration",
    "information_disclosure",
    "source_map_exposure",
    "secret_exposure",
)


class PreMainAnalyzerMergeGateTests(unittest.TestCase):
    def test_feature_freeze_family_set_is_explicit(self):
        self.assertEqual(MIGRATED_FAMILIES, EXPECTED_FROZEN_FAMILIES)

    def test_canonical_registry_and_researcher_logic_are_drift_free(self):
        self.assertEqual(validate_family_spec_registry(), [])
        self.assertEqual(validate_researcher_logic(), [])

    def test_external_knowledge_never_counts_as_target_evidence(self):
        for family in MIGRATED_FAMILIES:
            spec = get_detection_spec(family)
            self.assertTrue(spec.standard.writeups, family)
            self.assertTrue(
                all(not item.counts_as_target_evidence for item in spec.standard.writeups),
                family,
            )
            logic = researcher_logic_for_family(family)
            self.assertEqual(
                logic["evidence_policy"],
                "advisory_only_non_evidentiary",
                family,
            )

    def test_taxonomy_is_post_admission_metadata_only(self):
        for family in MIGRATED_FAMILIES:
            spec = get_detection_spec(family)
            decisive = {
                signal
                for group in (*spec.promotion_required, *spec.confirmation_required)
                for signal in group
            }
            hidden = evaluate_taxonomy_attribution(
                spec,
                admitted=False,
                decisive_signals=decisive,
            )
            self.assertEqual(hidden["role"], "post_admission_metadata_only", family)
            self.assertFalse(hidden["counts_as_target_evidence"], family)
            self.assertFalse(any(hidden["assigned_taxonomy"].values()), family)

            policy = spec.taxonomy_attribution_policy()
            expected = {
                (namespace, ref)
                for namespace, refs in spec.taxonomy().items()
                for ref in refs
            }
            actual = {(item["namespace"], item["ref"]) for item in policy}
            self.assertEqual(actual, expected, family)
            self.assertEqual(len(actual), len(policy), family)
            for item in policy:
                self.assertFalse(item["counts_as_target_evidence"], (family, item))
                if item["namespace"] in {"wstg", "capec"}:
                    self.assertFalse(item["auto_assign"], (family, item))
                if item["mapping"] == "methodology":
                    self.assertFalse(item["auto_assign"], (family, item))

    def test_explicit_cross_family_evidence_is_quarantined(self):
        families = list(MIGRATED_FAMILIES)
        for index, family in enumerate(families):
            other = families[(index + 1) % len(families)]
            packet = scope_family_evidence(
                family,
                [
                    {
                        "type": "synthetic_decisive_signal",
                        "source_group": "merge_gate",
                        "family_scope": other,
                    }
                ],
                annotate_unscoped=False,
                channel="pre_main_merge_gate",
            )
            self.assertEqual(packet["accepted_count"], 0, family)
            self.assertEqual(packet["rejected_count"], 1, family)
            self.assertEqual(
                packet["rejected"][0]["scope_rejection_reason"],
                "cross_family_evidence",
                family,
            )

    def test_newly_persistable_unscoped_evidence_gets_family_namespace(self):
        for family in MIGRATED_FAMILIES:
            packet = scope_family_evidence(
                family,
                [{"type": "synthetic_signal", "source_group": "merge_gate"}],
                annotate_unscoped=True,
                channel="pre_main_merge_gate",
            )
            item = packet["accepted"][0]
            self.assertEqual(item["family_scope"], family)
            self.assertEqual(item["evidence_namespace"], f"family:{family}")

    def test_manifest_tracks_permanent_final_analyzer_gate_files(self):
        manifest = (ROOT / "MANIFEST.sha256").read_text(encoding="utf-8")
        required = {
            "app/family_evidence_scope.py",
            "app/researcher_logic.py",
            "app/family_specs/taxonomy_attribution.py",
            "tests/test_final_taxonomy_attribution.py",
            "tests/test_pre_main_analyzer_merge_gate.py",
        }
        for path in required:
            self.assertIn(f"  {path}\n", manifest, path)


if __name__ == "__main__":
    unittest.main()
