from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_evidence_scope import scope_family_evidence
from family_specs.registry import MIGRATED_FAMILIES
from hypothesis_admission import assess_admission
from researcher_logic import researcher_logic_for_family, validate_researcher_logic


class Final633GapIntegrationTests(unittest.TestCase):
    def test_researcher_logic_covers_migrated_specs_without_provenance_keys(self):
        self.assertEqual(validate_researcher_logic(), [])
        for family in MIGRATED_FAMILIES:
            logic = researcher_logic_for_family(family)
            self.assertEqual(logic["role"], "reasoning_guidance_only_not_target_evidence")
            self.assertTrue(logic["security_principle"])
            self.assertTrue(logic["decisive_condition_signals"])
            serialized = repr(logic).lower()
            self.assertNotIn("'source':", serialized)
            self.assertNotIn("'ref':", serialized)
            self.assertNotIn("'url':", serialized)
            self.assertNotIn("counts_as_target_evidence", serialized)

    def test_cross_family_scoped_evidence_cannot_admit(self):
        decision = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request", "family_scope": "ssrf"},
            {"type": "sql_query_sink", "source_group": "sink", "family_scope": "ssrf"},
            {"type": "sql_query_influence_observed", "source_group": "behavior", "family_scope": "ssrf"},
        ])
        self.assertFalse(decision["admitted"])
        self.assertEqual(decision["independent_sources"], 0)
        self.assertEqual(decision["evidence_scope"]["rejected_cross_family_support"], 3)

    def test_matching_scope_and_legacy_unscoped_evidence_remain_compatible(self):
        matching = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request", "family_scope": "sql_injection"},
            {"type": "sql_query_sink", "source_group": "sink", "family_scope": "sql_injection"},
            {"type": "sql_query_influence_observed", "source_group": "behavior", "family_scope": "sql_injection"},
        ])
        legacy = assess_admission("sql_injection", [
            {"type": "sql_input", "source_group": "request"},
            {"type": "sql_query_sink", "source_group": "sink"},
            {"type": "sql_query_influence_observed", "source_group": "behavior"},
        ])
        self.assertTrue(matching["admitted"])
        self.assertTrue(legacy["admitted"])
        self.assertIn("researcher_logic", matching)
        self.assertEqual(matching["researcher_logic"]["evidence_policy"], "advisory_only_non_evidentiary")

    def test_persistence_scope_annotation_is_deterministic(self):
        packet = scope_family_evidence(
            "ssrf",
            [{"type": "server_fetch_observed", "source_group": "controlled"}],
            annotate_unscoped=True,
            channel="hypothesis_persistence",
        )
        self.assertEqual(packet["rejected_count"], 0)
        item = packet["accepted"][0]
        self.assertEqual(item["family_scope"], "ssrf")
        self.assertEqual(item["evidence_namespace"], "family:ssrf")
        self.assertEqual(item["evidence_scope_channel"], "hypothesis_persistence")

    def test_explicit_cross_family_scope_is_quarantined_not_rebound(self):
        packet = scope_family_evidence(
            "broken_object_authorization",
            [{"type": "unauthorized_object_success", "family_scope": "broken_function_authorization"}],
            annotate_unscoped=True,
            channel="hypothesis_persistence",
        )
        self.assertEqual(packet["accepted_count"], 0)
        self.assertEqual(packet["rejected_count"], 1)
        self.assertEqual(packet["rejected"][0]["scope_rejection_reason"], "cross_family_evidence")


if __name__ == "__main__":
    unittest.main()
