from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from bug_candidates import BUG_FAMILIES
from family_reasoning import (
    FAMILY_ORDER,
    FAMILY_REASONING,
    FAMILY_REASONING_RULE_VERSION,
    FAMILY_REASONING_VERSION,
    admission_policy_map,
    candidate_evidence_schema_map,
    case_requirement_map,
    catalog_audit,
    confirmation_gaps,
    validation_level_for_family,
)
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission


class FamilyReasoningV867Tests(unittest.TestCase):
    def test_catalog_exactly_covers_all_candidate_families(self):
        self.assertEqual(len(BUG_FAMILIES), 21)
        self.assertEqual(set(BUG_FAMILIES), set(FAMILY_ORDER))
        self.assertEqual(set(BUG_FAMILIES), set(FAMILY_REASONING))
        audit = catalog_audit(BUG_FAMILIES)
        self.assertTrue(audit["complete"], audit)
        self.assertEqual(audit["actual_count"], 21)
        self.assertEqual(audit["missing"], [])
        self.assertEqual(audit["unexpected"], [])
        self.assertEqual(audit["invalid"], [])

    def test_admission_engine_uses_catalog_for_every_family(self):
        generated = admission_policy_map()
        self.assertEqual(set(FAMILY_ADMISSION_POLICIES), set(BUG_FAMILIES))
        self.assertEqual(set(generated), set(BUG_FAMILIES))
        for family in BUG_FAMILIES:
            self.assertNotEqual(FAMILY_ADMISSION_POLICIES[family]["label"], "existing-family-gate")
            self.assertTrue(FAMILY_ADMISSION_POLICIES[family]["required"], family)
            self.assertTrue(FAMILY_ADMISSION_POLICIES[family]["confirmation_required"], family)

    def test_minimum_promotion_contract_is_satisfiable_for_every_family(self):
        for family, policy in FAMILY_ADMISSION_POLICIES.items():
            support = []
            for index, group in enumerate(policy["required"], start=1):
                support.append({
                    "type": sorted(group)[0],
                    "source": f"source-{index}",
                    "source_group": f"group-{index}",
                    "text": f"synthetic contract evidence {index}",
                })
            result = assess_admission(family, support, [])
            self.assertTrue(result["admitted"], (family, result))
            self.assertEqual(result["required_missing"], [], family)
            self.assertEqual(result["family_reasoning_version"], FAMILY_REASONING_VERSION)
            self.assertEqual(result["family_reasoning_rule_version"], FAMILY_REASONING_RULE_VERSION)
            self.assertEqual(result["validation_level"], policy["validation_level"])

    def test_removing_one_required_group_retains_hidden_recall(self):
        for family, policy in FAMILY_ADMISSION_POLICIES.items():
            groups = list(policy["required"])
            if len(groups) < 2:
                continue
            # When decisive evidence is intentionally allowed to satisfy
            # weaker structural groups, choose a preceding-group signal that
            # does not also satisfy the omitted final group. This preserves the
            # actual invariant under test: without the final required condition,
            # the hypothesis must stay hidden.
            omitted_group = set(groups[-1])
            support = []
            for index, group in enumerate(groups[:-1], start=1):
                candidates = set(group) - omitted_group
                chosen = sorted(candidates or set(group))[0]
                support.append({
                    "type": chosen,
                    "source": f"source-{index}",
                    "source_group": f"group-{index}",
                })
            result = assess_admission(family, support, [])
            self.assertFalse(result["admitted"], family)
            self.assertIn(result["state"], {"shadow_signal", "shadow_partial"})
            self.assertTrue(result["required_missing"], family)

    def test_blocking_contradiction_keeps_signal_hidden_unless_overridden(self):
        checked = 0
        for family, policy in FAMILY_ADMISSION_POLICIES.items():
            blockers = set(policy.get("blocking_contradictions", set()))
            overrides = set(policy.get("override_signals", set()))
            if not blockers:
                continue
            chosen = [sorted(group)[0] for group in policy["required"]]
            # Some families (notably BOLA) require a decisive target-boundary
            # failure as part of promotion. That evidence is intentionally an
            # override, so an otherwise blocking enforcement clue must not erase it.
            if set(chosen) & overrides:
                continue
            support = [
                {"type": evidence_type, "source": f"source-{index}", "source_group": f"group-{index}"}
                for index, evidence_type in enumerate(chosen, start=1)
            ]
            result = assess_admission(
                family,
                support,
                [{"type": sorted(blockers)[0], "source": "enforcement"}],
            )
            self.assertFalse(result["admitted"], family)
            self.assertEqual(result["state"], "shadow_contradicted", family)
            checked += 1
        self.assertGreater(checked, 0)

    def test_override_signal_can_outweigh_blocking_context(self):
        policy = FAMILY_ADMISSION_POLICIES["broken_object_authorization"]
        support = [
            {"type": "object_identifier", "source": "schema", "source_group": "object"},
            {"type": "object_operation", "source": "endpoint", "source_group": "operation"},
            {"type": "unauthorized_object_response", "source": "stored_context", "source_group": "authorization"},
        ]
        result = assess_admission(
            "broken_object_authorization",
            support,
            [{"type": sorted(policy["blocking_contradictions"])[0], "source": "enforcement"}],
        )
        self.assertTrue(result["admitted"])
        self.assertIn("unauthorized_object_response", result["decisive_signals"])

    def test_unknown_family_fails_closed(self):
        result = assess_admission(
            "future_unknown_family",
            [
                {"type": "strong_signal", "source": "one"},
                {"type": "second_signal", "source": "two"},
            ],
        )
        self.assertFalse(result["admitted"])
        self.assertEqual(result["state"], "shadow_signal")
        self.assertEqual(result["policy"], "missing-family-reasoning-policy")

    def test_known_detector_spellings_are_in_the_canonical_contract(self):
        schemas = candidate_evidence_schema_map()
        mass = {value for group in schemas["mass_assignment"]["required_any"] for value in group}
        self.assertIn("privileged_property", mass)
        self.assertIn("write_method", mass)

        ssrf = {value for group in schemas["ssrf"]["required_any"] for value in group}
        self.assertIn("remote_destination", ssrf)
        self.assertIn("server_feature", ssrf)

        dom = {value for group in schemas["dom_xss"]["required_any"] for value in group}
        self.assertIn("dataflow_source", dom)
        self.assertIn("dataflow_sink", dom)

    def test_case_and_validation_contracts_cover_every_family(self):
        requirements = case_requirement_map()
        self.assertEqual(set(requirements), set(BUG_FAMILIES))
        for family in BUG_FAMILIES:
            self.assertTrue(requirements[family], family)
            self.assertIn(
                validation_level_for_family(family),
                {"offline", "passive_live", "controlled", "manual_only"},
                family,
            )

    def test_confirmation_is_stricter_than_promotion_context(self):
        self.assertTrue(confirmation_gaps("dom_xss", {"dataflow_source", "dataflow_sink"}))
        self.assertTrue(confirmation_gaps("ssrf", {"remote_destination", "server_feature"}))
        self.assertTrue(confirmation_gaps("business_logic", {"workflow_markers", "stateful_operation"}))
        self.assertTrue(confirmation_gaps("race_condition", {"workflow_markers", "stateful_operation", "single_use_semantics"}))
        self.assertEqual(confirmation_gaps("source_map_exposure", {"source_map_publicly_reachable"}), [])

    def test_confirmation_contracts_match_dedicated_analyzer_decisive_conditions(self):
        # DOM reachability alone is promotion context; an unsanitized executable
        # flow is the stricter confirmation condition.
        self.assertTrue(confirmation_gaps("dom_xss", {"runtime_dom_sink_reached"}))
        self.assertEqual(confirmation_gaps("dom_xss", {"unsanitized_dom_flow"}), [])

        # Missing origin validation alone is support; the untrusted message must
        # actually reach the sensitive consumer for confirmation.
        self.assertTrue(confirmation_gaps("postmessage_trust", {"origin_validation_absent"}))
        self.assertEqual(confirmation_gaps("postmessage_trust", {"untrusted_message_accepted"}), [])

        # Missing redirect validation alone is support; an external controlled
        # destination must actually be accepted.
        self.assertTrue(confirmation_gaps("open_redirect", {"navigation_validation_absent"}))
        self.assertEqual(confirmation_gaps("open_redirect", {"external_destination_accepted"}), [])

        # A user-controlled server fetch or correlated callback can promote SSRF,
        # but confirmation requires the destination trust boundary to fail.
        self.assertTrue(confirmation_gaps("ssrf", {"server_fetch_observed"}))
        self.assertTrue(confirmation_gaps("ssrf", {"controlled_callback_observed"}))
        self.assertEqual(confirmation_gaps("ssrf", {"destination_policy_bypass_observed"}), [])
        self.assertEqual(confirmation_gaps("ssrf", {"restricted_destination_accepted"}), [])

        # Acceptance of a controlled inert file can promote an upload finding;
        # confirmation requires validation bypass or execution-capable handling.
        self.assertTrue(confirmation_gaps("file_upload", {"unsafe_file_accepted"}))
        self.assertEqual(confirmation_gaps("file_upload", {"content_type_bypass_observed"}), [])
        self.assertEqual(confirmation_gaps("file_upload", {"executable_upload_observed"}), [])


if __name__ == "__main__":
    unittest.main()
