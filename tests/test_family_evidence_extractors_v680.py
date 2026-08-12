from __future__ import annotations

import unittest

from analysis_ranking import RANKING_ENGINE_VERSION, rank_families
from family_evidence_extractors import (
    FAMILY_EVIDENCE_EXTRACTOR_PROFILES,
    FAMILY_EVIDENCE_EXTRACTOR_VERSION,
    FAMILY_EXTRACTION_IDENTITY_GATES,
    evidence_role,
    filter_evidence_for_family,
    scope_family_evidence,
)
from family_reasoners import FAMILY_IDENTITY_GATES, FAMILY_REASONER_VERSION, reason_family
from hypothesis_admission import ADMISSION_ENGINE_VERSION, FAMILY_ADMISSION_POLICIES, assess_admission


def ev(kind: str, source: str, family_scope: str = "") -> dict[str, str]:
    item = {"type": kind, "source": source, "source_group": source, "text": kind}
    if family_scope:
        item["family_scope"] = family_scope
    return item


class FamilyEvidenceExtractors680Tests(unittest.TestCase):
    def test_registry_exactly_covers_every_family_with_unique_strategy(self) -> None:
        self.assertEqual(FAMILY_EVIDENCE_EXTRACTOR_VERSION, "1.0.0")
        self.assertEqual(FAMILY_REASONER_VERSION, "1.1.0")
        self.assertEqual(RANKING_ENGINE_VERSION, "2.1.0")
        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.4.0")
        self.assertEqual(set(FAMILY_EVIDENCE_EXTRACTOR_PROFILES), set(FAMILY_ADMISSION_POLICIES))
        self.assertGreaterEqual(len(FAMILY_EVIDENCE_EXTRACTOR_PROFILES), 31)
        strategies = [profile.strategy for profile in FAMILY_EVIDENCE_EXTRACTOR_PROFILES.values()]
        self.assertEqual(len(strategies), len(set(strategies)))
        self.assertTrue(all(profile.channels for profile in FAMILY_EVIDENCE_EXTRACTOR_PROFILES.values()))

    def test_extractor_identity_gates_cannot_drift_from_reasoners(self) -> None:
        self.assertEqual(FAMILY_EXTRACTION_IDENTITY_GATES, FAMILY_IDENTITY_GATES)

    def test_shared_signal_is_namespaced_per_family(self) -> None:
        raw = [ev("input_parameter", "endpoint_schema")]
        sql = scope_family_evidence("sql_injection", raw, channel="alert")
        nosql = scope_family_evidence("nosql_injection", raw, channel="alert")
        self.assertEqual(sql["support"][0]["family_scope"], "sql_injection")
        self.assertEqual(nosql["support"][0]["family_scope"], "nosql_injection")
        self.assertNotEqual(sql["support"][0]["evidence_namespace"], nosql["support"][0]["evidence_namespace"])
        self.assertEqual(sql["extraction_state"], "surface_only")
        self.assertEqual(nosql["extraction_state"], "surface_only")

    def test_pre_scoped_evidence_cannot_be_reassigned(self) -> None:
        packet = scope_family_evidence(
            "sql_injection",
            [ev("input_parameter", "input"), ev("sql_query_surface", "sql")],
            channel="alert",
        )
        reassigned = scope_family_evidence("nosql_injection", packet["support"], channel="alert")
        self.assertEqual(reassigned["support"], [])
        self.assertEqual(reassigned["rejected_cross_family_count"], 2)

    def test_admission_ignores_complete_evidence_scoped_to_other_family(self) -> None:
        wrong_scope = [
            ev("input_parameter", "input", "nosql_injection"),
            ev("sql_query_surface", "sql", "nosql_injection"),
            ev("query_structure_influence", "behavior", "nosql_injection"),
        ]
        self.assertFalse(assess_admission("sql_injection", wrong_scope)["admitted"])
        legacy_unscoped = [
            ev("input_parameter", "input"),
            ev("sql_query_surface", "sql"),
            ev("query_structure_influence", "behavior"),
        ]
        self.assertTrue(assess_admission("sql_injection", legacy_unscoped)["admitted"])

    def test_reasoner_ignores_other_family_scope_even_for_shared_signal_names(self) -> None:
        sql = scope_family_evidence(
            "sql_injection",
            [
                ev("input_parameter", "input"),
                ev("sql_query_surface", "sql"),
                ev("query_structure_influence", "behavior"),
            ],
            channel="candidate",
        )["support"]
        nosql = scope_family_evidence(
            "nosql_injection",
            [
                ev("input_parameter", "input2"),
                ev("nosql_query_surface", "nosql"),
                ev("nosql_operator_accepted", "behavior2"),
            ],
            channel="candidate",
        )["support"]
        combined = [*sql, *nosql]
        sql_row = reason_family("sql_injection", combined, [])
        nosql_row = reason_family("nosql_injection", combined, [])
        self.assertTrue(sql_row["assessment"]["admitted"])
        self.assertTrue(nosql_row["assessment"]["admitted"])
        self.assertEqual(sql_row["condition_hits"], ["query_structure_influence"])
        self.assertEqual(nosql_row["condition_hits"], ["nosql_operator_accepted"])
        self.assertEqual(len(filter_evidence_for_family("sql_injection", combined)), 3)
        self.assertEqual(len(filter_evidence_for_family("nosql_injection", combined)), 3)

    def test_combined_scoped_dossier_keeps_family_rankings_independent(self) -> None:
        sql = scope_family_evidence(
            "sql_injection",
            [ev("input_parameter", "i1"), ev("sql_query_surface", "i2"), ev("query_structure_influence", "i3")],
        )["support"]
        bola = scope_family_evidence(
            "broken_object_authorization",
            [ev("object_identifier", "b1"), ev("object_operation", "b2"), ev("cross_identity_object_access", "b3")],
        )["support"]
        rows = {row["family"]: row for row in rank_families([*sql, *bola], [])}
        self.assertTrue(rows["sql_injection"]["assessment"]["admitted"])
        self.assertTrue(rows["broken_object_authorization"]["assessment"]["admitted"])
        self.assertEqual(rows["nosql_injection"]["family_fit_score"], 0.0)
        self.assertEqual(rows["broken_function_authorization"]["family_fit_score"], 0.0)

    def test_signal_roles_are_derived_from_each_family_policy(self) -> None:
        for family, policy in FAMILY_ADMISSION_POLICIES.items():
            required = list(policy.get("required", []))
            condition_signal = sorted(required[-1])[0]
            with self.subTest(family=family, condition_signal=condition_signal):
                self.assertEqual(evidence_role(family, condition_signal), "condition")
            for index in FAMILY_EXTRACTION_IDENTITY_GATES[family]:
                identity_signal = sorted(required[index])[0]
                if index != len(required) - 1:
                    with self.subTest(family=family, identity_signal=identity_signal):
                        self.assertEqual(evidence_role(family, identity_signal), "identity")

    def test_blocking_controls_are_scoped_and_tagged_as_controls(self) -> None:
        packet = scope_family_evidence(
            "broken_function_authorization",
            [ev("privileged_function", "surface"), ev("state_change", "operation")],
            [ev("lower_privilege_denied", "control")],
        )
        self.assertEqual(packet["contradict"][0]["signal_role"], "control")
        self.assertTrue(packet["contradict"][0]["counts_for_family"])
        self.assertEqual(packet["contradict"][0]["family_scope"], "broken_function_authorization")
        self.assertFalse(assess_admission("broken_function_authorization", packet["support"], packet["contradict"])["admitted"])

    def test_contextual_surface_is_preserved_without_counting_for_family(self) -> None:
        packet = scope_family_evidence(
            "sql_injection",
            [ev("semantic_marker", "semantic")],
        )
        self.assertEqual(packet["support"][0]["signal_role"], "surface")
        self.assertFalse(packet["support"][0]["counts_for_family"])
        self.assertEqual(packet["extraction_state"], "surface_only")


if __name__ == "__main__":
    unittest.main()
