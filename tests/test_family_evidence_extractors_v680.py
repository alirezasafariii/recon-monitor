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
        admission_version = tuple(int(part) for part in ADMISSION_ENGINE_VERSION.split("."))
        self.assertGreaterEqual(admission_version, (2, 4, 0))
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
        evidence = [
            ev("input_parameter", "input", "sql_injection"),
            ev("nosql_query_surface", "query", "sql_injection"),
            ev("operator_injection_observed", "behavior", "sql_injection"),
        ]
        scoped = scope_family_evidence("nosql_injection", evidence, channel="alert")
        self.assertEqual(scoped["support"], [])
        self.assertFalse(assess_admission("nosql_injection", scoped["support"], scoped["contradict"])["admitted"])

    def test_filter_evidence_rejects_cross_family_namespace(self) -> None:
        item = ev("input_parameter", "input", "sql_injection")
        item["evidence_namespace"] = "family:sql_injection"
        accepted, rejected = filter_evidence_for_family("nosql_injection", [item])
        self.assertEqual(accepted, [])
        self.assertEqual(len(rejected), 1)

    def test_evidence_role_distinguishes_identity_condition_blocker_and_surface(self) -> None:
        self.assertEqual(evidence_role("sql_injection", "input_parameter"), "identity")
        self.assertEqual(evidence_role("sql_injection", "database_error_observed"), "condition")
        self.assertEqual(evidence_role("sql_injection", "parameterized_query"), "blocker")
        self.assertEqual(evidence_role("sql_injection", "generic_observation"), "surface")

    def test_family_reasoning_uses_family_scoped_evidence(self) -> None:
        packet = scope_family_evidence(
            "sql_injection",
            [
                ev("input_parameter", "input"),
                ev("sql_query_surface", "sql"),
                ev("database_error_observed", "behavior"),
            ],
            channel="alert",
        )
        result = reason_family("sql_injection", packet["support"], packet["contradict"])
        self.assertTrue(result["admitted"])
        self.assertGreater(result["family_fit"], 0.8)

    def test_condition_without_identity_does_not_admit(self) -> None:
        packet = scope_family_evidence(
            "sql_injection",
            [ev("database_error_observed", "behavior")],
            channel="alert",
        )
        result = reason_family("sql_injection", packet["support"], packet["contradict"])
        self.assertFalse(result["admitted"])

    def test_blocker_survives_extractor_and_reasoner(self) -> None:
        packet = scope_family_evidence(
            "sql_injection",
            [
                ev("input_parameter", "input"),
                ev("sql_query_surface", "sql"),
                ev("database_error_observed", "behavior"),
            ],
            [ev("parameterized_query", "control")],
            channel="alert",
        )
        self.assertIn("parameterized_query", {row["type"] for row in packet["contradict"]})
        result = reason_family("sql_injection", packet["support"], packet["contradict"])
        self.assertFalse(result["admitted"])

    def test_unrelated_family_signal_is_not_admitted_by_shared_names(self) -> None:
        raw = [
            ev("input_parameter", "input"),
            ev("sql_query_surface", "sql"),
            ev("operator_injection_observed", "behavior"),
        ]
        sql = scope_family_evidence("sql_injection", raw, channel="alert")
        nosql = scope_family_evidence("nosql_injection", raw, channel="alert")
        self.assertFalse(assess_admission("sql_injection", sql["support"], sql["contradict"])["admitted"])
        self.assertFalse(assess_admission("nosql_injection", nosql["support"], nosql["contradict"])["admitted"])


if __name__ == "__main__":
    unittest.main()
