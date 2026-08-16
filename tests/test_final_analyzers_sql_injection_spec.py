from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_analyzers.sql_injection import (
    FALSE_POSITIVES,
    METHOD,
    SQL_INJECTION_SPEC,
    TAXONOMY,
    WRITEUPS,
)
from family_specs.knowledge_projection import (
    family_knowledge_projection,
    taxonomy_projection,
    validate_knowledge_projection,
)
from family_specs.registry import validate_family_spec_registry
from hypothesis_admission import assess_admission
from vulnerability_knowledge import BUILTIN_KNOWLEDGE, SPEC_KNOWLEDGE_ERRORS, taxonomy_for_family


class FinalAnalyzersSqlInjectionSpecTests(unittest.TestCase):
    family = "sql_injection"

    def test_sql_injection_spec_is_registry_backed_and_drift_free(self) -> None:
        self.assertEqual(validate_family_spec_registry(), [])
        self.assertFalse(SPEC_KNOWLEDGE_ERRORS)
        self.assertEqual(SQL_INJECTION_SPEC.family, self.family)
        self.assertEqual(SQL_INJECTION_SPEC.strategy, "sql_query_semantics")

    def test_official_taxonomy_and_real_world_lesson_are_canonical(self) -> None:
        self.assertIn("A05:2025 Injection", SQL_INJECTION_SPEC.standard.owasp)
        self.assertIn("WSTG-INPV-05", SQL_INJECTION_SPEC.standard.wstg)
        self.assertIn("CWE-89", SQL_INJECTION_SPEC.standard.cwe)
        self.assertTrue(SQL_INJECTION_SPEC.standard.writeups)
        self.assertTrue(
            all(not item.counts_as_target_evidence for item in SQL_INJECTION_SPEC.standard.writeups)
        )
        ids = {item.id for item in SQL_INJECTION_SPEC.standard.writeups}
        self.assertIn("ghsl-2026-059-chatwoot", ids)

    def test_analyzer_metadata_is_only_a_projection_of_the_spec(self) -> None:
        self.assertEqual(TAXONOMY, SQL_INJECTION_SPEC.taxonomy())
        self.assertEqual(METHOD, tuple(step.as_dict() for step in SQL_INJECTION_SPEC.standard.methodology))
        self.assertEqual(FALSE_POSITIVES, SQL_INJECTION_SPEC.standard.false_positive_checks)
        self.assertEqual(
            {str(item["id"]) for item in WRITEUPS},
            {item.id for item in SQL_INJECTION_SPEC.standard.writeups},
        )
        self.assertTrue(all(item.get("counts_as_target_evidence") is False for item in WRITEUPS))

    def test_knowledge_projection_comes_from_spec_and_is_non_evidentiary(self) -> None:
        self.assertEqual(validate_knowledge_projection(SQL_INJECTION_SPEC), [])
        self.assertEqual(taxonomy_for_family(self.family), taxonomy_projection(SQL_INJECTION_SPEC))
        self.assertEqual(
            BUILTIN_KNOWLEDGE[self.family],
            family_knowledge_projection(SQL_INJECTION_SPEC),
        )
        self.assertTrue(
            all(item.get("counts_as_target_evidence") is False for item in BUILTIN_KNOWLEDGE[self.family])
        )
        self.assertTrue(all("type" not in item for item in BUILTIN_KNOWLEDGE[self.family]))

    def test_input_and_query_sink_without_semantic_evidence_stays_hidden(self) -> None:
        result = assess_admission(
            self.family,
            [
                {"type": "sql_input", "source_group": "request-schema"},
                {"type": "sql_query_sink", "source_group": "server-query-context"},
            ],
        )
        self.assertFalse(result["admitted"])
        self.assertIn(result["state"], {"shadow_signal", "shadow_partial"})
        missing = [set(group) for group in result["required_missing"]]
        self.assertTrue(any("sql_query_influence_observed" in group for group in missing))

    def test_target_observed_unsafe_query_construction_can_promote(self) -> None:
        result = assess_admission(
            self.family,
            [
                {"type": "sql_input", "source_group": "request-schema"},
                {"type": "sql_query_sink", "source_group": "query-construction"},
                {
                    "type": "unsafe_sql_concatenation_observed",
                    "source_group": "stored-server-observation",
                },
            ],
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["state"], "admitted")
        self.assertGreaterEqual(result["independent_sources"], 2)

    def test_parameter_binding_blocks_non_decisive_unsafe_construction_signal(self) -> None:
        result = assess_admission(
            self.family,
            [
                {"type": "sql_input", "source_group": "request-schema"},
                {"type": "sql_query_sink", "source_group": "query-construction"},
                {
                    "type": "unsafe_sql_concatenation_observed",
                    "source_group": "stored-server-observation",
                },
            ],
            [
                {
                    "type": "query_parameter_binding_observed",
                    "source_group": "stored-query-control",
                }
            ],
        )
        self.assertFalse(result["admitted"])
        self.assertEqual(result["state"], "shadow_contradicted")
        self.assertIn("query_parameter_binding_observed", result["blocking_contradictions"])

    def test_standards_and_writeups_add_zero_admission_evidence(self) -> None:
        knowledge_like = [
            {"source": "OWASP", "ref": "A05:2025 Injection", "source_group": "knowledge"},
            {"source": "OWASP WSTG", "ref": "WSTG-INPV-05", "source_group": "knowledge"},
            {"source": "MITRE CWE", "ref": "CWE-89", "source_group": "knowledge"},
            {"source": "GitHub Security Lab", "ref": "GHSL-2026-059", "source_group": "knowledge"},
        ]
        result = assess_admission(self.family, knowledge_like)
        self.assertFalse(result["admitted"])
        self.assertEqual(result["independent_sources"], 0)


if __name__ == "__main__":
    unittest.main()
