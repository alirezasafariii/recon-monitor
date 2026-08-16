from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_analyzers.dom_xss import (
    DOM_XSS_FALSE_POSITIVE_CHECKS,
    DOM_XSS_METHOD,
    DOM_XSS_SPEC,
    DOM_XSS_TAXONOMY,
    DOM_XSS_WRITEUP_PATTERNS,
)
from family_specs.knowledge_projection import (
    family_knowledge_projection,
    taxonomy_projection,
    validate_knowledge_projection,
)
from family_specs.registry import MIGRATED_FAMILIES, validate_family_spec_registry
from hypothesis_admission import assess_admission
from vulnerability_knowledge import BUILTIN_KNOWLEDGE, SPEC_KNOWLEDGE_ERRORS, taxonomy_for_family


class FinalAnalyzersDomXssSpecTests(unittest.TestCase):
    family = "dom_xss"

    def test_dom_xss_is_registry_backed_and_drift_free(self) -> None:
        self.assertIn(self.family, MIGRATED_FAMILIES)
        self.assertEqual(validate_family_spec_registry(), [])
        self.assertFalse(SPEC_KNOWLEDGE_ERRORS)
        self.assertEqual(DOM_XSS_SPEC.family, self.family)
        self.assertEqual(DOM_XSS_SPEC.strategy, "dom_source_sink_runtime_boundary")

    def test_current_taxonomy_and_real_world_lessons_are_canonical(self) -> None:
        self.assertIn("A05:2025 Injection", DOM_XSS_SPEC.standard.owasp)
        self.assertIn("WSTG-CLNT-01", DOM_XSS_SPEC.standard.wstg)
        self.assertIn("CWE-79", DOM_XSS_SPEC.standard.cwe)
        self.assertIn("CAPEC-63", DOM_XSS_SPEC.standard.capec)
        ids = {item.id for item in DOM_XSS_SPEC.standard.writeups}
        self.assertIn("ghsl-2025-110-openlibrary-barcode-xss", ids)
        self.assertIn("ghsl-2026-030-nocodb-rendering", ids)
        self.assertTrue(all(not item.counts_as_target_evidence for item in DOM_XSS_SPEC.standard.writeups))

    def test_analyzer_metadata_is_only_a_projection_of_the_spec(self) -> None:
        self.assertEqual(DOM_XSS_TAXONOMY, DOM_XSS_SPEC.taxonomy())
        self.assertEqual(
            DOM_XSS_METHOD,
            tuple(step.as_dict() for step in DOM_XSS_SPEC.standard.methodology),
        )
        self.assertEqual(
            DOM_XSS_FALSE_POSITIVE_CHECKS,
            DOM_XSS_SPEC.standard.false_positive_checks,
        )
        self.assertEqual(
            {str(item["id"]) for item in DOM_XSS_WRITEUP_PATTERNS},
            {item.id for item in DOM_XSS_SPEC.standard.writeups},
        )
        self.assertTrue(
            all(item.get("counts_as_target_evidence") is False for item in DOM_XSS_WRITEUP_PATTERNS)
        )

    def test_knowledge_projection_comes_from_spec_and_is_non_evidentiary(self) -> None:
        self.assertEqual(validate_knowledge_projection(DOM_XSS_SPEC), [])
        self.assertEqual(taxonomy_for_family(self.family), taxonomy_projection(DOM_XSS_SPEC))
        self.assertEqual(
            BUILTIN_KNOWLEDGE[self.family],
            family_knowledge_projection(DOM_XSS_SPEC),
        )
        self.assertTrue(
            all(item.get("counts_as_target_evidence") is False for item in BUILTIN_KNOWLEDGE[self.family])
        )
        self.assertTrue(all("type" not in item for item in BUILTIN_KNOWLEDGE[self.family]))

    def test_source_and_sink_even_from_independent_roots_stay_hidden_without_runtime_condition(self) -> None:
        result = assess_admission(
            self.family,
            [
                {"type": "dataflow_source", "source_group": "static-source"},
                {"type": "dataflow_sink", "source_group": "static-sink"},
            ],
        )
        self.assertFalse(result["admitted"])
        self.assertIn(result["state"], {"shadow_signal", "shadow_partial"})
        missing = [set(group) for group in result["required_missing"]]
        self.assertIn({"unsanitized_dom_flow"}, missing)

    def test_runtime_reachability_without_unsanitized_condition_stays_hidden(self) -> None:
        result = assess_admission(
            self.family,
            [
                {"type": "dataflow_source", "source_group": "dom-static-flow"},
                {"type": "dataflow_sink", "source_group": "dom-static-flow"},
                {"type": "runtime_dom_sink_reached", "source_group": "dom-runtime"},
            ],
        )
        self.assertFalse(result["admitted"])
        self.assertTrue(result["required_missing"])
        self.assertNotIn("runtime_dom_sink_reached", result["decisive_signals"])

    def test_unsanitized_runtime_condition_can_promote_with_independent_target_roots(self) -> None:
        result = assess_admission(
            self.family,
            [
                {"type": "dataflow_source", "source_group": "dom-static-flow"},
                {"type": "dataflow_sink", "source_group": "dom-static-flow"},
                {"type": "runtime_dom_sink_reached", "source_group": "dom-runtime"},
                {"type": "unsanitized_dom_flow", "source_group": "dom-vulnerability-condition"},
            ],
        )
        self.assertTrue(result["admitted"])
        self.assertEqual(result["state"], "admitted")
        self.assertGreaterEqual(result["independent_sources"], 2)
        self.assertIn("unsanitized_dom_flow", result["decisive_signals"])

    def test_sanitization_blocks_surface_and_reachability_without_unsafe_condition(self) -> None:
        result = assess_admission(
            self.family,
            [
                {"type": "dataflow_source", "source_group": "dom-static-flow"},
                {"type": "dataflow_sink", "source_group": "dom-static-flow"},
                {"type": "runtime_dom_sink_reached", "source_group": "dom-runtime"},
            ],
            [
                {"type": "sanitization_observed", "source_group": "dom-neutralization"},
            ],
        )
        self.assertFalse(result["admitted"])
        self.assertEqual(result["state"], "shadow_contradicted")
        self.assertIn("sanitization_observed", result["blocking_contradictions"])

    def test_standards_and_writeups_add_zero_admission_evidence(self) -> None:
        knowledge_like = [
            {"source": "OWASP", "ref": "A05:2025 Injection", "source_group": "knowledge"},
            {"source": "OWASP WSTG", "ref": "WSTG-CLNT-01", "source_group": "knowledge"},
            {"source": "MITRE CWE", "ref": "CWE-79", "source_group": "knowledge"},
            {"source": "GitHub Security Lab", "ref": "GHSL-2025-110", "source_group": "knowledge"},
        ]
        result = assess_admission(self.family, knowledge_like)
        self.assertFalse(result["admitted"])
        self.assertEqual(result["independent_sources"], 0)


if __name__ == "__main__":
    unittest.main()
