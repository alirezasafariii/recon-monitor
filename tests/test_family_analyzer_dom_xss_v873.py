from __future__ import annotations

from _router_31_test_adapter import load_adapted_tests

_loaded = load_adapted_tests(__file__)
globals().update(_loaded)


def _canonical_methodology_grounding_test(self):
    from family_analyzers.dom_xss import (
        DOM_XSS_FAMILY_ANALYZER_VERSION,
        DOM_XSS_METHOD,
        DOM_XSS_SPEC,
    )

    result = self.analyze()
    self.assertIsNotNone(result)
    meta = result["family_analyzer"]
    self.assertEqual(DOM_XSS_FAMILY_ANALYZER_VERSION, "1.1.0")
    self.assertEqual(DOM_XSS_SPEC.family, "dom_xss")
    self.assertEqual(meta["family_spec_version"], DOM_XSS_SPEC.version)
    self.assertIn("CWE-79", meta["taxonomy"]["cwe"])
    self.assertIn("WSTG-CLNT-01", meta["taxonomy"]["wstg"])
    basis = {item for step in DOM_XSS_METHOD for item in step["basis"]}
    self.assertIn("CWE-79", basis)
    self.assertIn("WSTG-CLNT-01", basis)
    refs = {row["id"] for row in meta["writeup_patterns"]}
    self.assertIn("ghsl-2025-110-openlibrary-barcode-xss", refs)
    self.assertIn("ghsl-2026-030-nocodb-rendering", refs)
    self.assertTrue(all(row["non_evidentiary"] for row in meta["writeup_patterns"]))
    observed = {row["type"] for row in result["support"]}
    self.assertNotIn("ghsl-2025-110-openlibrary-barcode-xss", observed)
    self.assertNotIn("ghsl-2026-030-nocodb-rendering", observed)
    self.assertTrue(meta["knowledge_does_not_change_target_evidence"])


DomXssFamilyAnalyzerV873Tests.test_methodology_grounding_and_writeups_are_non_evidentiary = _canonical_methodology_grounding_test
