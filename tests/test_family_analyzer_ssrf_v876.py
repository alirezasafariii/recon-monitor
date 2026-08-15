from __future__ import annotations

from _router_31_test_adapter import load_adapted_tests

_loaded = load_adapted_tests(__file__)
globals().update(_loaded)


def _canonical_methodology_test(self):
    from family_analyzers.ssrf import SSRF_FAMILY_ANALYZER_VERSION, SSRF_METHOD, SSRF_SPEC

    result = self.analyze()
    self.assertIsNotNone(result)
    meta = result["family_analyzer"]
    self.assertEqual(SSRF_FAMILY_ANALYZER_VERSION, "1.1.0")
    self.assertEqual(meta["family_spec_version"], SSRF_SPEC.version)
    self.assertIn("WSTG-INPV-19", meta["taxonomy"]["wstg"])
    self.assertIn("CWE-918", meta["taxonomy"]["cwe"])
    basis = {item for step in SSRF_METHOD for item in step["basis"]}
    self.assertIn("WSTG-INPV-19", basis)
    self.assertIn("CWE-918", basis)
    self.assertTrue(all(row["non_evidentiary"] for row in meta["writeup_patterns"]))
    observed = {row["type"] for row in result["support"]}
    self.assertNotIn("ghsl-wekan-2026-045", observed)
    self.assertTrue(meta["knowledge_does_not_change_target_evidence"])
    self.assertFalse(meta["active_validation_performed"])
    self.assertFalse(meta["internal_or_metadata_probing_performed"])


SsrfFamilyAnalyzerV876Tests.test_methodology_grounding_is_non_evidentiary = _canonical_methodology_test
