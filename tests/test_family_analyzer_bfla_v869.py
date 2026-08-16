from __future__ import annotations

from _router_31_test_adapter import load_adapted_tests

_loaded = load_adapted_tests(__file__)
globals().update(_loaded)


def _canonical_methodology_test(self):
    from family_analyzers.bfla import BFLA_FAMILY_ANALYZER_VERSION, BFLA_METHOD, BFLA_SPEC

    result = self.analyze({}, body_fields=["role"])
    self.assertIsNotNone(result)
    meta = result["family_analyzer"]
    self.assertEqual(BFLA_FAMILY_ANALYZER_VERSION, "1.1.0")
    self.assertEqual(meta["family_spec_version"], BFLA_SPEC.version)
    self.assertIn("CWE-862", meta["taxonomy"]["cwe"])
    self.assertIn("WSTG-APIT-04", meta["taxonomy"]["wstg"])
    self.assertIn("WSTG-ATHZ-02", meta["taxonomy"]["wstg"])
    basis = {item for step in BFLA_METHOD for item in step["basis"]}
    self.assertIn("OWASP API5:2023", basis)
    self.assertIn("CWE-862", basis)
    self.assertIn("WSTG-ATHZ-02", basis)


BflaFamilyAnalyzerV869Tests.test_methodology_is_grounded_in_api5_wstg_and_cwe = _canonical_methodology_test
