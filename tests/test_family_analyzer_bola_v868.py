from __future__ import annotations

from _router_31_test_adapter import load_adapted_tests

_loaded = load_adapted_tests(__file__)
globals().update(_loaded)


def _canonical_compatibility_surface_test(self):
    import bola_intelligence
    import bug_candidates
    from family_analyzers.bola import BOLA_FAMILY_ANALYZER_VERSION, BOLA_SPEC, analyze_bola_signal

    self.assertIs(bola_intelligence.analyze_bola_signal, analyze_bola_signal)
    self.assertIs(bug_candidates._alert_candidates.__globals__["analyze_bola_signal"], analyze_bola_signal)
    self.assertEqual(bola_intelligence.BOLA_ENGINE_VERSION, "2.0.0")
    self.assertEqual(bola_intelligence.BOLA_RULE_VERSION, "2026.08.8.5")
    self.assertEqual(BOLA_FAMILY_ANALYZER_VERSION, "1.1.0")
    self.assertEqual(BOLA_SPEC.family, "broken_object_authorization")


BolaFamilyAnalyzerV868Tests.test_production_compatibility_surface_routes_to_family_analyzer = _canonical_compatibility_surface_test
