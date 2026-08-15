from __future__ import annotations

from _router_31_test_adapter import load_adapted_tests

_loaded = load_adapted_tests(__file__)
globals().update(_loaded)


def _canonical_compatibility_surface_test(self):
    from family_analyzers.bola import BOLA_FAMILY_ANALYZER_VERSION, BOLA_SPEC, analyze_bola_signal

    result = analyze_bola_signal(
        self.db,
        analysis_id="AN-BOLA-FAMILY",
        target="example.com",
        endpoint="https://example.com/api/orders/1001",
        method="GET",
        object_ids=["1001"],
        structural_fields=[],
        details={
            "identity_id": "fixture-user-a",
            "object_owner_id": "fixture-user-b",
            "status_code": 200,
        },
    )
    self.assertIsNotNone(result)
    self.assertEqual(BOLA_FAMILY_ANALYZER_VERSION, "1.1.0")
    self.assertEqual(result["family_analyzer"]["family_spec_version"], BOLA_SPEC.version)
    self.assertTrue(result["family_analyzer"]["knowledge_does_not_change_target_evidence"])


BolaFamilyAnalyzerV868Tests.test_production_compatibility_surface_routes_to_family_analyzer = _canonical_compatibility_surface_test
