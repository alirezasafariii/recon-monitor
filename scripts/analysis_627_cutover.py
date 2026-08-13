from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(rel: str, old: str, new: str, label: str) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing cutover marker {label} in {rel}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# Analysis/candidate/reasoning layer cutover.
replace_once(
    "app/analysis_engine.py",
    'ENGINE_VERSION = "6.25.0"\nRULE_VERSION = "2026.08.12.6.25"\n',
    'ENGINE_VERSION = "6.27.0"\nRULE_VERSION = "2026.08.13.6.27"\n',
    "analysis version",
)
replace_once(
    "app/bug_candidates.py",
    'CANDIDATE_ENGINE_VERSION = "6.25.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.25"\n',
    'CANDIDATE_ENGINE_VERSION = "6.27.0"\nCANDIDATE_RULE_VERSION = "2026.08.13.6.27"\n',
    "candidate version",
)
replace_once(
    "app/security_reasoning.py",
    'REASONING_ENGINE_VERSION = "6.25.0"\nREASONING_RULE_VERSION = "2026.08.12.6.25"\n',
    'REASONING_ENGINE_VERSION = "6.27.0"\nREASONING_RULE_VERSION = "2026.08.13.6.27"\n',
    "reasoning version",
)

# Component versions whose behavior changed during 6.27.
replace_once(
    "app/family_reasoners.py",
    'FAMILY_REASONER_VERSION = "1.1.0"\nFAMILY_REASONER_RULE_VERSION = "2026.08.10.6.8"\n',
    'FAMILY_REASONER_VERSION = "1.2.0"\nFAMILY_REASONER_RULE_VERSION = "2026.08.13.6.27"\n',
    "reasoner version",
)
replace_once(
    "app/family_evidence_extractors.py",
    'FAMILY_EVIDENCE_EXTRACTOR_VERSION = "1.0.0"\nFAMILY_EVIDENCE_EXTRACTOR_RULE_VERSION = "2026.08.10.6.8"\n',
    'FAMILY_EVIDENCE_EXTRACTOR_VERSION = "1.1.0"\nFAMILY_EVIDENCE_EXTRACTOR_RULE_VERSION = "2026.08.13.6.27"\n',
    "extractor version",
)

# Production candidate schema must recognize the new certificate-validation
# condition already owned by detector/admission. The consumed v4 advisory is NOT
# added as standards grounding or target evidence.
replace_once(
    "app/bug_candidates.py",
    '"unsafe_api_consumption": {"required_any": (("third_party_integration", "upstream_api_surface", "external_service_dependency"), ("upstream_tls_missing", "third_party_data_unsanitized", "upstream_redirect_followed_unrestricted", "upstream_timeout_absent", "upstream_response_unbounded", "third_party_auth_weak", "unsafe_upstream_data_reaches_sink")), "label": "third-party API dependency plus observed unsafe upstream consumption"},',
    '"unsafe_api_consumption": {"required_any": (("third_party_integration", "upstream_api_surface", "external_service_dependency"), ("upstream_tls_missing", "upstream_certificate_validation_failure", "third_party_data_unsanitized", "upstream_redirect_followed_unrestricted", "upstream_timeout_absent", "upstream_response_unbounded", "third_party_auth_weak", "unsafe_upstream_data_reaches_sink")), "label": "third-party API dependency plus observed unsafe upstream consumption"},',
    "candidate unsafe API condition",
)

# Security-reasoning schemas follow the same family sufficiency boundaries.
replace_once(
    "app/security_reasoning.py",
    '"required": [{"third_party_integration", "upstream_api_surface", "external_service_dependency"}, {"upstream_tls_missing", "third_party_data_unsanitized", "upstream_redirect_followed_unrestricted", "upstream_timeout_absent", "upstream_response_unbounded", "third_party_auth_weak", "unsafe_upstream_data_reaches_sink"}],\n        "support": {"third_party_data_unsanitized", "unsafe_upstream_data_reaches_sink"},',
    '"required": [{"third_party_integration", "upstream_api_surface", "external_service_dependency"}, {"upstream_tls_missing", "upstream_certificate_validation_failure", "third_party_data_unsanitized", "upstream_redirect_followed_unrestricted", "upstream_timeout_absent", "upstream_response_unbounded", "third_party_auth_weak", "unsafe_upstream_data_reaches_sink"}],\n        "support": {"upstream_certificate_validation_failure", "third_party_data_unsanitized", "unsafe_upstream_data_reaches_sink"},',
    "reasoning unsafe API condition",
)
replace_once(
    "app/security_reasoning.py",
    '"required": [{"source_map"}, {"internal_sources", "source_contents"}],\n        "support": {"public_observation", "production_javascript", "debug_information"},',
    '"required": [{"source_map"}, {"internal_sources", "source_contents"}, {"public_observation", "direct_reachability"}],\n        "support": {"public_observation", "direct_reachability", "production_javascript", "debug_information"},',
    "reasoning source-map public condition",
)
replace_once(
    "app/security_reasoning.py",
    '"rank_gate": {"cors_header", "wildcard_origin", "reflected_origin"},\n        "required": [{"cors_header", "wildcard_origin", "reflected_origin"}],\n        "support": {"credentials_allowed", "sensitive_fields", "authenticated_context"},',
    '"rank_gate": {"cors_policy_surface", "cors_header", "wildcard_origin", "reflected_origin"},\n        "required": [{"cors_policy_surface", "cors_header"}, {"wildcard_origin", "reflected_origin", "null_origin_accepted", "unsafe_origin_policy"}, {"credentials_allowed", "sensitive_cross_origin_response", "authenticated_context"}],\n        "support": {"credentials_allowed", "sensitive_cross_origin_response", "sensitive_fields", "authenticated_context"},',
    "reasoning CORS three-stage boundary",
)

# Historical seal tests remain regression floors; Analysis 6.27 owns the exact
# current lineage in its new seal contract.
replace_once(
    "tests/test_analysis_625_seal.py",
    '''    def test_analysis_layer_versions_are_exactly_sealed_at_625(self) -> None:\n        import analysis_engine\n        import bug_candidates\n        import security_reasoning\n\n        self.assertEqual(analysis_engine.ENGINE_VERSION, "6.25.0")\n        self.assertEqual(bug_candidates.CANDIDATE_ENGINE_VERSION, "6.25.0")\n        self.assertEqual(security_reasoning.REASONING_ENGINE_VERSION, "6.25.0")\n        self.assertEqual(analysis_engine.RULE_VERSION, "2026.08.12.6.25")\n        self.assertEqual(bug_candidates.CANDIDATE_RULE_VERSION, "2026.08.12.6.25")\n        self.assertEqual(security_reasoning.REASONING_RULE_VERSION, "2026.08.12.6.25")\n        self.assertEqual(OWASP_TOP10_2025_COLLECTOR_RULE_VERSION, "2026.08.12.6.25")\n        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")\n        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.1.0")\n        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")\n''',
    '''    def test_analysis_layer_versions_preserve_625_or_newer_lineage(self) -> None:\n        import analysis_engine\n        import bug_candidates\n        import security_reasoning\n\n        def version(value: str) -> tuple[int, ...]:\n            return tuple(int(part) for part in value.split("."))\n\n        self.assertGreaterEqual(version(analysis_engine.ENGINE_VERSION), (6, 25, 0))\n        self.assertGreaterEqual(version(bug_candidates.CANDIDATE_ENGINE_VERSION), (6, 25, 0))\n        self.assertGreaterEqual(version(security_reasoning.REASONING_ENGINE_VERSION), (6, 25, 0))\n        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)\n        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)\n        self.assertEqual(OWASP_TOP10_2025_COLLECTOR_RULE_VERSION, "2026.08.12.6.25")\n        self.assertGreaterEqual(version(STANDARDS_ENGINE_VERSION), (1, 3, 0))\n        self.assertGreaterEqual(version(DETECTOR_ENGINE_VERSION), (1, 1, 0))\n        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")\n''',
    "historical 625 version floor",
)
replace_once(
    "tests/test_family_reasoners_v670.py",
    '        self.assertEqual(FAMILY_REASONER_VERSION, "1.1.0")\n',
    '        self.assertGreaterEqual(tuple(int(part) for part in FAMILY_REASONER_VERSION.split(".")), (1, 1, 0))\n',
    "historical reasoner version floor",
)
replace_once(
    "tests/test_family_evidence_extractors_v680.py",
    '        self.assertEqual(FAMILY_EVIDENCE_EXTRACTOR_VERSION, "1.0.0")\n        self.assertEqual(FAMILY_REASONER_VERSION, "1.1.0")\n',
    '        self.assertGreaterEqual(tuple(int(part) for part in FAMILY_EVIDENCE_EXTRACTOR_VERSION.split(".")), (1, 0, 0))\n        self.assertGreaterEqual(tuple(int(part) for part in FAMILY_REASONER_VERSION.split(".")), (1, 1, 0))\n',
    "historical extractor/reasoner version floors",
)
