from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_detectors import evaluate_family_detector, execute_detector_intelligence
from family_detectors.execution import EXECUTION_ENGINE_VERSION, EXECUTION_RULE_VERSION
from hypothesis_admission import assess_admission
from raw_recon_corpus import load_raw_cases
from raw_recon_observability import (
    OBSERVABILITY_ENGINE_VERSION,
    OBSERVABILITY_RULE_VERSION,
    analyze_variant_observability,
)


def types(result: dict, family: str, side: str = "support") -> set[str]:
    return {str(row.get("type") or "") for row in result.get(family, {}).get(side, [])}


def admitted(result: dict, family: str) -> bool:
    packet = result.get(family, {"support": [], "contradict": []})
    scoped = evaluate_family_detector(family, packet.get("support") or [], packet.get("contradict") or [], channel="alert")
    return bool(assess_admission(family, scoped["support"], scoped["contradict"])["admitted"])


class RawConditionReconstruction6120Tests(unittest.TestCase):
    def test_generic_traceback_reconstructs_misconfiguration_condition(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/action",
            method="GET",
            endpoint_schema={},
            details={"status_code": 500, "response_text": "Traceback: framework exception with application path /srv/app/module.py:42"},
            category="debug error deployment configuration",
        )
        self.assertIn("stack_trace_exposed", types(result, "security_misconfiguration"))
        self.assertTrue(admitted(result, "security_misconfiguration"))

    def test_public_sensitive_diagnostic_material_reconstructs_disclosure(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/status",
            method="GET",
            endpoint_schema={},
            details={"status_code": 200, "response_text": "Stored public response contains sensitive diagnostic material described by the advisory"},
            business_context="customer_data",
        )
        self.assertIn("debug_information", types(result, "information_disclosure"))
        self.assertIn("public_observation", types(result, "information_disclosure"))
        self.assertTrue(admitted(result, "information_disclosure"))

    def test_diagnostic_material_with_auth_hint_does_not_become_public_observation(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/status",
            method="GET",
            endpoint_schema={"authentication_hints": ["session"]},
            details={"status_code": 200, "response_text": "sensitive diagnostic material"},
        )
        self.assertIn("debug_information", types(result, "information_disclosure"))
        self.assertNotIn("public_observation", types(result, "information_disclosure"))
        self.assertFalse(admitted(result, "information_disclosure"))

    def test_redacted_secret_is_identity_only_not_condition(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/assets/app.js",
            method="GET",
            endpoint_schema={},
            details={"source_code": 'DEFAULT_TOKEN_SECRET="<redacted>"'},
            category="production javascript client asset",
        )
        self.assertIn("secret_pattern", types(result, "secret_exposure"))
        self.assertNotIn("high_entropy_value", types(result, "secret_exposure"))
        self.assertFalse(admitted(result, "secret_exposure"))

    def test_auth_expected_deny_success_reconstructs_boundary_regression(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/session/refresh",
            method="POST",
            endpoint_schema={"authentication_hints": ["session"]},
            details={"context_observations": [{"context": "invalid_session", "expected_access": "denied", "status_code": 200}]},
            business_context="identity",
        )
        self.assertIn("authentication_boundary_regression", types(result, "authentication_session"))
        self.assertTrue(admitted(result, "authentication_session"))

    def test_account_enumeration_requires_stored_differential(self):
        base = dict(
            target="example.test",
            endpoint="/forgot-password",
            method="POST",
            endpoint_schema={"body_fields": ["email"]},
            business_context="identity",
        )
        no_diff = execute_detector_intelligence(**base, details={"context_observations": [{"context": "existing_identity", "status_code": 200}, {"context": "absent_identity", "status_code": 200}]})
        self.assertNotIn("response_difference", types(no_diff, "account_enumeration"))
        same_class_diff = execute_detector_intelligence(**base, details={"context_observations": [{"context": "existing_identity", "status_code": 200, "response_text": "sent"}, {"context": "another_existing_identity", "status_code": 404, "response_text": "unknown"}]})
        self.assertNotIn("response_difference", types(same_class_diff, "account_enumeration"))
        with_diff = execute_detector_intelligence(**base, details={"context_observations": [{"context": "existing_identity", "status_code": 200, "response_text": "sent"}, {"context": "absent_identity", "status_code": 404, "response_text": "unknown"}]})
        self.assertIn("response_difference", types(with_diff, "account_enumeration"))
        self.assertTrue(admitted(with_diff, "account_enumeration"))

    def test_mass_assignment_schema_alone_never_proves_acceptance(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/profile",
            method="PATCH",
            endpoint_schema={"body_fields": ["display_name", "role"]},
            details={},
        )
        self.assertIn("privileged_property", types(result, "mass_assignment"))
        self.assertNotIn("privileged_property_accepted", types(result, "mass_assignment"))
        self.assertFalse(admitted(result, "mass_assignment"))

    def test_mass_assignment_request_response_state_can_prove_acceptance(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/profile",
            method="PATCH",
            endpoint_schema={"body_fields": ["role"]},
            details={
                "status_code": 200,
                "request_json": {"role": "admin"},
                "resource_before": {"role": "user"},
                "response_json": {"role": "admin"},
            },
        )
        self.assertIn("privileged_property_accepted", types(result, "mass_assignment"))
        self.assertTrue(admitted(result, "mass_assignment"))

    def test_stored_outbound_request_can_prove_ssrf_without_active_probe(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/preview",
            method="POST",
            endpoint_schema={"body_fields": ["url"]},
            details={"outbound_request_url": "https://outside.example/resource"},
        )
        self.assertIn("server_fetch_observed", types(result, "ssrf"))
        self.assertTrue(admitted(result, "ssrf"))

    def test_dangerous_upload_requires_acceptance_artifact(self):
        common = dict(
            target="example.test",
            endpoint="/upload",
            method="POST",
            endpoint_schema={"body_fields": ["file"]},
        )
        surface = execute_detector_intelligence(**common, details={"request_json": {"filename": "shell.php", "content_type": "application/x-httpd-php"}})
        self.assertNotIn("dangerous_type_accepted", types(surface, "file_upload"))
        accepted = execute_detector_intelligence(**common, details={"status_code": 201, "request_json": {"filename": "shell.php", "content_type": "application/x-httpd-php"}, "stored_path": "/uploads/shell.php"})
        self.assertIn("dangerous_type_accepted", types(accepted, "file_upload"))

    def test_path_escape_requires_resolution_outside_base(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/download",
            method="GET",
            endpoint_schema={"query_parameters": ["path"]},
            details={"status_code": 200, "requested_path": "../../etc/passwd", "base_path": "/srv/files", "resolved_path": "/etc/passwd"},
        )
        self.assertIn("path_escape_observed", types(result, "path_traversal"))
        self.assertTrue(admitted(result, "path_traversal"))

    def test_plain_api_version_does_not_create_inventory_hypothesis(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/v1/prediction/123",
            method="POST",
            endpoint_schema={"body_fields": ["question"]},
            details={},
        )
        self.assertNotIn("improper_inventory_management", result)

    def test_command_and_template_semantics_are_routing_only(self):
        command = execute_detector_intelligence(target="example.test", endpoint="/tool", method="POST", endpoint_schema={"body_fields": ["name"]}, details={}, category="command process execution")
        self.assertIn("process_execution_surface", types(command, "command_injection"))
        self.assertFalse(admitted(command, "command_injection"))
        template = execute_detector_intelligence(target="example.test", endpoint="/render", method="POST", endpoint_schema={"body_fields": ["name"]}, details={}, category="server template render")
        self.assertIn("template_render_surface", types(template, "server_side_template_injection"))
        self.assertFalse(admitted(template, "server_side_template_injection"))

    def test_consumed_v1_collision_accounting_is_explicit(self):
        cases = load_raw_cases(ROOT / "benchmarks" / "raw" / "analysis_raw_v1.jsonl")
        report = analyze_variant_observability(cases)
        self.assertEqual(report["source_root_count"], 24)
        self.assertEqual(report["collision_root_count"], 15)
        self.assertEqual(report["raw_distinguishable_root_count"], 9)
        self.assertFalse(any("expected" in str(row.get("status")) for row in report["rows"]))

    def test_versions(self):
        self.assertGreaterEqual(tuple(int(part) for part in EXECUTION_ENGINE_VERSION.split(".")), (1, 2, 0))
        self.assertGreaterEqual(tuple(int(part) for part in EXECUTION_RULE_VERSION.split(".")), (2026, 8, 12, 6, 14))
        self.assertEqual(OBSERVABILITY_ENGINE_VERSION, "1.0.0")
        self.assertEqual(OBSERVABILITY_RULE_VERSION, "2026.08.11.6.12")


if __name__ == "__main__":
    unittest.main()