from __future__ import annotations

import unittest

from family_detectors.execution import execute_detector_intelligence
from hypothesis_admission import assess_admission


def run_packet(base: dict, details: dict):
    return execute_detector_intelligence(**base, details=details)


def admitted(family, result):
    packet = result.get(family, {"support": [], "contradict": []})
    return assess_admission(family, packet.get("support") or [], packet.get("contradict") or [])["admitted"]


def support_types(family, result):
    return {str(item.get("type") or "") for item in result.get(family, {}).get("support", [])}


class RawPrecisionCalibrationV6140Tests(unittest.TestCase):
    def test_account_enumeration_materiality(self):
        base = dict(target="fixture.invalid", endpoint="/api/login", method="POST", endpoint_schema={"body_fields": ["username", "password"]}, category="login username lookup", business_context="identity")
        positive = run_packet(base, {"context_observations": [{"context": "existing_username", "duration_ms": 52.0, "status_code": 401}, {"context": "absent_username", "duration_ms": 1.2, "status_code": 401}]})
        near = run_packet(base, {"context_observations": [{"context": "existing_username", "duration_ms": 51.0, "status_code": 401}, {"context": "another_existing_username", "duration_ms": 52.0, "status_code": 401}]})
        secure = run_packet(base, {"context_observations": [{"context": "existing_username", "duration_ms": 50.0, "status_code": 401}, {"context": "absent_username", "duration_ms": 50.0, "status_code": 401}]})
        self.assertIn("response_difference", support_types("account_enumeration", positive))
        self.assertNotIn("response_difference", support_types("account_enumeration", near))
        self.assertNotIn("response_difference", support_types("account_enumeration", secure))
        self.assertTrue(admitted("account_enumeration", positive))
        self.assertFalse(admitted("account_enumeration", near))

    def test_nosql_error_specificity(self):
        base = dict(target="fixture.invalid", endpoint="/api/search", method="POST", endpoint_schema={"body_fields": ["filter"]}, category="mongodb nosql document query filter", business_context="general")
        positive = run_packet(base, {"response_text": "MongoError: unknown operator $fixture in document query", "status_code": 500})
        near = run_packet(base, {"response_text": "document query returned zero results", "status_code": 200})
        self.assertIn("nosql_error_observed", support_types("nosql_injection", positive))
        self.assertNotIn("nosql_error_observed", support_types("nosql_injection", near))
        self.assertTrue(admitted("nosql_injection", positive))
        self.assertFalse(admitted("nosql_injection", near))

    def test_cors_condition_requires_unsafe_origin(self):
        base = dict(target="fixture.invalid", endpoint="/api/data", method="GET", endpoint_schema={"authentication_hints": ["session"]}, category="cors cross-origin authenticated response", business_context="customer_data")
        positive = run_packet(base, {"request_headers": {"Origin": "https://untrusted.fixture.invalid"}, "response_headers": {"Access-Control-Allow-Origin": "https://untrusted.fixture.invalid", "Access-Control-Allow-Credentials": "true"}, "status_code": 200})
        safe = run_packet(base, {"request_headers": {"Origin": "https://untrusted.fixture.invalid"}, "response_headers": {"Access-Control-Allow-Origin": "https://trusted.fixture.invalid"}, "status_code": 200})
        self.assertIn("credentials_allowed", support_types("cors_misconfiguration", positive))
        self.assertIn("authenticated_context", support_types("cors_misconfiguration", positive))
        self.assertNotIn("credentials_allowed", support_types("cors_misconfiguration", safe))
        self.assertNotIn("authenticated_context", support_types("cors_misconfiguration", safe))
        self.assertTrue(admitted("cors_misconfiguration", positive))
        self.assertFalse(admitted("cors_misconfiguration", safe))

    def test_command_direct_dataflow(self):
        base = dict(target="fixture.invalid", endpoint="/api/run", method="POST", endpoint_schema={"body_fields": ["input"]}, category="command process execution surface", business_context="general")
        positive = run_packet(base, {"source_code": "child_process.exec(userInput);", "status_code": 200})
        fixed = run_packet(base, {"source_code": "child_process.exec(fixedCommand);", "status_code": 200})
        structured = run_packet(base, {"source_code": "spawn(binary, validatedArgs);", "status_code": 400})
        self.assertIn("process_execution_reached", support_types("command_injection", positive))
        self.assertNotIn("process_execution_reached", support_types("command_injection", fixed))
        self.assertNotIn("process_execution_reached", support_types("command_injection", structured))
        self.assertTrue(admitted("command_injection", positive))
        self.assertFalse(admitted("command_injection", fixed))

    def test_race_duplicate_success(self):
        base = dict(target="fixture.invalid", endpoint="/redeem", method="POST", endpoint_schema={"body_fields": ["coupon"]}, category="redeem single-use concurrent business flow", business_context="payment")
        positive = run_packet(base, {"response_text": "two concurrent fixture requests both returned success", "status_code": 200})
        near = run_packet(base, {"response_text": "single fixture request returned success", "status_code": 200})
        blocked = run_packet(base, {"response_text": "second concurrent fixture request rejected", "status_code": 409})
        self.assertIn("duplicate_effect_observed", support_types("race_condition", positive))
        self.assertNotIn("duplicate_effect_observed", support_types("race_condition", near))
        self.assertNotIn("duplicate_effect_observed", support_types("race_condition", blocked))
        self.assertTrue(admitted("race_condition", positive))
        self.assertFalse(admitted("race_condition", near))

    def test_resource_high_amplification_material_cost(self):
        base = dict(target="fixture.invalid", endpoint="/api/export", method="GET", endpoint_schema={"query_parameters": ["limit"]}, category="bulk export expensive operation", business_context="general")
        positive = run_packet(base, {"duration_ms": 12000.0, "requested_limit": 1000000, "response_length": 5000000, "status_code": 200})
        near = run_packet(base, {"duration_ms": 45.0, "requested_limit": 100, "response_length": 5000, "status_code": 200})
        blocked = run_packet(base, {"requested_limit": 1000000, "response_text": "rate limited", "status_code": 429})
        self.assertIn("resource_exhaustion_differential", support_types("unrestricted_resource_consumption", positive))
        self.assertNotIn("resource_exhaustion_differential", support_types("unrestricted_resource_consumption", near))
        blockers = {str(item.get("type") or "") for item in blocked.get("unrestricted_resource_consumption", {}).get("contradict", [])}
        self.assertIn("rate_limit_enforced", blockers)
        self.assertTrue(admitted("unrestricted_resource_consumption", positive))
        self.assertFalse(admitted("unrestricted_resource_consumption", near))
        self.assertFalse(admitted("unrestricted_resource_consumption", blocked))

    def test_versions(self):
        import analysis_engine
        import bug_candidates
        import security_reasoning
        from raw_condition_reconstruction import RECONSTRUCTION_ENGINE_VERSION, RECONSTRUCTION_RULE_VERSION
        from family_detectors.execution import EXECUTION_ENGINE_VERSION, EXECUTION_RULE_VERSION
        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(
            tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")),
            (6, 14, 0),
        )
        self.assertEqual(RECONSTRUCTION_ENGINE_VERSION, "1.1.0")
        self.assertEqual(EXECUTION_ENGINE_VERSION, "1.2.0")
        self.assertEqual(RECONSTRUCTION_RULE_VERSION, "2026.08.12.6.14")
        self.assertEqual(EXECUTION_RULE_VERSION, "2026.08.12.6.14")


if __name__ == "__main__":
    unittest.main()
