from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_detectors import (
    EXECUTION_ENGINE_VERSION,
    EXECUTION_PROFILES,
    EXECUTION_RULE_VERSION,
    execute_detector_intelligence,
    validate_execution_profiles,
)
from family_detectors.registry import DETECTOR_SPECS


def packet_types(result: dict, family: str, side: str = "support") -> set[str]:
    return {str(row.get("type") or "") for row in result.get(family, {}).get(side, [])}


class DetectorExecutionIntelligence6100Tests(unittest.TestCase):
    def test_exact_31_family_execution_coverage(self):
        self.assertEqual(set(EXECUTION_PROFILES), set(DETECTOR_SPECS))
        self.assertEqual(len(EXECUTION_PROFILES), 31)
        self.assertEqual(validate_execution_profiles(), [])

    def test_sql_error_signature_stays_sql_specific(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/search",
            method="GET",
            endpoint_schema={"query_parameters": ["q"], "body_fields": [], "path_parameters": []},
            details={"status_code": 500, "response_text": "SQL syntax error at or near SELECT"},
            category="search",
        )
        sql = packet_types(result, "sql_injection")
        self.assertIn("input_parameter", sql)
        self.assertIn("sql_query_surface", sql)
        self.assertIn("database_error_observed", sql)
        self.assertNotIn("nosql_error_observed", packet_types(result, "nosql_injection"))

    def test_ssrf_server_fetch_does_not_become_open_redirect(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/preview",
            method="POST",
            endpoint_schema={"body_fields": ["url"], "query_parameters": [], "path_parameters": []},
            details={"source_code": "def preview(url): return requests.get(url).text"},
        )
        ssrf = packet_types(result, "ssrf")
        self.assertIn("remote_destination", ssrf)
        self.assertIn("server_request_function", ssrf)
        self.assertNotIn("external_destination", packet_types(result, "open_redirect"))

    def test_external_location_is_redirect_not_ssrf_condition(self):
        result = execute_detector_intelligence(
            target="https://example.test",
            endpoint="https://example.test/login",
            method="GET",
            endpoint_schema={"query_parameters": ["redirect"], "body_fields": [], "path_parameters": []},
            details={
                "status_code": 302,
                "response_headers": {"Location": "https://external.invalid/landing"},
            },
        )
        redirect = packet_types(result, "open_redirect")
        self.assertIn("redirect_parameter", redirect)
        self.assertIn("navigation_sink", redirect)
        self.assertIn("external_destination", redirect)
        self.assertNotIn("server_fetch_observed", packet_types(result, "ssrf"))

    def test_cors_header_interaction_builds_family_condition(self):
        origin = "https://attacker.invalid"
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/me",
            method="GET",
            endpoint_schema={"authentication_hints": ["bearer"], "query_parameters": [], "body_fields": [], "path_parameters": []},
            details={
                "request_headers": {"Origin": origin},
                "response_headers": {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
            },
            business_context="identity",
        )
        cors = packet_types(result, "cors_misconfiguration")
        self.assertIn("reflected_origin", cors)
        self.assertIn("credentials_allowed", cors)
        self.assertIn("authenticated_context", cors)

    def test_source_map_reachability_is_extracted_from_stored_response(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="https://example.test/app.js.map",
            method="GET",
            endpoint_schema={"query_parameters": [], "body_fields": [], "path_parameters": []},
            details={"status_code": 200, "response_body": '{"sources":["src/app.ts"],"sourcesContent":["const x=1"]}'},
        )
        types = packet_types(result, "source_map_exposure")
        self.assertIn("source_map", types)
        self.assertIn("internal_sources", types)
        self.assertIn("direct_reachability", types)

    def test_secret_value_is_fingerprinted_never_persisted(self):
        raw_secret = "ABCD1234EFGH5678IJKL9012MNOP3456"
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="https://example.test/app.js",
            method="GET",
            endpoint_schema={"query_parameters": [], "body_fields": [], "path_parameters": []},
            details={"source_code": f"const api_key = '{raw_secret}';"},
        )
        packet = result.get("secret_exposure", {})
        rendered = repr(packet)
        self.assertNotIn(raw_secret, rendered)
        self.assertIn("secret_pattern", packet_types(result, "secret_exposure"))
        self.assertIn("fingerprint=", rendered)
        for row in packet.get("support", []):
            self.assertTrue(row.get("execution_passive_only"))

    def test_http_429_is_a_resource_control_not_vulnerability_condition(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/export",
            method="GET",
            endpoint_schema={"query_parameters": ["limit"], "body_fields": [], "path_parameters": []},
            details={"status_code": 429},
        )
        self.assertIn("resource_control_parameter", packet_types(result, "unrestricted_resource_consumption"))
        self.assertIn("rate_limit_enforced", packet_types(result, "unrestricted_resource_consumption", "contradict"))
        self.assertNotIn("rate_limit_absent_observed", packet_types(result, "unrestricted_resource_consumption"))

    def test_external_knowledge_cannot_enter_target_evidence(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/search",
            method="GET",
            endpoint_schema={"query_parameters": ["q"], "body_fields": [], "path_parameters": []},
            details={},
            evidence_for=[
                {"type": "database_error_observed", "source": "OWASP WSTG", "url": "https://owasp.org/"},
                {"type": "database_error_observed", "source": "stored_behavior", "text": "target evidence"},
            ],
        )
        sql_rows = result.get("sql_injection", {}).get("support", [])
        self.assertTrue(any(row.get("source") == "stored_behavior" for row in sql_rows))
        self.assertFalse(any("owasp" in str(row.get("source") or "").lower() for row in sql_rows))

    def test_explicit_condition_flags_are_read_without_active_probing(self):
        result = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/render",
            method="POST",
            endpoint_schema={"body_fields": ["template"], "query_parameters": [], "path_parameters": []},
            details={"template_expression_evaluated": True},
        )
        rows = result["server_side_template_injection"]["support"]
        self.assertIn("template_expression_evaluated", {row["type"] for row in rows})
        self.assertTrue(all(row.get("execution_passive_only") for row in rows))
        self.assertFalse(any("payload" in row or "request" in row for row in rows))

    def test_versions(self):
        self.assertEqual(EXECUTION_ENGINE_VERSION, "1.0.0")
        self.assertEqual(EXECUTION_RULE_VERSION, "2026.08.11.6.10")


if __name__ == "__main__":
    unittest.main()
