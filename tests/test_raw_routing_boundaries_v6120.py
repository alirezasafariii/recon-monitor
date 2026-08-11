from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_detectors import execute_detector_intelligence
from security_family_ranker import rank_security_families


def types(result: dict, family: str) -> set[str]:
    return {str(row.get("type") or "") for row in result.get(family, {}).get("support", [])}


def top1(result: dict) -> str:
    support = [item for packet in result.values() for item in packet.get("support", [])]
    contradict = [item for packet in result.values() for item in packet.get("contradict", [])]
    ranked = rank_security_families(support, contradict)
    return str(ranked[0]["family"]) if ranked else ""


class RawRoutingBoundaries6120Tests(unittest.TestCase):
    def test_upload_route_is_not_path_traversal_without_path_input(self):
        result = execute_detector_intelligence(
            target="example.test", endpoint="/api/upload", method="POST",
            endpoint_schema={"body_fields": ["file"]}, details={}, category="file upload multipart/form-data",
        )
        self.assertIn("file_upload", result)
        self.assertNotIn("path_traversal", result)
        self.assertEqual(top1(result), "file_upload")

    def test_bulk_report_resource_surface_is_not_sql_without_query_semantics(self):
        result = execute_detector_intelligence(
            target="example.test", endpoint="/api/export", method="GET",
            endpoint_schema={"query_parameters": ["limit"]}, details={"status_code": 200}, category="bulk export report",
        )
        self.assertIn("unrestricted_resource_consumption", result)
        self.assertNotIn("sql_injection", result)
        self.assertEqual(top1(result), "unrestricted_resource_consumption")

    def test_oauth_provider_segment_is_not_third_party_api_by_itself(self):
        result = execute_detector_intelligence(
            target="example.test", endpoint="/api/v1/auths/oauth/{provider}/token/exchange", method="POST",
            endpoint_schema={"authentication_hints": ["session"], "body_fields": ["username", "password"]},
            details={}, business_context="identity",
        )
        self.assertIn("authentication_session", result)
        self.assertNotIn("unsafe_api_consumption", result)
        self.assertEqual(top1(result), "authentication_session")

    def test_stored_cli_invocation_is_command_surface_only(self):
        result = execute_detector_intelligence(
            target="example.test", endpoint="/api/convert", method="POST",
            endpoint_schema={"body_fields": ["input"]},
            details={"source_code": "jsii-diff npm:my-package@latest .\n"},
        )
        self.assertIn("process_execution_surface", types(result, "command_injection"))
        self.assertNotIn("process_execution_reached", types(result, "command_injection"))
        self.assertEqual(top1(result), "command_injection")


if __name__ == "__main__":
    unittest.main()
