from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from hypothesis_admission import ADMISSION_ENGINE_VERSION, assess_admission


class AnalysisAdmissionV600Tests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.0.0")

    def assert_hidden(self, family, support, contradict=None):
        result = assess_admission(family, support, contradict or [])
        self.assertFalse(result["admitted"], result)
        self.assertIn(result["state"], {"shadow_signal", "shadow_partial", "shadow_contradicted"})
        return result

    def assert_admitted(self, family, support, contradict=None):
        result = assess_admission(family, support, contradict or [])
        self.assertTrue(result["admitted"], result)
        self.assertEqual(result["state"], "admitted")
        return result

    def test_bfla_admin_route_is_surface_only(self):
        self.assert_hidden("broken_function_authorization", [
            {"type": "privileged_function", "source": "semantic"},
            {"type": "state_change", "source": "method"},
        ])

    def test_bfla_lower_privilege_success_is_decisive(self):
        self.assert_admitted("broken_function_authorization", [
            {"type": "privileged_function", "source": "semantic"},
            {"type": "state_change", "source": "method"},
            {"type": "lower_privilege_success", "source": "stored_context"},
        ])

    def test_mass_assignment_schema_is_surface_only(self):
        self.assert_hidden("mass_assignment", [
            {"type": "write_method", "source": "method"},
            {"type": "privileged_property", "source": "schema"},
        ])

    def test_mass_assignment_server_acceptance_is_decisive(self):
        self.assert_admitted("mass_assignment", [
            {"type": "write_method", "source": "method"},
            {"type": "privileged_property", "source": "schema"},
            {"type": "privileged_property_accepted", "source": "stored_behavior"},
        ])

    def test_ssrf_url_field_is_surface_only(self):
        self.assert_hidden("ssrf", [
            {"type": "remote_destination", "source": "schema"},
            {"type": "server_feature", "source": "semantic"},
        ])

    def test_ssrf_backend_fetch_is_decisive(self):
        self.assert_admitted("ssrf", [
            {"type": "remote_destination", "source": "schema"},
            {"type": "server_fetch_observed", "source": "stored_behavior"},
        ])

    def test_open_redirect_parameter_is_surface_only(self):
        self.assert_hidden("open_redirect", [
            {"type": "redirect_parameter", "source": "schema"},
            {"type": "navigation_sink", "source": "javascript"},
        ])

    def test_open_redirect_external_destination_is_decisive(self):
        self.assert_admitted("open_redirect", [
            {"type": "redirect_parameter", "source": "schema"},
            {"type": "navigation_sink", "source": "javascript"},
            {"type": "external_destination", "source": "stored_behavior"},
        ])

    def test_file_upload_surface_does_not_promote(self):
        self.assert_hidden("file_upload", [
            {"type": "file_input", "source": "schema"},
            {"type": "upload_operation", "source": "endpoint"},
        ])

    def test_path_download_surface_does_not_promote(self):
        self.assert_hidden("path_traversal", [
            {"type": "filename_field", "source": "schema"},
            {"type": "download_operation", "source": "endpoint"},
        ])

    def test_graphql_id_is_surface_only(self):
        self.assert_hidden("graphql_authorization", [
            {"type": "graphql_operation", "source": "graphql"},
            {"type": "graphql_identifier", "source": "graphql"},
        ])

    def test_cors_header_alone_is_not_a_candidate(self):
        self.assert_hidden("cors_misconfiguration", [
            {"type": "wildcard_origin", "source": "headers"},
        ])

    def test_business_terms_are_watchlist_only(self):
        self.assert_hidden("business_logic", [
            {"type": "business_operation", "source": "semantic"},
            {"type": "state_change", "source": "method"},
        ])


if __name__ == "__main__":
    unittest.main()
