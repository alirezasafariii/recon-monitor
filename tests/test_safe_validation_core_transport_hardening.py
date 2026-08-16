from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import safe_validation
import safe_validation_core


class SafeValidationCoreTransportHardeningTests(unittest.TestCase):
    def test_core_transport_helper_delegates_to_pinned_transport(self):
        item = {"method": "GET", "url": "https://example.com/health", "headers": {}}
        policy = object()
        expected = ({"status_code": 200}, "ok")
        with mock.patch(
            "safe_validation_core.perform_pinned_request", return_value=expected
        ) as pinned:
            result = safe_validation_core._perform_request_via_safe_transport(item, policy)
        self.assertEqual(result, expected)
        pinned.assert_called_once()
        kwargs = pinned.call_args.kwargs
        self.assertIs(kwargs["url_safety"], safe_validation_core._url_safety)
        self.assertIs(kwargs["observation"], safe_validation_core._observation)
        self.assertEqual(kwargs["safe_methods"], safe_validation_core.SAFE_METHODS)

    def test_public_patch_point_still_routes_execute_core_hook(self):
        item = {"method": "GET", "url": "https://example.com/health", "headers": {}}
        policy = object()
        expected = ({"status_code": 204}, "ok")
        with mock.patch("safe_validation._perform_request", return_value=expected) as patched:
            result = safe_validation_core._perform_request(item, policy)
        self.assertEqual(result, expected)
        patched.assert_called_once_with(item, policy)

    def test_public_default_uses_core_pinned_helper(self):
        item = {"method": "GET", "url": "https://example.com/health", "headers": {}}
        policy = object()
        expected = ({"status_code": 200}, "ok")
        with mock.patch(
            "safe_validation_core._perform_request_via_safe_transport", return_value=expected
        ) as helper:
            result = safe_validation._perform_request(item, policy)
        self.assertEqual(result, expected)
        helper.assert_called_once_with(item, policy)

    def test_core_source_has_no_second_direct_http_open_path(self):
        source = (ROOT / "app/safe_validation_core.py").read_text(encoding="utf-8")
        start = source.index("def _perform_request_via_safe_transport(")
        end = source.index("\ndef _classify(", start)
        transport_section = source[start:end]
        self.assertIn("perform_pinned_request", transport_section)
        self.assertNotIn("build_opener", transport_section)
        self.assertNotIn("opener.open", transport_section)
        self.assertNotIn("getaddrinfo", transport_section)


if __name__ == "__main__":
    unittest.main()
