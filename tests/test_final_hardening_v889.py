from __future__ import annotations

import inspect
import ssl
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import bug_candidates_core
import safe_transport
from family_reasoning import candidate_evidence_schema_map


class FinalHardeningV889Tests(unittest.TestCase):
    def test_candidate_core_runtime_schema_is_canonical(self) -> None:
        expected = candidate_evidence_schema_map()
        self.assertEqual(bug_candidates_core.FAMILY_EVIDENCE_SCHEMAS, expected)
        self.assertEqual(bug_candidates_core._legacy.FAMILY_EVIDENCE_SCHEMAS, expected)
        source = inspect.getsource(bug_candidates_core)
        self.assertIn("candidate_evidence_schema_map()", source)
        self.assertNotIn('"broken_object_authorization": {"required_any"', source)

    def test_public_resolution_fails_closed_on_mixed_private_answer(self) -> None:
        rows = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        with mock.patch.object(safe_transport.socket, "getaddrinfo", return_value=rows):
            public, addresses = safe_transport.resolve_public_addresses("example.com", 443)
        self.assertFalse(public)
        self.assertEqual(addresses, ["93.184.216.34", "127.0.0.1"])

    def test_public_resolution_rejects_shared_cgnat(self) -> None:
        rows = [(2, 1, 6, "", ("100.64.0.1", 443))]
        with mock.patch.object(safe_transport.socket, "getaddrinfo", return_value=rows):
            public, addresses = safe_transport.resolve_public_addresses("example.com", 443)
        self.assertFalse(public)
        self.assertEqual(addresses, ["100.64.0.1"])

    def test_public_resolution_rejects_documentation_range(self) -> None:
        rows = [(2, 1, 6, "", ("192.0.2.1", 443))]
        with mock.patch.object(safe_transport.socket, "getaddrinfo", return_value=rows):
            public, addresses = safe_transport.resolve_public_addresses("example.com", 443)
        self.assertFalse(public)
        self.assertEqual(addresses, ["192.0.2.1"])

    def test_http_connection_uses_pinned_ip_not_hostname(self) -> None:
        connection = safe_transport._PinnedHTTPConnection(
            "example.com",
            "93.184.216.34",
            timeout=1,
        )
        fake_socket = object()
        connection._create_connection = mock.Mock(return_value=fake_socket)
        connection.connect()
        self.assertIs(connection.sock, fake_socket)
        self.assertEqual(connection._create_connection.call_args.args[0], ("93.184.216.34", 80))

    def test_https_connection_pins_ip_but_keeps_original_sni(self) -> None:
        context = ssl.create_default_context()
        connection = safe_transport._PinnedHTTPSConnection(
            "example.com",
            "93.184.216.34",
            timeout=1,
            context=context,
        )
        raw_socket = object()
        wrapped_socket = object()
        connection._create_connection = mock.Mock(return_value=raw_socket)
        connection._context = mock.Mock()
        connection._context.wrap_socket.return_value = wrapped_socket
        connection.connect()
        self.assertEqual(connection._create_connection.call_args.args[0], ("93.184.216.34", 443))
        connection._context.wrap_socket.assert_called_once_with(
            raw_socket,
            server_hostname="example.com",
        )
        self.assertIs(connection.sock, wrapped_socket)


if __name__ == "__main__":
    unittest.main()
