from __future__ import annotations

import inspect
import io
import sys
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import safe_transport
import stages
from stages import (
    _katana_crawl_plan,
    _katana_scope_regex,
    _origin_probe_one,
    _policy_headers_for_url,
)


class _Policy:
    headers: dict[str, str] = {}

    def url_in_scope(self, url: str) -> bool:
        try:
            host = __import__("urllib.parse").parse.urlsplit(url).hostname or ""
        except ValueError:
            return False
        return host == "example.test" or host.endswith(".example.test")


class _Response:
    def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self, amount: int = -1) -> bytes:
        return self._body if amount < 0 else self._body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _Opener:
    def __init__(self, outcome):
        self.outcome = outcome

    def open(self, request, timeout=None):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class _Budget:
    def __init__(self) -> None:
        self.used = 0

    def consume(self, metric: str, amount: int = 1):
        if metric == "http_requests":
            self.used += amount
        return self.used, 100


def _probe_ctx():
    return SimpleNamespace(
        policy=SimpleNamespace(
            headers={},
            url_in_scope=lambda url: str(url).startswith("https://example.test"),
            limits=SimpleNamespace(http_workers=8),
        ),
        budget=_Budget(),
    )


class ReconFinalTransportHardeningTests(unittest.TestCase):
    def test_pinned_download_repins_every_in_scope_redirect_hop(self) -> None:
        redirect = urllib.error.HTTPError(
            "https://a.example.test/app.js",
            302,
            "Found",
            {"Location": "https://b.example.test/static/app.js"},
            io.BytesIO(b""),
        )
        openers = [
            _Opener(redirect),
            _Opener(
                _Response(
                    200,
                    b"console.log('ok')",
                    {"Content-Type": "application/javascript"},
                )
            ),
        ]
        resolutions = {
            "a.example.test": (True, ["93.184.216.34"]),
            "b.example.test": (True, ["93.184.216.35"]),
        }
        requested: list[str] = []

        with (
            mock.patch.object(
                safe_transport,
                "resolve_public_addresses",
                side_effect=lambda host, _port: resolutions[host],
            ) as resolver,
            mock.patch.object(
                safe_transport,
                "build_pinned_opener",
                side_effect=openers,
            ) as opener,
        ):
            result = safe_transport.perform_pinned_download(
                "https://a.example.test/app.js",
                _Policy(),
                max_response_bytes=1000,
                max_redirects=3,
                before_request=requested.append,
            )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["final_url"], "https://b.example.test/static/app.js")
        self.assertEqual(result["data"], b"console.log('ok')")
        self.assertEqual(result["pinned_address"], "93.184.216.35")
        self.assertEqual(result["dns_rebinding_protection"], "resolution_pinned_each_hop")
        self.assertFalse(result["environment_proxy_used"])
        self.assertEqual(requested, [
            "https://a.example.test/app.js",
            "https://b.example.test/static/app.js",
        ])
        self.assertEqual(resolver.call_count, 2)
        self.assertEqual(
            [call.args[0] for call in opener.call_args_list],
            ["93.184.216.34", "93.184.216.35"],
        )
        self.assertEqual(len(result["transport_hops"]), 2)

    def test_cross_origin_redirect_strips_sensitive_headers(self) -> None:
        headers = {
            "Authorization": "Bearer secret",
            "Cookie": "session=secret",
            "X-API-Key": "secret-key",
            "X-Company-Session": "custom-secret",
            "Accept-Language": "en",
        }
        sanitized = safe_transport._redirect_headers(
            headers,
            previous_url="https://a.example.test/start",
            next_url="https://b.example.test/final",
        )
        self.assertNotIn("Authorization", sanitized)
        self.assertNotIn("Cookie", sanitized)
        self.assertNotIn("X-API-Key", sanitized)
        self.assertNotIn("X-Company-Session", sanitized)
        self.assertEqual(sanitized["Accept-Language"], "en")

        same_origin = safe_transport._redirect_headers(
            headers,
            previous_url="https://a.example.test/start",
            next_url="https://a.example.test/final",
        )
        self.assertEqual(same_origin["Authorization"], "Bearer secret")
        self.assertEqual(same_origin["Cookie"], "session=secret")

    def test_https_to_http_redirect_is_blocked_before_second_connect(self) -> None:
        redirect = urllib.error.HTTPError(
            "https://a.example.test/start",
            302,
            "Found",
            {"Location": "http://a.example.test/plain"},
            io.BytesIO(b""),
        )
        with (
            mock.patch.object(
                safe_transport,
                "resolve_public_addresses",
                return_value=(True, ["93.184.216.34"]),
            ) as resolver,
            mock.patch.object(
                safe_transport,
                "build_pinned_opener",
                return_value=_Opener(redirect),
            ) as opener,
        ):
            result = safe_transport.perform_pinned_download(
                "https://a.example.test/start",
                _Policy(),
                headers={"Authorization": "Bearer secret"},
                max_response_bytes=1000,
            )

        self.assertEqual(result["transport_status"], "stopped_for_safety")
        self.assertEqual(result["error"], "redirect_scheme_downgrade_blocked")
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(opener.call_count, 1)

    def test_pinned_download_blocks_out_of_scope_redirect_before_second_resolution(self) -> None:
        redirect = urllib.error.HTTPError(
            "https://a.example.test/app.js",
            302,
            "Found",
            {"Location": "https://outside.test/steal"},
            io.BytesIO(b""),
        )
        with (
            mock.patch.object(
                safe_transport,
                "resolve_public_addresses",
                return_value=(True, ["93.184.216.34"]),
            ) as resolver,
            mock.patch.object(
                safe_transport,
                "build_pinned_opener",
                return_value=_Opener(redirect),
            ),
        ):
            result = safe_transport.perform_pinned_download(
                "https://a.example.test/app.js",
                _Policy(),
                max_response_bytes=1000,
            )

        self.assertEqual(result["status_code"], 302)
        self.assertEqual(result["transport_status"], "stopped_for_safety")
        self.assertEqual(result["error"], "redirect_outside_scope")
        self.assertTrue(result["redirect_outside_scope"])
        self.assertEqual(resolver.call_count, 1)

    def test_pinned_download_blocks_non_public_resolution_without_opening_socket(self) -> None:
        with (
            mock.patch.object(
                safe_transport,
                "resolve_public_addresses",
                return_value=(False, ["127.0.0.1"]),
            ),
            mock.patch.object(
                safe_transport,
                "build_pinned_opener",
            ) as opener,
        ):
            result = safe_transport.perform_pinned_download(
                "https://a.example.test/app.js",
                _Policy(),
                max_response_bytes=1000,
            )
        self.assertEqual(result["transport_status"], "stopped_for_safety")
        self.assertEqual(result["error"], "non_public_resolution_blocked")
        opener.assert_not_called()

    def test_tls_peer_collection_connects_to_pinned_ip_and_keeps_sni(self) -> None:
        raw_socket = object()
        raw_cm = mock.MagicMock()
        raw_cm.__enter__.return_value = raw_socket
        tls_socket = mock.MagicMock()
        tls_socket.getpeercert.return_value = {
            "serialNumber": "01",
            "subjectAltName": (("DNS", "example.test"),),
        }
        tls_cm = mock.MagicMock()
        tls_cm.__enter__.return_value = tls_socket
        ssl_context = mock.MagicMock()
        ssl_context.wrap_socket.return_value = tls_cm

        with (
            mock.patch.object(
                safe_transport,
                "resolve_public_addresses",
                return_value=(True, ["93.184.216.34"]),
            ),
            mock.patch.object(
                safe_transport.socket,
                "create_connection",
                return_value=raw_cm,
            ) as connect,
            mock.patch.object(
                safe_transport.ssl,
                "create_default_context",
                return_value=ssl_context,
            ),
        ):
            result = safe_transport.fetch_pinned_tls_peer(
                "https://example.test/",
                _Policy(),
                timeout=3,
            )

        connect.assert_called_once_with(("93.184.216.34", 443), timeout=3.0)
        ssl_context.wrap_socket.assert_called_once_with(
            raw_socket,
            server_hostname="example.test",
        )
        self.assertEqual(result["certificate"]["serialNumber"], "01")
        self.assertEqual(result["pinned_address"], "93.184.216.34")
        self.assertEqual(result["dns_rebinding_protection"], "resolution_pinned")

    def test_policy_credentials_are_https_only(self) -> None:
        policy = SimpleNamespace(
            headers={
                "Authorization": "Bearer secret",
                "X-Company-Session": "custom-secret",
            }
        )
        self.assertEqual(
            _policy_headers_for_url(policy, "http://example.test/private"),
            {},
        )
        self.assertEqual(
            _policy_headers_for_url(policy, "https://example.test/private"),
            policy.headers,
        )

    def test_origin_probe_never_sends_policy_credentials_over_http(self) -> None:
        ctx = SimpleNamespace(
            policy=SimpleNamespace(
                headers={
                    "Authorization": "Bearer secret",
                    "X-Company-Session": "custom-secret",
                },
                url_in_scope=lambda _url: True,
                limits=SimpleNamespace(http_workers=8),
            ),
            budget=_Budget(),
        )
        seen: list[dict[str, str]] = []

        def fake_transport(item, _policy, **kwargs):
            seen.append(dict(item.get("headers") or {}))
            observation = kwargs["observation"]
            return (
                observation(
                    item["method"],
                    item["url"],
                    200,
                    {"Content-Type": "text/html"},
                    b"",
                    "",
                ),
                "ok",
            )

        with mock.patch("stages.perform_pinned_request", side_effect=fake_transport):
            _origin_probe_one(ctx, "http://example.test")
            _origin_probe_one(ctx, "https://example.test")

        self.assertEqual(seen[0], {})
        self.assertEqual(seen[1]["Authorization"], "Bearer secret")
        self.assertEqual(seen[1]["X-Company-Session"], "custom-secret")

    def test_external_recon_tools_never_receive_policy_credentials(self) -> None:
        for fn in (
            stages.stage_urls,
            stages.stage_fingerprint,
            stages.stage_nuclei,
        ):
            source = inspect.getsource(fn)
            self.assertNotIn("header_args(ctx.policy.headers)", source)
            self.assertNotIn("ctx.policy.headers.items()", source)

        self.assertIn(
            "_policy_headers_for_url",
            inspect.getsource(stages._download_url),
        )
        self.assertIn(
            "_policy_headers_for_url",
            inspect.getsource(stages._safe_validate_endpoint),
        )

    def test_origin_probe_falls_back_to_tiny_get_after_inconclusive_head(self) -> None:
        ctx = _probe_ctx()
        methods: list[str] = []

        def fake_transport(item, _policy, **kwargs):
            methods.append(item["method"])
            observation = kwargs["observation"]
            if item["method"] == "HEAD":
                return (
                    observation("HEAD", item["url"], 0, {}, b"", "timeout"),
                    "error",
                )
            return (
                observation(
                    "GET",
                    item["url"],
                    200,
                    {"Content-Type": "text/html"},
                    b"x",
                    "",
                ),
                "ok",
            )

        with mock.patch("stages.perform_pinned_request", side_effect=fake_transport):
            result = _origin_probe_one(ctx, "https://example.test")

        self.assertEqual(methods, ["HEAD", "GET"])
        self.assertEqual(ctx.budget.used, 2)
        self.assertEqual(result["method"], "GET")
        self.assertTrue(result["live"])
        self.assertTrue(result["head_fallback"])
        self.assertEqual(result["head_status_code"], 0)

    def test_origin_probe_does_not_retry_after_safety_stop(self) -> None:
        ctx = _probe_ctx()
        methods: list[str] = []

        def fake_transport(item, _policy, **kwargs):
            methods.append(item["method"])
            observation = kwargs["observation"]
            return (
                observation(
                    item["method"],
                    item["url"],
                    0,
                    {},
                    b"",
                    "non_public_resolution_blocked",
                ),
                "stopped_for_safety",
            )

        with mock.patch("stages.perform_pinned_request", side_effect=fake_transport):
            result = _origin_probe_one(ctx, "https://example.test")

        self.assertEqual(methods, ["HEAD"])
        self.assertEqual(ctx.budget.used, 1)
        self.assertFalse(result["live"])

    def test_katana_plan_stays_inside_reserved_rate_duration_envelope(self) -> None:
        origins = [
            "https://a.example.test",
            "https://b.example.test:8443",
            "http://c.example.test",
        ]
        plan = _katana_crawl_plan(
            origins,
            remaining_requests=90,
            request_rate=20,
            timeout_seconds=600,
            http_threads=20,
            max_urls=10000,
        )
        self.assertEqual(plan["reservation"], 90)
        self.assertEqual(len(plan["origins"]), 3)
        self.assertLessEqual(
            plan["rate_limit"] * plan["crawl_seconds"] * len(plan["origins"]),
            plan["reservation"],
        )
        self.assertLessEqual(plan["concurrency"], 5)

        scope = _katana_scope_regex(origins)
        self.assertRegex("https://a.example.test/admin", scope)
        self.assertRegex("https://b.example.test:8443/api", scope)
        self.assertNotRegex("https://other.example.test/admin", scope)
        self.assertNotRegex("https://a.example.test:9443/admin", scope)

    def test_katana_plan_skips_when_http_budget_is_exhausted(self) -> None:
        plan = _katana_crawl_plan(
            ["https://a.example.test"],
            remaining_requests=0,
            request_rate=20,
            timeout_seconds=600,
            http_threads=20,
            max_urls=10000,
        )
        self.assertEqual(plan["origins"], [])
        self.assertEqual(plan["reservation"], 0)

    def test_stage_network_helpers_no_longer_bypass_shared_transport(self) -> None:
        download_source = inspect.getsource(stages._download_url)
        tls_source = inspect.getsource(stages._tls_certificate_info)
        url_stage_source = inspect.getsource(stages.stage_urls)

        self.assertIn("perform_pinned_download", download_source)
        self.assertNotIn("urllib.request", download_source)
        self.assertNotIn("urlopen(", download_source)
        self.assertIn("fetch_pinned_tls_peer", tls_source)
        self.assertNotIn("socket.create_connection", tls_source)
        for token in ('"-cs"', '"-ct"', '"-mrs"', '"-retry"', '"-p"'):
            self.assertIn(token, url_stage_source)
        self.assertNotIn(
            'ctx.budget.consume("http_requests", min(katana_observed',
            url_stage_source,
        )


if __name__ == "__main__":
    unittest.main()
