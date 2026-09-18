from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import TargetPolicy, normalize_url, normalize_url_preserving_semantics
import stages
from stages import (
    _endpoint_candidate_urls,
    _httpx_record,
    _safe_validate_endpoint,
    stage_fingerprint,
    stage_urls,
)


class _Budget:
    def __init__(self) -> None:
        self.used = 0

    def consume(self, metric: str, amount: int = 1):
        if metric == "http_requests":
            self.used += amount
        return self.used, 100


def _ctx():
    policy = TargetPolicy.from_dict(
        {
            "name": "example.com",
            "roots": ["example.com"],
            "include": [r"(^|\.)example\.com$"],
        }
    )
    return SimpleNamespace(policy=policy, budget=_Budget())


class ReconP0HardeningTests(unittest.TestCase):
    def test_relative_endpoint_prefers_javascript_source_origin(self) -> None:
        ctx = _ctx()
        candidates = _endpoint_candidate_urls(
            ctx,
            "/api/v2/account",
            ["https://app.example.com/static/chunks/app.js"],
        )
        self.assertGreaterEqual(len(candidates), 1)
        self.assertEqual(candidates[0][0], "https://app.example.com/api/v2/account")
        self.assertEqual(candidates[0][1], "source_origin")
        self.assertEqual(candidates[0][2], "https://app.example.com/static/chunks/app.js")

    def test_root_fallback_is_only_used_without_source_origin(self) -> None:
        ctx = _ctx()
        candidates = _endpoint_candidate_urls(ctx, "/api/v2/account", [])
        self.assertEqual(candidates[0][0], "https://example.com/api/v2/account")
        self.assertEqual(candidates[0][1], "root_fallback")

    def test_endpoint_validation_uses_shared_pinned_transport(self) -> None:
        ctx = _ctx()
        seen = {}

        def fake_transport(item, policy, **kwargs):
            seen["item"] = dict(item)
            observation = kwargs["observation"]
            result = observation(
                "HEAD",
                item["url"],
                302,
                {"Content-Type": "text/plain", "Location": "https://outside.test/login"},
                b"",
                "http_error",
            )
            result["redirect_outside_scope"] = True
            result["safe_transport_version"] = "test"
            result["dns_rebinding_protection"] = "resolution_pinned"
            return result, "ok"

        with patch("stages.perform_pinned_request", side_effect=fake_transport):
            result = _safe_validate_endpoint(
                ctx,
                "/api/v2/account",
                ["https://app.example.com/static/app.js"],
            )

        self.assertEqual(seen["item"]["url"], "https://app.example.com/api/v2/account")
        self.assertEqual(result["resolution_method"], "source_origin")
        self.assertTrue(result["redirect_outside_scope"])
        self.assertEqual(result["dns_rebinding_protection"], "resolution_pinned")
        self.assertEqual(ctx.budget.used, 1)
        self.assertNotIn("urllib.request.urlopen", inspect.getsource(_safe_validate_endpoint))

    def test_fingerprint_does_not_auto_follow_redirects(self) -> None:
        source = inspect.getsource(stage_fingerprint)
        self.assertNotIn('" -fr"', source)
        self.assertNotIn('"-fr"', source)

    def test_fingerprint_requests_response_headers_without_persisting_sensitive_headers(self) -> None:
        source = inspect.getsource(stage_fingerprint)
        self.assertIn('"-irh"', source)

        url, record = _httpx_record(
            {
                "url": "https://example.com/",
                "status_code": 200,
                "content_type": "text/html",
                "header": {
                    "Content-Security-Policy": "default-src 'self'",
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Frame-Options": "DENY",
                    "Set-Cookie": "session=secret",
                    "Authorization": "Bearer secret",
                    "X-Internal-Debug": "sensitive",
                },
            }
        )
        self.assertEqual(url, "https://example.com/")
        self.assertTrue(record["response_headers_observed"])
        self.assertEqual(
            record["response_headers"]["x-frame-options"],
            "DENY",
        )
        self.assertIn(
            "strict-transport-security",
            record["response_headers"],
        )
        self.assertNotIn("set-cookie", record["response_headers"])
        self.assertNotIn("authorization", record["response_headers"])
        self.assertNotIn("x-internal-debug", record["response_headers"])

    def test_raw_url_evidence_keeps_security_significant_semantics(self) -> None:
        raw = normalize_url_preserving_semantics(
            "HTTPS://Example.COM:443//api/a%2Fb?ref=one&x=2&x=1#fragment"
        )
        self.assertEqual(
            raw,
            "https://example.com//api/a%2Fb?ref=one&x=2&x=1",
        )
        canonical = normalize_url(raw or "")
        self.assertEqual(canonical, "https://example.com/api/a/b?x=1&x=2")
        self.assertNotEqual(raw, canonical)

        source = inspect.getsource(stage_urls)
        self.assertIn('"raw_url": raw_url', source)
        self.assertIn('"canonical_url": canonical_url', source)


if __name__ == "__main__":
    unittest.main()
