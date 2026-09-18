from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from stages import (
    _download_url,
    stage_javascript,
)


class _Config:
    def get(self, key, default=None):
        return default


class _Policy:
    headers = {}
    limits = SimpleNamespace(timeout_seconds=30)

    def url_in_scope(self, url: str) -> bool:
        return str(url).startswith("https://example.test/")


class _Budget:
    def __init__(self) -> None:
        self.http_requests = 0
        self.download_bytes = 0

    def consume(self, metric: str, amount: int = 1):
        if metric == "http_requests":
            self.http_requests += amount
        elif metric == "download_bytes":
            self.download_bytes += amount
        return amount, 1000000


def _ctx():
    return SimpleNamespace(
        config=_Config(),
        policy=_Policy(),
        budget=_Budget(),
    )


def _transport_status(code: int, *, body: bytes = b"", location: str = "", error: str = ""):
    def fake(item, _policy, **kwargs):
        observation = kwargs["observation"]
        headers = {}
        if location:
            headers["Location"] = location
        row = observation(
            item["method"],
            item["url"],
            code,
            headers,
            body,
            error or ("http_error" if code >= 400 else ""),
        )
        row["dns_rebinding_protection"] = "resolution_pinned"
        row["environment_proxy_used"] = False
        row["pinned_address"] = "203.0.113.10"
        return row, "ok"

    return fake


class JavascriptNotFoundTests(unittest.TestCase):

    def test_404_is_not_found_not_runtime_error(self):
        ctx = _ctx()
        with mock.patch(
            "stages.perform_pinned_request",
            side_effect=_transport_status(404),
        ):
            result = _download_url(
                ctx,
                "https://example.test/app.js",
                100000,
            )

        self.assertTrue(result["not_found"])
        self.assertEqual(result["status_code"], 404)
        self.assertNotIn("error", result)
        self.assertEqual(ctx.budget.http_requests, 1)


    def test_410_is_not_found_not_runtime_error(self):
        with mock.patch(
            "stages.perform_pinned_request",
            side_effect=_transport_status(410),
        ):
            result = _download_url(
                _ctx(),
                "https://example.test/old.js",
                100000,
            )

        self.assertTrue(result["not_found"])
        self.assertEqual(result["status_code"], 410)
        self.assertNotIn("error", result)


    def test_403_remains_error(self):
        with mock.patch(
            "stages.perform_pinned_request",
            side_effect=_transport_status(403),
        ):
            result = _download_url(
                _ctx(),
                "https://example.test/private.js",
                100000,
            )

        self.assertFalse(result.get("not_found", False))
        self.assertEqual(result["status_code"], 403)
        self.assertIn("error", result)


    def test_in_scope_redirect_is_reissued_through_pinned_transport(self):
        ctx = _ctx()
        seen = []

        def fake(item, _policy, **kwargs):
            seen.append(item["url"])
            observation = kwargs["observation"]
            if len(seen) == 1:
                row = observation(
                    "GET",
                    item["url"],
                    302,
                    {"Location": "/assets/app-v2.js"},
                    b"",
                    "http_error",
                )
            else:
                row = observation(
                    "GET",
                    item["url"],
                    200,
                    {"Content-Type": "application/javascript"},
                    b"console.log('ok')",
                    "",
                )
            row["dns_rebinding_protection"] = "resolution_pinned"
            row["environment_proxy_used"] = False
            return row, "ok"

        with mock.patch("stages.perform_pinned_request", side_effect=fake):
            result = _download_url(
                ctx,
                "https://example.test/app.js",
                100000,
            )

        self.assertEqual(
            seen,
            [
                "https://example.test/app.js",
                "https://example.test/assets/app-v2.js",
            ],
        )
        self.assertEqual(
            result["final_url"],
            "https://example.test/assets/app-v2.js",
        )
        self.assertEqual(result["data"], b"console.log('ok')")
        self.assertEqual(result["redirect_chain"], ["https://example.test/app.js"])
        self.assertEqual(ctx.budget.http_requests, 2)
        self.assertEqual(ctx.budget.download_bytes, len(result["data"]))


    def test_out_of_scope_redirect_is_blocked_without_second_request(self):
        ctx = _ctx()
        seen = []

        def fake(item, _policy, **kwargs):
            seen.append(item["url"])
            observation = kwargs["observation"]
            row = observation(
                "GET",
                item["url"],
                302,
                {"Location": "https://outside.test/app.js"},
                b"",
                "http_error",
            )
            row["redirect_outside_scope"] = True
            return row, "ok"

        with mock.patch("stages.perform_pinned_request", side_effect=fake):
            result = _download_url(
                ctx,
                "https://example.test/app.js",
                100000,
            )

        self.assertEqual(seen, ["https://example.test/app.js"])
        self.assertTrue(result["redirect_outside_scope"])
        self.assertIn("redirect left authorized scope", result["error"])


    def test_oversized_download_fails_closed_without_persisting_partial_body(self):
        ctx = _ctx()

        def fake(item, _policy, **kwargs):
            observation = kwargs["observation"]
            row = observation(
                "GET",
                item["url"],
                200,
                {"Content-Type": "application/javascript"},
                b"x" * 10,
                "response_budget_exceeded",
            )
            row["dns_rebinding_protection"] = "resolution_pinned"
            return row, "stopped_for_safety"

        with mock.patch("stages.perform_pinned_request", side_effect=fake):
            result = _download_url(
                ctx,
                "https://example.test/app.js",
                5,
            )

        self.assertIn("Content exceeded limit", result["error"])
        self.assertEqual(result["transport_status"], "stopped_for_safety")
        self.assertEqual(ctx.budget.download_bytes, 0)


    def test_download_uses_shared_pinned_transport_not_direct_urllib(self):
        source = inspect.getsource(_download_url)
        self.assertIn("perform_pinned_request", source)
        self.assertNotIn("urllib.request", source)
        self.assertNotIn("urlopen(", source)
        self.assertIn("redirect limit exceeded", source)


    def test_javascript_stage_completes_not_found_work(self):
        source = inspect.getsource(stage_javascript)

        self.assertIn('result.get("not_found")', source)
        self.assertIn("work_queue.finish", source)
        self.assertIn('"javascript-not-found.jsonl"', source)
        self.assertIn('"not_found": len(not_found)', source)


if __name__ == "__main__":
    unittest.main()
