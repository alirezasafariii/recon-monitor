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


def _ctx():
    return SimpleNamespace(
        config=_Config(),
        policy=SimpleNamespace(
            headers={},
            url_in_scope=lambda url: str(url).startswith("https://example.test/"),
            limits=SimpleNamespace(
                timeout_seconds=30,
            ),
        ),
        budget=None,
    )


class JavascriptNotFoundTests(unittest.TestCase):

    def test_404_is_not_found_not_runtime_error(self):
        with mock.patch(
            "stages.perform_pinned_download",
            return_value={
                "url": "https://example.test/app.js",
                "final_url": "https://example.test/app.js",
                "status_code": 404,
                "headers": {},
                "data": b"",
                "error": "http_error",
                "transport_status": "ok",
                "transport_hops": [],
                "resolved_addresses": ["93.184.216.34"],
                "pinned_address": "93.184.216.34",
                "dns_rebinding_protection": "resolution_pinned_each_hop",
                "environment_proxy_used": False,
                "safe_transport_version": "test",
            },
        ):
            result = _download_url(
                _ctx(),
                "https://example.test/app.js",
                100000,
            )

        self.assertTrue(result["not_found"])
        self.assertEqual(result["status_code"], 404)
        self.assertNotIn("error", result)


    def test_410_is_not_found_not_runtime_error(self):
        with mock.patch(
            "stages.perform_pinned_download",
            return_value={
                "url": "https://example.test/old.js",
                "final_url": "https://example.test/old.js",
                "status_code": 410,
                "headers": {},
                "data": b"",
                "error": "http_error",
                "transport_status": "ok",
                "transport_hops": [],
                "resolved_addresses": ["93.184.216.34"],
                "pinned_address": "93.184.216.34",
                "dns_rebinding_protection": "resolution_pinned_each_hop",
                "environment_proxy_used": False,
                "safe_transport_version": "test",
            },
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
            "stages.perform_pinned_download",
            return_value={
                "url": "https://example.test/private.js",
                "final_url": "https://example.test/private.js",
                "status_code": 403,
                "headers": {},
                "data": b"",
                "error": "http_error",
                "transport_status": "ok",
                "transport_hops": [],
                "resolved_addresses": ["93.184.216.34"],
                "pinned_address": "93.184.216.34",
                "dns_rebinding_protection": "resolution_pinned_each_hop",
                "environment_proxy_used": False,
                "safe_transport_version": "test",
            },
        ):
            result = _download_url(
                _ctx(),
                "https://example.test/private.js",
                100000,
            )

        self.assertFalse(
            result.get("not_found", False)
        )
        self.assertEqual(
            result["status_code"],
            403,
        )
        self.assertIn(
            "error",
            result,
        )


    def test_javascript_stage_completes_not_found_work(self):
        source = inspect.getsource(
            stage_javascript
        )

        self.assertIn(
            'result.get("not_found")',
            source,
        )
        self.assertIn(
            "work_queue.finish",
            source,
        )
        self.assertIn(
            '"javascript-not-found.jsonl"',
            source,
        )
        self.assertIn(
            '"not_found": len(not_found)',
            source,
        )


if __name__ == "__main__":
    unittest.main()
