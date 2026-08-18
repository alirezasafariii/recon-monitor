from __future__ import annotations

import inspect
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

from stages import (
    _download_url,
    stage_javascript,
)


class _Config:
    def get(self, key, default=None):
        return default


class _FakeOpener:
    def __init__(self, status_code):
        self.status_code = status_code

    def open(self, request, timeout=None):
        raise urllib.error.HTTPError(
            request.full_url,
            self.status_code,
            f"HTTP {self.status_code}",
            hdrs=None,
            fp=None,
        )


def _ctx():
    return SimpleNamespace(
        config=_Config(),
        policy=SimpleNamespace(
            headers={},
            limits=SimpleNamespace(
                timeout_seconds=30,
            ),
        ),
        budget=None,
    )


class JavascriptNotFoundTests(unittest.TestCase):

    def test_404_is_not_found_not_runtime_error(self):
        with mock.patch(
            "stages.urllib.request.build_opener",
            return_value=_FakeOpener(404),
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
            "stages.urllib.request.build_opener",
            return_value=_FakeOpener(410),
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
            "stages.urllib.request.build_opener",
            return_value=_FakeOpener(403),
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
