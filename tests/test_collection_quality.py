from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from collection_quality import snapshot_collection_quality


class FakeDB:
    def __init__(self, stages):
        self.stages = stages

    def one(self, _sql, params=()):
        stage = params[-1]
        value = self.stages.get(stage)
        if value is None:
            return None
        return {
            "status": value.get("status", "success"),
            "metrics_json": json.dumps(value.get("metrics", {})),
            "error": value.get("error"),
        }


def make_ctx(root: Path, stages, *, modules=None, max_urls=10000, max_js_files=200):
    policy = SimpleNamespace(
        name="example.test",
        modules=modules
        or {
            "dns": True,
            "urls": True,
            "javascript": True,
        },
        limits=SimpleNamespace(max_urls=max_urls, max_js_files=max_js_files),
    )
    run_dir = root / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        db=FakeDB(stages),
        run_id="RUN-QUALITY",
        policy=policy,
        run_dir=run_dir,
    )


class CollectionQualityTests(unittest.TestCase):
    def test_dns_fallback_visibility_is_degraded(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                {
                    "dns": {
                        "metrics": {
                            "successful_rrtypes": ["A", "AAAA"],
                            "wildcard_candidates": 0,
                        }
                    }
                },
            )
            result = snapshot_collection_quality(ctx, persist=False)
            dns = result["dimensions"]["dns"]
            self.assertEqual(dns["status"], "degraded")
            self.assertEqual(dns["observable"], ["A", "AAAA"])
            self.assertEqual(dns["not_collected"], ["CNAME", "NS"])

    def test_url_truncation_is_partial(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                {
                    "urls": {
                        "metrics": {
                            "urls": 10000,
                            "truncated": True,
                        }
                    }
                },
                max_urls=10000,
            )
            result = snapshot_collection_quality(ctx, persist=False)
            urls = result["dimensions"]["urls"]
            self.assertEqual(urls["status"], "partial")
            self.assertTrue(urls["truncated"])
            self.assertEqual(urls["limit"], 10000)
            self.assertIn("urls_beyond_configured_limit", urls["not_collected"])

    def test_javascript_download_gaps_are_partial(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                {
                    "javascript": {
                        "metrics": {
                            "files": 10,
                            "downloaded": 7,
                            "errors": 3,
                        }
                    }
                },
            )
            result = snapshot_collection_quality(ctx, persist=False)
            javascript = result["dimensions"]["javascript"]
            self.assertEqual(javascript["status"], "partial")
            self.assertEqual(javascript["downloaded"], 7)
            self.assertEqual(javascript["errors"], 3)
            self.assertIn("undownloaded_javascript_files", javascript["not_collected"])

    def test_zero_javascript_run_without_errors_is_complete_no_work(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                {
                    "dns": {
                        "metrics": {
                            "successful_rrtypes": ["A", "AAAA", "CNAME", "NS"],
                        }
                    },
                    "urls": {"metrics": {"urls": 4, "truncated": False}},
                    "javascript": {
                        "metrics": {
                            "files": 0,
                            "downloaded": 0,
                        }
                    },
                },
            )
            result = snapshot_collection_quality(ctx, persist=False)
            javascript = result["dimensions"]["javascript"]
            self.assertEqual(javascript["status"], "complete")
            self.assertEqual(javascript["files_selected"], 0)
            self.assertEqual(javascript["downloaded"], 0)
            self.assertEqual(javascript["errors"], 0)
            self.assertEqual(result["status"], "complete")

    def test_nonempty_javascript_run_without_errors_remains_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                {
                    "javascript": {
                        "metrics": {
                            "files": 2,
                            "downloaded": 2,
                        }
                    }
                },
            )
            result = snapshot_collection_quality(ctx, persist=False)
            javascript = result["dimensions"]["javascript"]
            self.assertEqual(javascript["status"], "unknown")

    def test_historical_success_without_completeness_metrics_is_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                {
                    "dns": {"metrics": {}},
                    "urls": {"metrics": {}},
                    "javascript": {"metrics": {}},
                },
            )
            result = snapshot_collection_quality(ctx, persist=False)
            self.assertEqual(result["status"], "unknown")
            for name in ("dns", "urls", "javascript"):
                self.assertEqual(result["dimensions"][name]["status"], "unknown")

    def test_snapshot_is_diagnostic_only_and_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                {
                    "dns": {
                        "metrics": {
                            "successful_rrtypes": ["A", "AAAA", "CNAME", "NS"],
                        }
                    },
                    "urls": {"metrics": {"urls": 42, "truncated": False}},
                    "javascript": {
                        "metrics": {
                            "files": 3,
                            "downloaded": 3,
                            "errors": 0,
                        }
                    },
                },
            )
            result = snapshot_collection_quality(ctx)
            self.assertEqual(result["status"], "complete")
            self.assertTrue(result["diagnostic_only"])
            self.assertFalse(result["affects_admission"])
            self.assertFalse(result["affects_candidate_promotion"])
            self.assertIsNone(result["numeric_score"])
            output = Path(result["output"])
            self.assertTrue(output.exists())
            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(persisted["run_id"], "RUN-QUALITY")
            self.assertEqual(persisted["dimensions"]["dns"]["status"], "complete")

    def test_disabled_dimension_is_skipped_not_missing(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                {},
                modules={"dns": False, "urls": False, "javascript": False},
            )
            result = snapshot_collection_quality(ctx, persist=False)
            self.assertEqual(result["status"], "unknown")
            self.assertTrue(
                all(value["status"] == "skipped" for value in result["dimensions"].values())
            )


if __name__ == "__main__":
    unittest.main()
