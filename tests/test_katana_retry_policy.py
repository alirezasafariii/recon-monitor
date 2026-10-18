from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

APP = Path(__file__).resolve().parents[1] / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from katana_reliability import (
    THROTTLE_COOLDOWN_SECONDS,
    classify_katana_request_errors,
    frontier_reduction_observed,
    katana_host,
    load_throttle_state,
    register_throttling,
)


class KatanaRetryPolicyTests(unittest.TestCase):
    def test_error_classification_matches_actual_hollister_error_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "request-errors.jsonl"
            path.write_text("\n".join([
                json.dumps({"endpoint": "https://h.example.test/login",
                            "error": 'Get "https://h.example.test": cause="no address found for host"'}),
                json.dumps({"endpoint": "https://h.example.test/",
                            "error": "HTTP 429; origin crawl stopped for throttling"}),
                json.dumps({"endpoint": "https://h.example.test/",
                            "error": "context canceled"}),
                json.dumps({"endpoint": "https://other.example.test/",
                            "error": "context canceled"}),
            ]), encoding="utf-8")
            result = classify_katana_request_errors(path, ["https://h.example.test"])
            self.assertEqual(result["counts"],
                             {"dns_failure": 1, "http_429": 1, "cancelled": 2})
            self.assertEqual(result["throttled_hosts"], ["h.example.test"])

    def test_http_429_conservatively_defers_unknown_endpoint_for_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "error.jsonl"
            p.write_text(json.dumps({"error": "HTTP 429; throttled",
                                    "endpoint": "https://unrelated.invalid"}) + "\n")
            result = classify_katana_request_errors(
                p, ["http://one.example.test", "https://two.example.test"],
            )
            self.assertEqual(result["throttled_hosts"],
                             ["one.example.test", "two.example.test"])

    def test_cooldown_is_host_level_and_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "katana-throttle-state.json"
            state = {}
            now = 12345.0
            register_throttling(state, ["h.example.test"], now=now)
            path.write_text(json.dumps({"version": 1, "hosts": state}))
            self.assertGreaterEqual(state["h.example.test"]["retry_not_before"],
                                    now + THROTTLE_COOLDOWN_SECONDS)
            self.assertIn(katana_host("http://h.example.test"), load_throttle_state(path, now=now + 15))
            self.assertNotIn("h.example.test",
                             load_throttle_state(path, now=now + THROTTLE_COOLDOWN_SECONDS + 1))
            self.assertEqual(load_throttle_state(Path(tmp) / "missing.json"), {})

    def test_frontier_reduction_is_progress_even_with_same_pending_origin(self):
        def snapshot(pending):
            return [{
                "origin_urls": ["https://h.example.test"],
                "origin_completion": {
                    "key": {"stop_reason": "deadline",
                            "counters": {"pending_items": pending, "active_items": 0}}
                }
            }]
        self.assertTrue(frontier_reduction_observed(snapshot(178), snapshot(100)))
        self.assertFalse(frontier_reduction_observed(snapshot(4), snapshot(4)))
        self.assertFalse(frontier_reduction_observed(snapshot(4), snapshot(8)))

    def test_429_blocks_resume_without_any_probe_or_crawl(self):
        # Simulate the real custom completion contract. No real networking.
        from core import TargetPolicy
        from stages import stage_urls
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "current"
            changes = root / "changes"
            current.mkdir()
            changes.mkdir()
            (current / "resolved-hosts.txt").write_text("example.test\n")
            policy = TargetPolicy.from_dict({
                "name": "example.test",
                "roots": ["example.test"],
                "include": [r"(^|\.)example\.test$"],
                "analysis": {"asset_graph": False},
                "limits": {"timeout_seconds": 600, "request_rate": 3},
            })
            db = MagicMock()
            db.upsert_url.return_value = False
            calls = []
            probes = []

            def runner(args, **kwargs):
                out = Path(kwargs["output_path"])
                out.write_text("")
                if "-h" in args:
                    out.write_text(
                        "-recon-completion-log EXPERIMENTAL v1 per-origin standard-engine completion JSONL\n"
                        "-recon-checkpoint-dir EXPERIMENTAL v1 durable standard-engine GET frontier checkpoint\n"
                    )
                    return SimpleNamespace(returncode=0, timed_out=False, lines=0, duration=0.01)
                calls.append(args)
                Path(args[args.index("-elog") + 1]).write_text(json.dumps({
                    "endpoint": "https://example.test/",
                    "error": "HTTP 429; origin crawl stopped for throttling",
                }) + "\n")
                return SimpleNamespace(returncode=0, timed_out=False,
                                       lines=0, duration=0.1)

            ctx = SimpleNamespace(
                current=current, changes=changes, policy=policy, db=db,
                runner=SimpleNamespace(run=runner), budget=None,
                run_id="offline-429", logger=MagicMock(), progress=MagicMock(),
            )

            def probe(_ctx, urls):
                probes.append(list(urls))
                return ["https://example.test"], []

            def incomplete(_path, origins, **_kwargs):
                from stages import origin_key
                return {origin_key(origin): {
                    "status": "partial", "stop_reason": "request_errors",
                    "counters": {"pending_items": 4, "active_items": 0}
                } for origin in origins}

            with patch("stages.tool_path", side_effect=lambda name: "katana" if name == "katana" else None), \
                 patch("stages._probe_live_origins", side_effect=probe), \
                 patch("stages.read_completion", side_effect=incomplete):
                first = stage_urls(ctx)
                second = stage_urls(ctx)
            self.assertEqual(len(calls), 1)
            self.assertEqual(probes[-1], [])
            self.assertEqual(first["collection_status"], "partial")
            self.assertEqual(second["collection_status"], "partial")
            self.assertEqual(first["katana_request_error_categories_this_attempt"].get("http_429"), 1)
            self.assertEqual(second["katana_status"], "throttled")
            self.assertGreater(second["katana_deferred_origins"], 0)
            self.assertEqual(second["katana_batches_this_attempt"], 0)


if __name__ == "__main__":
    unittest.main()
