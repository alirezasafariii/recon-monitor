from __future__ import annotations

import inspect
import sys
import urllib.parse
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import TargetPolicy
from stages import (
    _origin_probe_one,
    _probe_live_origins,
    _select_diverse_urls,
    _web_origin_for_port,
    stage_dns,
    stage_ports,
    stage_urls,
)


class _Budget:
    def __init__(self) -> None:
        self.used = 0

    def consume(self, metric: str, amount: int = 1):
        if metric == "http_requests":
            self.used += amount
        return self.used, 100


class _Progress:
    def update(self, *_args, **_kwargs) -> None:
        pass


def _ctx():
    policy = TargetPolicy.from_dict(
        {
            "name": "example.com",
            "roots": ["example.com"],
            "include": [r"(^|\.)example\.com$"],
            "limits": {"http_workers": 8},
        }
    )
    return SimpleNamespace(policy=policy, budget=_Budget(), progress=_Progress())


class ReconP1CollectionTests(unittest.TestCase):
    def test_diverse_url_selection_preserves_hosts_before_extra_depth(self) -> None:
        candidates = {
            "https://a.example.com/zzz": {"wayback"},
            "https://a.example.com/api/admin/users?role=all": {"katana"},
            "https://b.example.com/public": {"wayback"},
            "https://c.example.com/": {"base"},
        }
        selected = _select_diverse_urls(candidates, 3)
        hosts = {urllib.parse.urlsplit(url).hostname for url in selected}
        self.assertEqual(hosts, {"a.example.com", "b.example.com", "c.example.com"})

    def test_sensitive_live_path_wins_within_same_host(self) -> None:
        candidates = {
            "https://api.example.com/about": {"wayback"},
            "https://api.example.com/api/admin/export?account=1": {"katana"},
        }
        selected = _select_diverse_urls(candidates, 1)
        self.assertEqual(selected, ["https://api.example.com/api/admin/export?account=1"])

    def test_common_open_web_ports_become_origins(self) -> None:
        self.assertEqual(_web_origin_for_port("api.example.com", 80), "http://api.example.com")
        self.assertEqual(_web_origin_for_port("api.example.com", 443), "https://api.example.com")
        self.assertEqual(_web_origin_for_port("api.example.com", 8080), "http://api.example.com:8080")
        self.assertEqual(_web_origin_for_port("api.example.com", 8443), "https://api.example.com:8443")
        self.assertEqual(_web_origin_for_port("api.example.com", 22), "")

    def test_origin_probe_uses_shared_no_redirect_transport_contract(self) -> None:
        ctx = _ctx()
        seen = {}

        def fake_transport(item, policy, **kwargs):
            seen["item"] = dict(item)
            observation = kwargs["observation"]
            row = observation(
                "HEAD",
                item["url"],
                302,
                {"Content-Type": "text/html", "Location": "https://outside.test/login"},
                b"",
                "http_error",
            )
            row["redirect_outside_scope"] = True
            row["dns_rebinding_protection"] = "resolution_pinned"
            return row, "ok"

        with patch("stages.perform_pinned_request", side_effect=fake_transport):
            result = _origin_probe_one(ctx, "https://app.example.com")

        self.assertEqual(seen["item"]["method"], "HEAD")
        self.assertEqual(result["status_code"], 302)
        self.assertTrue(result["live"])
        self.assertTrue(result["redirect_outside_scope"])
        self.assertEqual(result["dns_rebinding_protection"], "resolution_pinned")
        self.assertEqual(ctx.budget.used, 1)

    def test_out_of_scope_redirect_is_not_a_crawl_origin(self) -> None:
        ctx = _ctx()

        def fake_probe(_ctx, url):
            return {
                "url": url,
                "status_code": 302,
                "live": True,
                "redirect_outside_scope": True,
            }

        with patch("stages._origin_probe_one", side_effect=fake_probe):
            live, rows = _probe_live_origins(ctx, ["https://app.example.com"])

        self.assertEqual(live, [])
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["redirect_outside_scope"])

    def test_dns_wildcards_are_classified_but_still_queried(self) -> None:
        source = inspect.getsource(stage_dns)
        self.assertIn('"dns-filtered-hosts.txt"', source)
        self.assertIn('"dns-query-hosts.txt"', source)
        self.assertIn('for host in sorted(hosts)', source)
        self.assertIn('else query_input', source)
        self.assertIn('"wildcard_resolved"', source)
        self.assertIn("wildcard_classification_complete", source)
        self.assertIn("if wildcard_classification_complete:", source)
        self.assertIn("wildcard=0", source)

    def test_port_results_feed_url_pipeline_and_probe_precedes_katana(self) -> None:
        port_source = inspect.getsource(stage_ports)
        url_source = inspect.getsource(stage_urls)
        self.assertIn('"port-web-origins.txt"', port_source)
        self.assertIn('"port-web-origins.txt"', url_source)
        self.assertIn('"origin_redirects_outside_scope"', url_source)
        probe_pos = url_source.index("_probe_live_origins")
        katana_pos = url_source.index('tool_path("katana")')
        self.assertLess(probe_pos, katana_pos)
        self.assertIn("_select_diverse_urls", url_source)

    def test_orchestrator_and_progress_order_ports_before_urls(self) -> None:
        orchestrator = (APP / "recon_monitor_core.py").read_text(encoding="utf-8")
        progress = (APP / "progress_tracking.py").read_text(encoding="utf-8")
        self.assertLess(orchestrator.index('("ports",'), orchestrator.index('("urls",'))
        self.assertLess(progress.index('("ports",'), progress.index('("urls",'))


if __name__ == "__main__":
    unittest.main()
