from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import recon_monitor
from dependency_advisory_catalog_sync import build_catalog_from_pages


def _fixture_payload():
    row = {
        "ghsa_id": "GHSA-2345-6789-cfgh",
        "cve_id": "CVE-2026-12345",
        "html_url": "https://github.com/advisories/GHSA-2345-6789-cfgh",
        "severity": "high",
        "published_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "reviewed_at": "2026-01-02T00:00:00Z",
        "withdrawn_at": None,
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "demo"},
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": {"identifier": "2.0.0"},
            }
        ],
    }
    return build_catalog_from_pages(
        fetch_page=lambda _url: ([row], ""),
        now="2026-09-18T00:00:00Z",
    )


class DependencyAdvisoryCatalogCliTests(unittest.TestCase):
    def test_parser_exposes_catalog_status_and_sync(self):
        parser = recon_monitor.build_parser()
        status = parser.parse_args(["analysis", "advisory-catalog-status"])
        sync = parser.parse_args(
            [
                "analysis",
                "advisory-catalog-sync",
                "--advisory-max-pages",
                "12",
                "--advisory-update-manifest",
            ]
        )
        self.assertEqual(status.action, "advisory-catalog-status")
        self.assertEqual(sync.action, "advisory-catalog-sync")
        self.assertEqual(sync.advisory_max_pages, 12)
        self.assertTrue(sync.advisory_update_manifest)

    def test_status_is_offline_and_never_claims_catalog_miss_is_safe(self):
        parser = recon_monitor.build_parser()
        args = parser.parse_args(["analysis", "advisory-catalog-status"])
        payload = recon_monitor.advisory_catalog_status_cli_payload(args)
        self.assertEqual(payload["action"], "advisory-catalog-status")
        self.assertEqual(payload["safety"]["network_requests"], 0)
        self.assertFalse(payload["safety"]["catalog_miss_means_safe"])
        self.assertFalse(payload["status"]["catalog_is_exhaustive"])

    def test_sync_cli_uses_explicit_sync_layer_and_writes_snapshot(self):
        payload = _fixture_payload()
        parser = recon_monitor.build_parser()
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "catalog.json"
            args = parser.parse_args(
                [
                    "analysis",
                    "advisory-catalog-sync",
                    "--advisory-catalog-output",
                    str(output),
                    "--advisory-max-pages",
                    "3",
                ]
            )
            with mock.patch.object(
                recon_monitor,
                "sync_dependency_advisory_catalog",
                return_value=payload,
            ) as sync:
                result = recon_monitor.advisory_catalog_sync_cli_payload(args)
            sync.assert_called_once()
            self.assertEqual(
                sync.call_args.kwargs["max_pages"],
                3,
            )
            self.assertTrue(output.exists())
            self.assertTrue(result["summary"]["sync_complete"])
            self.assertEqual(
                result["safety"]["network_scope"],
                "github_public_advisory_api_only",
            )
            self.assertFalse(
                result["safety"]["runtime_scan_network_dependency_added"]
            )
            self.assertFalse(result["safety"]["target_contact_performed"])


if __name__ == "__main__":
    unittest.main()
