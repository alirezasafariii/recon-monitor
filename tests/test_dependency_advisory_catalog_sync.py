from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from dependency_advisory_catalog_sync import (
    build_catalog_from_pages,
    sync_summary,
    update_manifest_entry,
    write_catalog_atomic,
)
from dependency_advisory_matcher import (
    catalog_status,
    match_versioned_technology,
    validate_catalog_payload,
)


def advisory(
    ghsa: str,
    *,
    package: str = "demo",
    ecosystem: str = "npm",
    vulnerable_range: str = "< 2.0.0",
    patched: str = "2.0.0",
    updated_at: str = "2026-01-01T00:00:00Z",
    withdrawn_at: str = "",
):
    return {
        "ghsa_id": ghsa,
        "cve_id": "CVE-2026-12345",
        "html_url": f"https://github.com/advisories/{ghsa}",
        "severity": "high",
        "published_at": "2026-01-01T00:00:00Z",
        "updated_at": updated_at,
        "reviewed_at": updated_at,
        "withdrawn_at": withdrawn_at or None,
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": ecosystem,
                    "name": package,
                },
                "vulnerable_version_range": vulnerable_range,
                "first_patched_version": (
                    {"identifier": patched} if patched else None
                ),
            }
        ],
    }


class DependencyAdvisoryCatalogSyncTests(unittest.TestCase):
    def test_full_cursor_sync_normalizes_dedupes_and_excludes_withdrawn(self):
        first = "https://api.github.com/advisories?cursor=1"
        second = "https://api.github.com/advisories?cursor=2"
        pages = {
            first: (
                [
                    advisory("GHSA-2345-6789-cfgh", package="demo"),
                    advisory(
                        "GHSA-2345-6789-cfgh",
                        package="demo",
                        vulnerable_range=">= 2.1.0, < 2.2.0",
                        patched="2.2.0",
                        updated_at="2026-01-02T00:00:00Z",
                    ),
                ],
                second,
            ),
            second: (
                [
                    advisory(
                        "GHSA-3456-789c-fghj",
                        package="withdrawn",
                        withdrawn_at="2026-01-03T00:00:00Z",
                    ),
                    advisory(
                        "GHSA-4567-89cf-ghjm",
                        package="complex",
                        vulnerable_range=">= 1.0.0-beta.1, < 2.0.0",
                    ),
                ],
                "",
            ),
        }

        def fetch(url):
            if "per_page=100" in url:
                return pages[first]
            return pages[url]

        payload = build_catalog_from_pages(
            fetch_page=fetch,
            alias_registry={"npm:demo": ["DemoJS"]},
            now="2026-09-18T00:00:00Z",
        )
        source = payload["source_snapshot"]
        self.assertTrue(source["sync_complete"])
        self.assertEqual(source["page_count"], 2)
        self.assertEqual(source["source_advisory_count"], 4)
        self.assertEqual(source["withdrawn_excluded_count"], 1)
        self.assertEqual(len(payload["advisories"]), 2)

        demo = next(
            row for row in payload["advisories"]
            if row["product"] == "demo"
        )
        self.assertEqual(
            demo["affected_ranges"],
            ["< 2.0.0", ">= 2.1.0, < 2.2.0"],
        )
        self.assertEqual(demo["patched_versions"], ["2.0.0", "2.2.0"])
        self.assertIn("DemoJS", demo["aliases"])
        self.assertTrue(demo["range_match_supported"])

        complex_entry = next(
            row for row in payload["advisories"]
            if row["product"] == "complex"
        )
        self.assertFalse(complex_entry["range_match_supported"])

        validation = validate_catalog_payload(payload)
        self.assertTrue(validation["valid"])
        self.assertTrue(validation["integrity_valid"])

    def test_page_cap_marks_snapshot_partial_not_complete(self):
        calls = 0

        def fetch(_url):
            nonlocal calls
            calls += 1
            return (
                [advisory("GHSA-5678-9cfg-hjmp")],
                "https://api.github.com/advisories?after=next",
            )

        payload = build_catalog_from_pages(
            fetch_page=fetch,
            max_pages=1,
            now="2026-09-18T00:00:00Z",
        )
        self.assertEqual(calls, 1)
        self.assertFalse(payload["source_snapshot"]["sync_complete"])
        self.assertEqual(
            payload["completeness"],
            "github_reviewed_partial_snapshot",
        )

    def test_atomic_catalog_write_status_and_runtime_match(self):
        payload = build_catalog_from_pages(
            fetch_page=lambda _url: (
                [
                    advisory(
                        "GHSA-6789-cfgh-jmpq",
                        package="demo",
                        vulnerable_range=">= 1.0.0, < 2.0.0",
                    )
                ],
                "",
            ),
            now="2026-09-18T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as td:
            catalog = Path(td) / "catalog.json"
            write_catalog_atomic(catalog, payload)
            status = catalog_status(catalog)
            self.assertTrue(status["integrity_valid"])
            self.assertTrue(status["source_sync_complete"])
            self.assertEqual(status["advisory_count"], 1)

            matched = match_versioned_technology(
                "demo:1.5.0",
                catalog_path=catalog,
            )
            self.assertEqual(len(matched["matches"]), 1)
            self.assertEqual(
                matched["matches"][0]["advisory_id"],
                "GHSA-6789-cfgh-jmpq",
            )
            self.assertTrue(matched["catalog_source_sync_complete"])

    def test_integrity_tamper_fails_closed(self):
        payload = build_catalog_from_pages(
            fetch_page=lambda _url: (
                [advisory("GHSA-789c-fghj-mpqr")],
                "",
            ),
            now="2026-09-18T00:00:00Z",
        )
        payload["advisories"][0]["product"] = "tampered"
        with tempfile.TemporaryDirectory() as td:
            catalog = Path(td) / "catalog.json"
            catalog.write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                catalog_status(catalog)

    def test_manifest_updater_changes_only_selected_entry(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = root / "data"
            data.mkdir()
            catalog = data / "catalog.json"
            catalog.write_text("{}\n", encoding="utf-8")
            manifest = root / "MANIFEST.sha256"
            manifest.write_text(
                ("0" * 64) + "  data/catalog.json\n"
                + ("1" * 64) + "  other.txt\n",
                encoding="utf-8",
            )
            update_manifest_entry(
                manifest,
                file_path=catalog,
                root=root,
            )
            lines = manifest.read_text(encoding="utf-8").splitlines()
            self.assertTrue(lines[0].endswith("  data/catalog.json"))
            self.assertNotEqual(lines[0][:64], "0" * 64)
            self.assertEqual(lines[1], ("1" * 64) + "  other.txt")

    def test_sync_summary_never_claims_safety_or_target_contact(self):
        payload = build_catalog_from_pages(
            fetch_page=lambda _url: (
                [advisory("GHSA-89cf-ghjm-pqrv")],
                "",
            ),
            now="2026-09-18T00:00:00Z",
        )
        summary = sync_summary(payload)
        self.assertTrue(summary["sync_complete"])
        self.assertFalse(summary["catalog_miss_means_safe"])
        self.assertFalse(summary["runtime_network_dependency"])
        self.assertFalse(summary["target_contact_performed"])


if __name__ == "__main__":
    unittest.main()
