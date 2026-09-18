from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from recon_monitor import (
    build_parser,
    corpus_v1_coverage_status_cli_payload,
)


class CorpusV1CoverageCliTests(unittest.TestCase):
    def test_parser_exposes_coverage_status_and_expansion(self):
        parser = build_parser()
        status = parser.parse_args(["analysis", "corpus-v1-coverage-status"])
        expand = parser.parse_args([
            "analysis",
            "corpus-v1-expand-coverage",
            "--coverage-quota",
            "10",
            "--max-pages-per-family",
            "7",
        ])
        self.assertEqual(status.action, "corpus-v1-coverage-status")
        self.assertEqual(expand.action, "corpus-v1-expand-coverage")
        self.assertEqual(expand.coverage_quota, 10)
        self.assertEqual(expand.max_pages_per_family, 7)

    def test_status_tracks_all_74_families_without_network(self):
        parser = build_parser()
        args = parser.parse_args(["analysis", "corpus-v1-coverage-status"])
        payload = corpus_v1_coverage_status_cli_payload(args)
        inventory = payload["inventory"]
        self.assertEqual(inventory["canonical_family_count"], 74)
        self.assertEqual(inventory["represented_family_count"], 60)
        self.assertEqual(inventory["missing_family_count"], 14)
        self.assertTrue(payload["safety"]["all_74_canonical_families_tracked"])
        self.assertTrue(payload["safety"]["no_network_required_for_status"])

    def test_status_can_write_inventory_json(self):
        parser = build_parser()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "coverage.json"
            args = parser.parse_args([
                "analysis",
                "corpus-v1-coverage-status",
                "--coverage-output",
                str(path),
            ])
            payload = corpus_v1_coverage_status_cli_payload(args)
            self.assertTrue(path.exists())
            self.assertEqual(payload["coverage_output"], str(path))
            self.assertIn('"canonical_family_count": 74', path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
