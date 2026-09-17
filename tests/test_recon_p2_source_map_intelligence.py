from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from stages import (
    _extract_js_chunk_references,
    _find_source_map_url,
    _resolve_source_map_source,
    _source_map_entries,
    stage_javascript,
)


class ReconP2SourceMapIntelligenceTests(unittest.TestCase):
    def test_source_map_url_preserves_security_significant_bytes(self) -> None:
        url = _find_source_map_url(
            "https://app.example.com/static/app.js",
            "//# sourceMappingURL=maps/app%2Fprod.js.map?x=2&x=1\n",
        )
        self.assertEqual(
            url,
            "https://app.example.com/static/maps/app%2Fprod.js.map?x=2&x=1",
        )

    def test_source_map_entries_hash_embedded_content_and_resolve_http_sources(self) -> None:
        source_map_url = "https://app.example.com/static/js/app.js.map"
        entries = _source_map_entries(
            source_map_url,
            {
                "sourceRoot": "../../src/",
                "sources": ["api/client.ts", "webpack:///internal/admin.ts"],
                "sourcesContent": [
                    "export const endpoint = '/api/admin/export';",
                    "export const internalOnly = true;",
                ],
            },
        )

        self.assertEqual(len(entries), 2)
        self.assertEqual(
            entries[0]["resolved_source_url"],
            "https://app.example.com/src/api/client.ts",
        )
        self.assertTrue(entries[0]["embedded"])
        self.assertGreater(entries[0]["content_size"], 0)
        self.assertTrue(entries[0]["content_hash"])
        self.assertTrue(entries[0]["semantic_hash"])
        self.assertEqual(entries[1]["resolved_source_url"], "")
        self.assertIn("webpack:///internal/admin.ts", entries[1]["source_identity"])

    def test_virtual_source_scheme_is_never_promoted_to_network_url(self) -> None:
        self.assertEqual(
            _resolve_source_map_source(
                "https://app.example.com/static/app.js.map",
                "",
                "webpack:///src/private.ts",
            ),
            "",
        )

    def test_chunk_references_are_resolved_without_losing_raw_semantics(self) -> None:
        chunks = _extract_js_chunk_references(
            "https://app.example.com/static/app.js",
            """
            const a = "./chunks/admin%2Fpanel.js?x=2&x=1";
            const b = "/assets/runtime.js";
            const duplicate = "./chunks/admin%2Fpanel.js?x=2&x=1";
            const inline = "data:text/javascript,alert(1).js";
            """,
        )
        self.assertEqual(
            chunks,
            [
                "https://app.example.com/assets/runtime.js",
                "https://app.example.com/static/chunks/admin%2Fpanel.js?x=2&x=1",
            ],
        )

    def test_stage_embedded_source_analysis_is_offline_and_graph_backed(self) -> None:
        source = inspect.getsource(stage_javascript)
        self.assertIn('"source-map-sources.jsonl"', source)
        self.assertIn('"javascript-chunk-edges.jsonl"', source)
        self.assertIn('"has_source_map"', source)
        self.assertIn('"contains_source"', source)
        self.assertIn('"references_chunk"', source)
        self.assertIn('"embedded_source": True', source)
        self.assertNotIn("_download_url(ctx, resolved_source_url", source)


if __name__ == "__main__":
    unittest.main()
