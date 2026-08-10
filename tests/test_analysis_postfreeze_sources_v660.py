from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from analysis_postfreeze_sources import DEFAULT_SOURCE_REGISTRY, load_source_registry, validate_source_registry


class AnalysisPostFreezeSourceRegistry660Tests(unittest.TestCase):
    def test_current_registry_is_valid_but_collection_is_incomplete(self) -> None:
        result = validate_source_registry()
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(result["verified_source_roots"], 7)
        self.assertEqual(result["target_source_roots"], 50)
        self.assertEqual(result["remaining_source_roots"], 43)
        self.assertFalse(result["collection_complete"])
        self.assertTrue(any("7/50" in warning for warning in result["warnings"]))
        self.assertEqual(result["family_counts"]["broken_object_authorization"], 4)
        self.assertEqual(result["family_counts"]["broken_function_authorization"], 2)
        self.assertEqual(result["family_counts"]["sql_injection"], 1)

    def test_source_registry_loader_does_not_require_case_id(self) -> None:
        rows = load_source_registry(DEFAULT_SOURCE_REGISTRY)
        self.assertEqual(len(rows), 7)
        self.assertTrue(all("source_root" in row for row in rows))
        self.assertTrue(all("id" not in row for row in rows))

    def test_duplicate_root_is_rejected(self) -> None:
        rows = load_source_registry(DEFAULT_SOURCE_REGISTRY)
        duplicate = dict(rows[0])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roots.jsonl"
            path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in [*rows, duplicate]) + "\n", encoding="utf-8")
            result = validate_source_registry(registry_path=path)
        self.assertFalse(result["passed"])
        self.assertTrue(any("duplicate source_root" in error for error in result["errors"]))

    def test_reused_primary_source_url_is_rejected(self) -> None:
        rows = load_source_registry(DEFAULT_SOURCE_REGISTRY)
        changed = [dict(row) for row in rows]
        changed[1] = {
            **changed[1],
            "provenance": {
                **changed[1]["provenance"],
                "url": changed[0]["provenance"]["url"],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roots.jsonl"
            path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in changed) + "\n", encoding="utf-8")
            result = validate_source_registry(registry_path=path)
        self.assertFalse(result["passed"])
        self.assertTrue(any("URL is reused" in error for error in result["errors"]))

    def test_unverified_root_is_rejected(self) -> None:
        rows = load_source_registry(DEFAULT_SOURCE_REGISTRY)
        changed = [dict(row) for row in rows]
        changed[0] = {**changed[0], "review_status": "candidate"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roots.jsonl"
            path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in changed) + "\n", encoding="utf-8")
            result = validate_source_registry(registry_path=path)
        self.assertFalse(result["passed"])
        self.assertTrue(any("primary_source_verified" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
