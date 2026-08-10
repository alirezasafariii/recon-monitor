from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from analysis_postfreeze_sources import DEFAULT_SOURCE_REGISTRY, load_source_registry, validate_source_registry


def _write_registry(rows: list[dict], directory: str) -> Path:
    path = Path(directory) / "roots.jsonl"
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )
    return path


class AnalysisPostFreezeSourceRegistry660Tests(unittest.TestCase):
    def test_current_registry_is_valid_but_collection_is_incomplete(self) -> None:
        result = validate_source_registry()
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(result["verified_source_roots"], 16)
        self.assertEqual(result["target_source_roots"], 50)
        self.assertEqual(result["remaining_source_roots"], 34)
        self.assertEqual(result["source_projects"], 16)
        self.assertFalse(result["collection_complete"])
        self.assertTrue(any("16/50" in warning for warning in result["warnings"]))
        self.assertEqual(result["family_counts"]["broken_object_authorization"], 4)
        self.assertEqual(result["family_counts"]["broken_function_authorization"], 2)
        self.assertEqual(result["family_counts"]["sql_injection"], 2)
        self.assertEqual(result["family_counts"]["command_injection"], 2)
        self.assertEqual(result["family_counts"]["path_traversal"], 2)
        self.assertEqual(result["family_counts"]["ssrf"], 1)
        self.assertEqual(result["family_counts"]["cors_misconfiguration"], 1)
        self.assertEqual(result["family_counts"]["open_redirect"], 1)
        self.assertEqual(result["family_counts"]["server_side_template_injection"], 1)

    def test_source_registry_loader_does_not_require_case_id(self) -> None:
        rows = load_source_registry(DEFAULT_SOURCE_REGISTRY)
        self.assertEqual(len(rows), 16)
        self.assertTrue(all("source_root" in row for row in rows))
        self.assertTrue(all("id" not in row for row in rows))

    def test_duplicate_root_is_rejected(self) -> None:
        rows = load_source_registry(DEFAULT_SOURCE_REGISTRY)
        with tempfile.TemporaryDirectory() as tmp:
            result = validate_source_registry(registry_path=_write_registry([*rows, dict(rows[0])], tmp))
        self.assertFalse(result["passed"])
        self.assertTrue(any("duplicate source_root" in error for error in result["errors"]))

    def test_reused_primary_source_url_is_rejected(self) -> None:
        rows = copy.deepcopy(load_source_registry(DEFAULT_SOURCE_REGISTRY))
        rows[1]["provenance"]["url"] = rows[0]["provenance"]["url"]
        with tempfile.TemporaryDirectory() as tmp:
            result = validate_source_registry(registry_path=_write_registry(rows, tmp))
        self.assertFalse(result["passed"])
        self.assertTrue(any("URL is reused" in error for error in result["errors"]))

    def test_unverified_root_is_rejected(self) -> None:
        rows = copy.deepcopy(load_source_registry(DEFAULT_SOURCE_REGISTRY))
        rows[0]["review_status"] = "candidate"
        with tempfile.TemporaryDirectory() as tmp:
            result = validate_source_registry(registry_path=_write_registry(rows, tmp))
        self.assertFalse(result["passed"])
        self.assertTrue(any("primary_source_verified" in error for error in result["errors"]))

    def test_secure_control_must_be_frozen_family_blocker(self) -> None:
        rows = copy.deepcopy(load_source_registry(DEFAULT_SOURCE_REGISTRY))
        rows[6]["adjudication"]["secure_control"] = "operator_allowlist"
        with tempfile.TemporaryDirectory() as tmp:
            result = validate_source_registry(registry_path=_write_registry(rows, tmp))
        self.assertFalse(result["passed"])
        self.assertTrue(any("not a frozen sql_injection blocking contradiction" in error for error in result["errors"]))

    def test_adjudication_must_cover_every_frozen_required_group(self) -> None:
        rows = copy.deepcopy(load_source_registry(DEFAULT_SOURCE_REGISTRY))
        rows[7]["adjudication"] = {
            "surface": ["url_parameter"],
            "decisive": ["external_destination"],
            "secure_control": "host_allowlist",
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = validate_source_registry(registry_path=_write_registry(rows, tmp))
        self.assertFalse(result["passed"])
        self.assertTrue(any("does not satisfy frozen ssrf required groups" in error for error in result["errors"]))
        self.assertTrue(any("decisive evidence does not intersect" in error for error in result["errors"]))

    def test_decisive_evidence_must_reach_condition_group(self) -> None:
        rows = copy.deepcopy(load_source_registry(DEFAULT_SOURCE_REGISTRY))
        rows[11]["adjudication"] = {
            "surface": ["redirect_parameter", "redirect_response", "external_destination"],
            "decisive": ["redirect_response"],
            "secure_control": "same_origin_only",
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = validate_source_registry(registry_path=_write_registry(rows, tmp))
        self.assertFalse(result["passed"])
        self.assertTrue(any("decisive evidence does not intersect" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
