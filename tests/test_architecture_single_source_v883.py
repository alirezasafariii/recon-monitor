from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import bug_candidates
import safe_validation
import workspace_v7
from family_reasoning import FAMILY_ORDER, candidate_evidence_schema_map, case_requirement_map, validation_level_for_family


class _FakeCaseDB:
    def __init__(self, family: str):
        self.family = family

    def one(self, sql, params=()):
        if "FROM security_cases" in sql:
            return {"case_id": "CASE-SINGLE-SOURCE", "target": "example.com", "primary_family": self.family}
        return None

    def all(self, sql, params=()):
        return []


class ArchitectureSingleSourceV883Tests(unittest.TestCase):
    def test_candidate_engine_uses_exact_canonical_schema_map_for_all_21(self):
        expected = candidate_evidence_schema_map()
        self.assertEqual(set(expected), set(FAMILY_ORDER))
        self.assertEqual(len(expected), 21)
        self.assertEqual(bug_candidates.FAMILY_EVIDENCE_SCHEMAS, expected)
        self.assertEqual(bug_candidates._base.FAMILY_EVIDENCE_SCHEMAS, expected)
        self.assertEqual(bug_candidates.CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION, "2.1.0")
        source = inspect.getsource(bug_candidates)
        self.assertNotIn('_base.FAMILY_EVIDENCE_SCHEMAS["broken_function_authorization"]', source)
        self.assertIn('candidate_evidence_schema_map()', source)

    def test_workspace_case_requirements_are_exact_canonical_map(self):
        expected = case_requirement_map()
        self.assertEqual(set(expected), set(FAMILY_ORDER))
        self.assertEqual(workspace_v7.FAMILY_CASE_REQUIREMENTS, expected)
        self.assertEqual([row["key"] for row in expected["broken_object_authorization"]], ["authenticated_context", "second_identity", "ownership_map", "comparable_response"])
        self.assertEqual(workspace_v7._canonical_family("Sensitive Response Caching"), "sensitive_caching")
        source = inspect.getsource(workspace_v7)
        self.assertNotIn("BUG_FAMILY_REQUIREMENTS", source)
        self.assertNotIn("DEFAULT_REQUIREMENTS =", source)

    def test_safe_validation_calls_exact_family_reasoning_classifier(self):
        db = _FakeCaseDB("account_enumeration")
        with patch.object(safe_validation, "validation_level_for_family", return_value="manual_only") as classifier:
            result = safe_validation.validation_eligibility(db, "CASE-SINGLE-SOURCE")
        classifier.assert_called_once_with("account_enumeration")
        self.assertEqual(result["canonical_family"], "account_enumeration")
        self.assertEqual(result["recommended_level"], "manual_only")

    def test_safe_validation_matches_all_21_canonical_levels(self):
        self.assertEqual(safe_validation.VALIDATION_VERSION, "6.1.0")
        for family in FAMILY_ORDER:
            result = safe_validation.validation_eligibility(_FakeCaseDB(family), "CASE-SINGLE-SOURCE")
            self.assertEqual(result["canonical_family"], family)
            self.assertEqual(result["recommended_level"], validation_level_for_family(family))

    def test_safe_validation_canonicalizes_family_labels_before_legacy_hints(self):
        result = safe_validation.validation_eligibility(_FakeCaseDB("BOLA / IDOR"), "CASE-SINGLE-SOURCE")
        self.assertEqual(result["canonical_family"], "broken_object_authorization")
        self.assertEqual(result["recommended_level"], "controlled")
        result = safe_validation.validation_eligibility(_FakeCaseDB("Unsafe postMessage Trust"), "CASE-SINGLE-SOURCE")
        self.assertEqual(result["canonical_family"], "postmessage_trust")
        self.assertEqual(result["recommended_level"], "manual_only")

    def test_unknown_family_fails_closed_to_offline(self):
        result = safe_validation.validation_eligibility(_FakeCaseDB("future_unknown_family"), "CASE-SINGLE-SOURCE")
        self.assertEqual(result["canonical_family"], "")
        self.assertEqual(result["recommended_level"], "offline")
        self.assertTrue(result["executable_in_this_release"])

    def test_exact_recipe_selection_uses_canonical_ids(self):
        self.assertEqual([row["method"] for row in safe_validation._request_recipe("sensitive_caching", "https://example.com/account")], ["GET"])
        self.assertEqual([row["method"] for row in safe_validation._request_recipe("cors_misconfiguration", "https://example.com/api")], ["OPTIONS", "GET"])
        self.assertEqual([row["method"] for row in safe_validation._request_recipe("source_map_exposure", "https://example.com/app.js.map")], ["GET"])


if __name__ == "__main__":
    unittest.main()
