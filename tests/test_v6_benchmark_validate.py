from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from v6_benchmark_validate import _validate_observation


class V6BenchmarkValidationTests(unittest.TestCase):
    def _raw(self) -> dict:
        return {
            "target": "literal.example.test",
            "endpoint": "/login",
            "method": "POST",
            "endpoint_schema": {
                "query_parameters": [],
                "body_fields": ["username", "password"],
                "path_parameters": [],
                "object_identifiers": [],
                "authentication_hints": [],
            },
            "business_context": "identity",
            "category": "login response comparison",
            "details": {"status_code": 401, "trace_id": "capture-4d91f7"},
        }

    def test_family_name_in_raw_value_is_rejected(self) -> None:
        raw = self._raw()
        raw["details"]["note"] = "observed account_enumeration behavior"
        errors: list[str] = []
        leakage: dict[str, list[str]] = {}
        _validate_observation(raw, "case-family-value", set(), errors, leakage)
        self.assertIn("case-family-value", leakage)
        self.assertTrue(any("benchmark labels leaked" in error for error in errors))

    def test_condition_signal_in_raw_value_is_rejected(self) -> None:
        raw = self._raw()
        raw["details"]["note"] = "response_difference"
        errors: list[str] = []
        leakage: dict[str, list[str]] = {}
        _validate_observation(raw, "case-condition-value", {"response_difference"}, errors, leakage)
        self.assertIn("case-condition-value", leakage)

    def test_family_derived_trace_id_is_rejected(self) -> None:
        raw = self._raw()
        raw["details"]["trace_id"] = "v6-account_"
        errors: list[str] = []
        leakage: dict[str, list[str]] = {}
        _validate_observation(raw, "case-derived-id", set(), errors, leakage)
        self.assertIn("case-derived-id", leakage)
        self.assertTrue(any(item.startswith("derived-id:") for item in leakage["case-derived-id"]))

    def test_unrelated_literal_raw_value_can_pass_leakage_scan(self) -> None:
        raw = self._raw()
        errors: list[str] = []
        leakage: dict[str, list[str]] = {}
        _validate_observation(raw, "case-clean", set(), errors, leakage)
        self.assertNotIn("case-clean", leakage)
        self.assertFalse(any("benchmark labels leaked" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
