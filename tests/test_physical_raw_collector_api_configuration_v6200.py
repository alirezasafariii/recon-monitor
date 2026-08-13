from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import AppPaths, Database, utc_now
from family_detectors import evaluate_family_detector, execute_detector_intelligence, get_detector_spec
from hypothesis_admission import assess_admission
from raw_family_collectors import (
    API_CONFIGURATION_FAMILIES,
    API_CONFIGURATION_OBSERVATIONS,
    collect_api_configuration_observations,
    validate_api_configuration_collectors,
)


class PhysicalRawCollectorApiConfiguration6200Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        extraction = evaluate_family_detector(family, packet.get("support", []), packet.get("contradict", []), channel="alert")
        return execution, assess_admission(family, extraction["support"], extraction["contradict"])

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(API_CONFIGURATION_FAMILIES), {
            "unrestricted_resource_consumption", "sensitive_business_flow_abuse",
            "security_misconfiguration", "improper_inventory_management", "unsafe_api_consumption",
        })
        self.assertEqual(validate_api_configuration_collectors(), [])
        for family in API_CONFIGURATION_FAMILIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)

    def test_positive_execution_contracts_admit_all_five(self):
        fixtures = {
            "unrestricted_resource_consumption": dict(target="fixture.invalid", endpoint="/api/report?limit=5000", method="GET", endpoint_schema={"query_parameters": ["limit"]}, details={"rate_limit_absent_observed": True}, category="api", business_context="general"),
            "sensitive_business_flow_abuse": dict(target="fixture.invalid", endpoint="/api/checkout", method="POST", endpoint_schema={}, details={"per_user_limit_absent": True}, category="api", business_context="commerce"),
            "security_misconfiguration": dict(target="fixture.invalid", endpoint="/debug", method="GET", endpoint_schema={}, details={"response_body": "Traceback (most recent call last):\nRuntimeError: boom", "status_code": 500}, category="debug", business_context="general"),
            "improper_inventory_management": dict(target="fixture.invalid", endpoint="/api/legacy/v1/users", method="GET", endpoint_schema={}, details={"status_code": 200}, category="api", business_context="general"),
            "unsafe_api_consumption": dict(target="fixture.invalid", endpoint="/api/integration/webhook", method="POST", endpoint_schema={"body_fields": ["webhook"]}, details={"upstream_timeout_absent": True}, category="integration", business_context="general"),
        }
        execution_map = {}
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_api_configuration_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(API_CONFIGURATION_FAMILIES))

    def test_plain_api_version_is_not_inventory_signal_by_itself(self):
        execution = execute_detector_intelligence(
            target="fixture.invalid", endpoint="/api/v1/users", method="GET",
            endpoint_schema={}, details={"status_code": 200}, category="api", business_context="general",
        )
        self.assertNotIn("improper_inventory_management", execution)

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "unrestricted_resource_consumption": dict(target="fixture.invalid", endpoint="/api/report?limit=100", method="GET", endpoint_schema={"query_parameters": ["limit"]}, details={}, category="api", business_context="general"),
            "sensitive_business_flow_abuse": dict(target="fixture.invalid", endpoint="/api/checkout", method="POST", endpoint_schema={}, details={}, category="api", business_context="commerce"),
            "security_misconfiguration": dict(target="fixture.invalid", endpoint="/swagger", method="GET", endpoint_schema={}, details={}, category="api", business_context="general"),
            "improper_inventory_management": dict(target="fixture.invalid", endpoint="/api/legacy/v1/users", method="GET", endpoint_schema={}, details={"status_code": 404}, category="api", business_context="general"),
            "unsafe_api_consumption": dict(target="fixture.invalid", endpoint="/api/integration/webhook", method="POST", endpoint_schema={"body_fields": ["webhook"]}, details={}, category="integration", business_context="general"),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_flag_only_misconfiguration_retains_identity_without_auto_promotion_shortcut(self):
        execution, assessment = self._assessment("security_misconfiguration", dict(
            target="fixture.invalid", endpoint="/health", method="GET", endpoint_schema={},
            details={"debug_mode_exposed": True}, category="api", business_context="general",
        ))
        packet = execution["security_misconfiguration"]
        types = {str(row.get("type") or "") for row in packet["support"]}
        self.assertIn("misconfiguration_surface", types)
        self.assertIn("debug_mode_exposed", types)
        self.assertTrue(assessment["admitted"], assessment)

    def test_collector_is_metadata_only(self):
        for family, observation in API_CONFIGURATION_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_all_five_legacy_blocks(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_raw_owned_observations(execution_map)", source)
        self.assertIn("validate_family_ownership()", source)
        self.assertNotIn('collect_api_configuration_observations(execution_map)', source)
        self.assertNotIn("detector-execution-fallback", source)

    def test_run_analysis_routes_all_five_through_api_configuration_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-620-api-config"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.19.0", "success", now, now, target))
                alerts = [
                    ("Resource limit", "/api/report?limit=5000", {"method": "GET", "query_parameters": ["limit"], "rate_limit_absent_observed": True, "category": "api"}),
                    ("Sensitive checkout", "/api/checkout", {"method": "POST", "per_user_limit_absent": True, "category": "api"}),
                    ("Debug exposure", "/debug", {"method": "GET", "response_body": "Traceback (most recent call last):\nRuntimeError: boom", "status_code": 500, "category": "debug"}),
                    ("Legacy API", "/api/legacy/v1/users", {"method": "GET", "status_code": 200, "category": "api"}),
                    ("Upstream API", "/api/integration/webhook", {"method": "POST", "body_fields": ["webhook"], "upstream_timeout_absent": True, "category": "integration"}),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"620:{title}", "new_endpoint", "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(API_CONFIGURATION_FAMILIES) and "raw-collector-api-configuration-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(API_CONFIGURATION_FAMILIES), hypotheses)
                for family, expected in API_CONFIGURATION_OBSERVATIONS.items():
                    family_rows = [row for row in routed[family] if str(row["bug_variant"]) == expected.variant]
                    self.assertTrue(family_rows, (family, routed[family]))
                    promoted = [row for row in family_rows if str(row["state"]) == "promoted"]
                    self.assertTrue(promoted, (family, [dict(row) for row in family_rows]))
                    conditions = set(get_detector_spec(family).condition_signals)
                    self.assertTrue(any(
                        {str(item.get("type") or "") for item in json.loads(row["supporting_evidence_json"] or "[]")} & conditions
                        for row in promoted
                    ), (family, conditions, [dict(row) for row in promoted]))
                candidates = db.all("SELECT bug_family,rule_ids_json FROM bug_candidates WHERE analysis_id=?", (result["analysis_id"],))
                promoted_families = {
                    str(row["bug_family"]) for row in candidates
                    if "raw-collector-api-configuration-v1" in json.loads(row["rule_ids_json"] or "[]")
                }
                self.assertEqual(promoted_families, set(API_CONFIGURATION_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
