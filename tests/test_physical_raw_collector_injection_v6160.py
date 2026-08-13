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
from family_detectors import evaluate_family_detector, execute_detector_intelligence
from hypothesis_admission import assess_admission
from raw_family_collectors import (
    INJECTION_COLLECTOR_RULE_VERSION,
    INJECTION_COLLECTOR_VERSION,
    INJECTION_FAMILIES,
    INJECTION_OBSERVATIONS,
    collect_injection_observations,
    validate_injection_collectors,
)


class PhysicalRawCollectorInjection6160Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        scoped = evaluate_family_detector(family, packet.get("support") or [], packet.get("contradict") or [], channel="analysis_616_test")
        return execution, assess_admission(family, scoped["support"], scoped["contradict"])

    def test_registry_owns_exactly_five_injection_families(self):
        self.assertEqual(
            set(INJECTION_FAMILIES),
            {"sql_injection", "nosql_injection", "command_injection", "server_side_template_injection", "ldap_injection"},
        )
        self.assertEqual(set(INJECTION_OBSERVATIONS), set(INJECTION_FAMILIES))
        self.assertEqual(validate_injection_collectors(), [])
        self.assertEqual(INJECTION_COLLECTOR_VERSION, "1.0.0")
        self.assertEqual(INJECTION_COLLECTOR_RULE_VERSION, "2026.08.12.6.16")

    def test_collectors_only_emit_for_execution_packets_that_exist(self):
        execution = {
            "sql_injection": {"support": [{"type": "input_parameter"}], "contradict": []},
            "cors_misconfiguration": {"support": [{"type": "wildcard_origin"}], "contradict": []},
        }
        observations = collect_injection_observations(execution)
        self.assertEqual([item.family for item in observations], ["sql_injection"])
        self.assertEqual(observations[0].variant, "query_semantic_influence")
        self.assertIn("raw-collector-injection-v1", observations[0].rules)

    def test_positive_execution_contracts_admit_all_five_families(self):
        fixtures = {
            "sql_injection": dict(
                target="fixture.invalid", endpoint="/api/reports/search", method="POST",
                endpoint_schema={"body_fields": ["query"]},
                details={"response_text": "SQL syntax error near fixture", "status_code": 500},
                category="sql query report search", business_context="general",
            ),
            "nosql_injection": dict(
                target="fixture.invalid", endpoint="/api/document/search", method="POST",
                endpoint_schema={"body_fields": ["filter"]},
                details={"response_text": "MongoError: unknown operator $fixture", "status_code": 500},
                category="mongodb nosql document query", business_context="general",
            ),
            "command_injection": dict(
                target="fixture.invalid", endpoint="/api/diagnostic/run", method="POST",
                endpoint_schema={"body_fields": ["input"]},
                details={"source_code": "child_process.exec(userInput);", "status_code": 200},
                category="command process execution diagnostic", business_context="general",
            ),
            "server_side_template_injection": dict(
                target="fixture.invalid", endpoint="/api/template/preview", method="POST",
                endpoint_schema={"body_fields": ["template"]},
                details={"response_text": "jinja2.exceptions.TemplateSyntaxError: unexpected fixture", "status_code": 500},
                category="template render preview jinja", business_context="general",
            ),
            "ldap_injection": dict(
                target="fixture.invalid", endpoint="/api/directory/search", method="POST",
                endpoint_schema={"body_fields": ["username"]},
                details={"response_text": "LDAP error: invalid filter syntax", "status_code": 500},
                category="ldap directory search filter", business_context="identity",
            ),
        }
        execution = {}
        for family, raw in fixtures.items():
            packet, assessment = self._assessment(family, raw)
            execution[family] = packet[family]
            self.assertTrue(assessment["admitted"], (family, assessment, packet.get(family)))
        observations = collect_injection_observations(execution)
        self.assertEqual({item.family for item in observations}, set(INJECTION_FAMILIES))

    def test_near_misses_do_not_gain_decisive_conditions(self):
        fixtures = {
            "sql_injection": dict(target="fixture.invalid", endpoint="/api/reports/search", method="POST", endpoint_schema={"body_fields": ["query"]}, details={"response_text": "query completed", "status_code": 200}, category="sql query report", business_context="general"),
            "nosql_injection": dict(target="fixture.invalid", endpoint="/api/document/search", method="POST", endpoint_schema={"body_fields": ["filter"]}, details={"response_text": "document query returned zero results", "status_code": 200}, category="mongodb nosql document query", business_context="general"),
            "command_injection": dict(target="fixture.invalid", endpoint="/api/diagnostic/run", method="POST", endpoint_schema={"body_fields": ["input"]}, details={"source_code": "spawn(binary, validatedArgs);", "status_code": 400}, category="command process execution diagnostic", business_context="general"),
            "server_side_template_injection": dict(target="fixture.invalid", endpoint="/api/template/preview", method="POST", endpoint_schema={"body_fields": ["template"]}, details={"response_text": "preview rendered as plain text", "status_code": 200}, category="template render preview", business_context="general"),
            "ldap_injection": dict(target="fixture.invalid", endpoint="/api/directory/search", method="POST", endpoint_schema={"body_fields": ["username"]}, details={"response_text": "directory search returned zero results", "status_code": 200}, category="ldap directory search filter", business_context="identity"),
        }
        for family, raw in fixtures.items():
            _, assessment = self._assessment(family, raw)
            self.assertFalse(assessment["admitted"], (family, assessment))

    def test_sql_and_nosql_conditions_remain_family_specific(self):
        sql_raw = dict(target="fixture.invalid", endpoint="/api/search", method="POST", endpoint_schema={"body_fields": ["query"]}, details={"response_text": "SQL syntax error near fixture", "status_code": 500}, category="sql query", business_context="general")
        nosql_raw = dict(target="fixture.invalid", endpoint="/api/search", method="POST", endpoint_schema={"body_fields": ["filter"]}, details={"response_text": "MongoError: unknown operator $fixture", "status_code": 500}, category="mongodb nosql query", business_context="general")
        sql_execution = execute_detector_intelligence(**sql_raw)
        nosql_execution = execute_detector_intelligence(**nosql_raw)
        sql_types = {str(x.get("type") or "") for x in sql_execution.get("sql_injection", {}).get("support", [])}
        sql_as_nosql = {str(x.get("type") or "") for x in sql_execution.get("nosql_injection", {}).get("support", [])}
        nosql_types = {str(x.get("type") or "") for x in nosql_execution.get("nosql_injection", {}).get("support", [])}
        nosql_as_sql = {str(x.get("type") or "") for x in nosql_execution.get("sql_injection", {}).get("support", [])}
        self.assertIn("database_error_observed", sql_types)
        self.assertNotIn("nosql_error_observed", sql_as_nosql)
        self.assertIn("nosql_error_observed", nosql_types)
        self.assertNotIn("database_error_observed", nosql_as_sql)

    def test_orchestrator_no_longer_contains_legacy_injection_collector(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_raw_owned_observations(execution_map)", source)
        self.assertIn("validate_family_ownership()", source)
        self.assertNotIn('collect_injection_observations(execution_map)', source)
        self.assertNotIn("detector-execution-fallback", source)

    def test_run_analysis_routes_injection_hypotheses_through_physical_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now()
                run_id = "run-616-injection"
                target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.16.0", "success", now, now, target))
                alerts = [
                    ("SQL report search", "/api/reports/search", {"method": "POST", "body_fields": ["query"], "response_text": "SQL syntax error near fixture", "status_code": 500, "category": "sql query report"}),
                    ("NoSQL document search", "/api/document/search", {"method": "POST", "body_fields": ["filter"], "response_text": "MongoError: unknown operator $fixture", "status_code": 500, "category": "mongodb nosql document query"}),
                    ("Command diagnostic", "/api/diagnostic/run", {"method": "POST", "body_fields": ["input"], "source_code": "child_process.exec(userInput);", "status_code": 200, "category": "command process execution"}),
                    ("Template preview", "/api/template/preview", {"method": "POST", "body_fields": ["template"], "response_text": "jinja2.exceptions.TemplateSyntaxError: unexpected fixture", "status_code": 500, "category": "template render preview"}),
                    ("LDAP directory search", "/api/directory/search", {"method": "POST", "body_fields": ["username"], "response_text": "LDAP error: invalid filter syntax", "status_code": 500, "category": "ldap directory search filter"}),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"616:{title}", "new_endpoint", "HIGH", 85, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                rows = db.all("SELECT bug_family,bug_variant,rule_ids_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                by_family = {str(row["bug_family"]): row for row in rows if str(row["bug_family"]) in set(INJECTION_FAMILIES)}
                self.assertEqual(set(by_family), set(INJECTION_FAMILIES), rows)
                for family, expected in INJECTION_OBSERVATIONS.items():
                    row = by_family[family]
                    self.assertEqual(str(row["bug_variant"]), expected.variant)
                    self.assertIn("raw-collector-injection-v1", json.loads(row["rule_ids_json"]))
            finally:
                db.close()

    def test_versions(self):
        import analysis_engine
        import bug_candidates
        import security_reasoning
        self.assertEqual(analysis_engine.ENGINE_VERSION, bug_candidates.CANDIDATE_ENGINE_VERSION)
        self.assertEqual(analysis_engine.ENGINE_VERSION, security_reasoning.REASONING_ENGINE_VERSION)
        self.assertGreaterEqual(
            tuple(int(part) for part in analysis_engine.ENGINE_VERSION.split(".")),
            (6, 16, 0),
        )


if __name__ == "__main__":
    unittest.main()
