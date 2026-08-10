from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import ENGINE_VERSION, run_analysis
from bug_candidates import BUG_FAMILIES, CANDIDATE_ENGINE_VERSION, SAFE_ACTIONS
from core import AppPaths, Database, utc_now
from hypothesis_admission import ADMISSION_ENGINE_VERSION, assess_admission
from security_reasoning import FAMILY_SCHEMAS, REASONING_ENGINE_VERSION

NEW_FAMILIES = {
    "sql_injection", "nosql_injection", "command_injection", "server_side_template_injection", "ldap_injection",
    "unrestricted_resource_consumption", "sensitive_business_flow_abuse", "security_misconfiguration",
    "improper_inventory_management", "unsafe_api_consumption",
}

def ev(kind: str, source: str = "fixture") -> dict[str, str]:
    return {"type": kind, "source": source, "text": kind}

class AnalysisCoverageV610Tests(unittest.TestCase):
    def test_versions_and_registry(self):
        self.assertEqual(ENGINE_VERSION, "6.5.0")
        self.assertEqual(CANDIDATE_ENGINE_VERSION, "6.5.0")
        self.assertEqual(REASONING_ENGINE_VERSION, "6.7.0")
        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.3.0")
        for family in NEW_FAMILIES:
            self.assertIn(family, BUG_FAMILIES)
            self.assertIn(family, SAFE_ACTIONS)
            self.assertIn(family, FAMILY_SCHEMAS)

    def test_sql_surface_stays_hidden_until_query_influence(self):
        surface = [ev("input_parameter", "schema"), ev("sql_query_surface", "semantic")]
        self.assertFalse(assess_admission("sql_injection", surface)["admitted"])
        decisive = surface + [ev("boolean_response_differential", "stored_behavior")]
        self.assertTrue(assess_admission("sql_injection", decisive)["admitted"])
        blocked = assess_admission("sql_injection", decisive, [ev("parameterized_query", "code")])
        self.assertFalse(blocked["admitted"])

    def test_injection_variants_need_execution_or_interpreter_effect(self):
        cases = {
            "nosql_injection": ([ev("input_parameter", "schema"), ev("nosql_query_surface", "semantic")], ev("nosql_operator_accepted", "stored_behavior")),
            "command_injection": ([ev("input_parameter", "schema"), ev("command_execution_surface", "semantic")], ev("command_output_observed", "stored_behavior")),
            "server_side_template_injection": ([ev("template_input", "schema"), ev("template_render_surface", "semantic")], ev("template_expression_evaluated", "stored_behavior")),
            "ldap_injection": ([ev("input_parameter", "schema"), ev("ldap_query_surface", "semantic")], ev("ldap_filter_influence", "stored_behavior")),
        }
        for family, (surface, decisive) in cases.items():
            with self.subTest(family=family):
                self.assertFalse(assess_admission(family, surface)["admitted"])
                self.assertTrue(assess_admission(family, surface + [decisive])["admitted"])

    def test_api_top10_surfaces_need_decisive_behavior(self):
        cases = {
            "unrestricted_resource_consumption": ([ev("resource_control_parameter", "schema")], ev("unbounded_page_size_observed", "stored_behavior")),
            "sensitive_business_flow_abuse": ([ev("sensitive_business_flow", "semantic")], ev("workflow_frequency_unrestricted", "stored_behavior")),
            "security_misconfiguration": ([ev("misconfiguration_surface", "semantic")], ev("stack_trace_exposed", "http")),
            "improper_inventory_management": ([ev("api_version_surface", "semantic")], ev("deprecated_version_still_reachable", "http")),
            "unsafe_api_consumption": ([ev("third_party_integration", "semantic")], ev("third_party_data_unsanitized", "stored_behavior")),
        }
        for family, (surface, decisive) in cases.items():
            with self.subTest(family=family):
                self.assertFalse(assess_admission(family, surface)["admitted"])
                self.assertTrue(assess_admission(family, surface + [decisive])["admitted"])

    def _project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name)); paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('run61','6.1.0','success',?,?,?,1)", (now, now, "example.com"))
        return temp, paths, db

    def test_surface_only_sql_is_hidden_in_real_analysis(self):
        temp, paths, db = self._project()
        try:
            db.execute("INSERT INTO targets(id,run_id,target,domain,created_at) VALUES('t61','run61','api.example.com','example.com',?)", (utc_now(),))
            db.execute("INSERT INTO endpoints(run_id,target,url,method,source,first_seen,last_seen) VALUES('run61','api.example.com','https://api.example.com/search?q=1','GET','fixture',?,?)", (utc_now(), utc_now()))
            db.execute("INSERT INTO api_parameters(run_id,target,endpoint,method,parameter,location,evidence_json,created_at) VALUES('run61','api.example.com','https://api.example.com/search?q=1','GET','q','query','{}',?)", (utc_now(),))
            result = run_analysis(paths, "run61")
            self.assertEqual(result["analysis_engine_version"], "6.5.0")
            families = {str(row["bug_family"]) for row in db.all("SELECT bug_family FROM bug_candidates WHERE analysis_id=?", (result["analysis_id"],))}
            self.assertNotIn("sql_injection", families)
        finally:
            db.close(); temp.cleanup()

    def test_all_new_families_are_covered_by_security_reasoning(self):
        self.assertTrue(NEW_FAMILIES.issubset(FAMILY_SCHEMAS))


if __name__ == "__main__":
    unittest.main()
