from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import bug_candidates
from core import APP_VERSION, Database, utc_now
from family_analyzers.dom_xss import (
    DOM_XSS_FAMILY_ANALYZER_VERSION,
    DOM_XSS_METHOD,
    analyze_dom_xss_signal,
)
from family_analyzers.router import analyzer_for_family, router_status


class DomXssFamilyAnalyzerV873Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-DOM-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-DOM-FAMILY','RUN-DOM-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details=None, *, source="location.hash", sink="innerHTML", snippet="target.innerHTML = location.hash", confidence=85):
        return analyze_dom_xss_signal(
            self.db,
            analysis_id="AN-DOM-FAMILY",
            target="example.com",
            js_url="https://example.com/app.js",
            endpoint="https://example.com/app.js",
            method="GET",
            source_kind=source,
            sink_kind=sink,
            snippet=snippet,
            confidence=confidence,
            details=dict(details or {}),
            business_context="general",
        )

    def test_router_registers_nine_dedicated_families_without_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered_count"], 9)
        self.assertEqual(status["pending_count"], 12)
        self.assertEqual(status["registered"], [
            "broken_object_authorization",
            "broken_function_authorization",
            "mass_assignment",
            "authentication_session",
            "account_enumeration",
            "dom_xss",
            "postmessage_trust",
            "open_redirect",
            "ssrf",
        ])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("dom_xss"))
        self.assertIsNotNone(analyzer_for_family("postmessage_trust"))
        self.assertIsNotNone(analyzer_for_family("open_redirect"))
        self.assertIsNotNone(analyzer_for_family("ssrf"))
        self.assertIsNone(analyzer_for_family("file_upload"))

    def test_methodology_grounding_and_writeups_are_non_evidentiary(self):
        result = self.analyze()
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(DOM_XSS_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("CWE-79", meta["taxonomy"]["cwe"])
        self.assertIn("WSTG-CLNT-01", meta["taxonomy"]["wstg"])
        basis = {item for step in DOM_XSS_METHOD for item in step["basis"]}
        self.assertIn("CWE-79", basis)
        self.assertIn("WSTG-CLNT-01", basis)
        refs = {row["id"] for row in meta["writeup_patterns"]}
        self.assertIn("ghsl-2026-030-nocodb-rendering", refs)
        self.assertTrue(all(row["non_evidentiary"] for row in meta["writeup_patterns"]))
        observed = {row["type"] for row in result["support"]}
        self.assertNotIn("ghsl-2026-030-nocodb-rendering", observed)
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])

    def test_static_source_and_sink_are_one_correlated_root_and_not_confirmation(self):
        result = self.analyze()
        self.assertIsNotNone(result)
        observed = {row["type"] for row in result["support"]}
        roots = {row.get("source_group") for row in result["support"]}
        self.assertEqual(observed, {"dataflow_source", "dataflow_sink"})
        self.assertEqual(roots, {"dom_static_flow"})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])

    def test_safe_text_sink_does_not_emit_dom_xss(self):
        self.assertIsNone(self.analyze(sink="textContent", snippet="target.textContent = location.hash"))

    def test_postmessage_surface_stays_in_neighbor_family_without_dom_condition(self):
        self.assertIsNone(self.analyze(source="postMessage", sink="innerHTML", snippet="onmessage = e => out.innerHTML = e.data"))

    def test_runtime_reachability_without_neutralization_result_is_not_direct(self):
        result = self.analyze({"dom_runtime_observations": [{"source_kind": "location_hash", "sink_kind": "innerhtml", "runtime_dom_sink_reached": True}]})
        observed = {row["type"] for row in result["support"]}
        self.assertIn("runtime_dom_sink_reached", observed)
        self.assertNotIn("unsanitized_dom_flow", observed)
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_runtime_unsanitized_execution_sink_is_direct_condition_evidence(self):
        result = self.analyze({"dom_runtime_observations": [{"source_kind": "location_hash", "sink_kind": "eval", "runtime_dom_sink_reached": True, "sanitized": False}]}, sink="eval", snippet="eval(location.hash)")
        observed = {row["type"] for row in result["support"]}
        self.assertIn("runtime_dom_sink_reached", observed)
        self.assertIn("unsanitized_dom_flow", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "runtime_unsanitized_dom_flow")
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_html_sink_requires_explicit_script_capable_context_for_direct_condition(self):
        incomplete = self.analyze({"dom_runtime_observations": [{"source_kind": "location_hash", "sink_kind": "innerhtml", "runtime_dom_sink_reached": True, "sanitized": False}]})
        self.assertNotIn("unsanitized_dom_flow", {row["type"] for row in incomplete["support"]})
        established = self.analyze({"dom_runtime_observations": [{"source_kind": "location_hash", "sink_kind": "innerhtml", "runtime_dom_sink_reached": True, "sanitized": False, "execution_context_reached": True}]})
        self.assertIn("unsanitized_dom_flow", {row["type"] for row in established["support"]})
        self.assertTrue(established["direct"])

    def test_sanitization_or_trusted_types_is_contradiction(self):
        result = self.analyze({"dom_runtime_observations": [{"source_kind": "location_hash", "sink_kind": "innerhtml", "runtime_dom_sink_reached": True, "sanitized": True, "trusted_types_enforced": True}]})
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("sanitization_observed", contradictions)
        self.assertFalse(result["direct"])
        triggered = {row["signal"] for row in result["family_analyzer"]["triggered_false_positive_checks"]}
        self.assertIn("sanitization_observed", triggered)

    def test_static_candidate_path_retains_surface_as_hidden_hypothesis_not_candidate(self):
        now = utc_now()
        self.db.execute(
            """INSERT INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            ("AN-DOM-FAMILY", "example.com", "RUN-DOM-FAMILY", "https://example.com/app.js", "location.hash", "innerHTML", 90, "out.innerHTML = location.hash", now),
        )
        count = bug_candidates._static_candidates(self.db, "AN-DOM-FAMILY", "RUN-DOM-FAMILY", "example.com")
        self.assertEqual(count, 0)
        hypothesis = self.db.one("SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='dom_xss'", ("AN-DOM-FAMILY",))
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertFalse(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "dom_xss")
        self.assertTrue(admission["family_analyzer"]["static_source_and_sink_are_one_evidence_root"])
        candidate = self.db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='dom_xss'", ("AN-DOM-FAMILY",))
        self.assertIsNone(candidate)

    def test_static_path_promotes_only_with_independent_stored_runtime_condition(self):
        now = utc_now()
        js_url = "https://example.com/runtime.js"
        self.db.execute(
            """INSERT INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            ("AN-DOM-FAMILY", "example.com", "RUN-DOM-FAMILY", js_url, "location.hash", "eval", 92, "eval(location.hash)", now),
        )
        self.db.execute(
            """INSERT INTO semantic_js_units(analysis_id,target,run_id,js_url,unit_type,unit_key,value_json,confidence,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            ("AN-DOM-FAMILY", "example.com", "RUN-DOM-FAMILY", js_url, "dom_runtime_observation", "controlled-marker-runtime", json.dumps({"source_kind": "location_hash", "sink_kind": "eval", "runtime_dom_sink_reached": True, "sanitized": False}), 95, now),
        )
        count = bug_candidates._static_candidates(self.db, "AN-DOM-FAMILY", "RUN-DOM-FAMILY", "example.com")
        self.assertEqual(count, 1)
        hypothesis = self.db.one("SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='dom_xss'", ("AN-DOM-FAMILY",))
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("runtime_dom_sink_reached", support)
        self.assertIn("unsanitized_dom_flow", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertTrue(admission["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        candidate = self.db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='dom_xss'", ("AN-DOM-FAMILY",))
        self.assertIsNotNone(candidate)
        candidate_support = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("unsanitized_dom_flow", candidate_support)


if __name__ == "__main__":
    unittest.main()
