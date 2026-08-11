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
from family_analyzers.open_redirect import (
    OPEN_REDIRECT_FAMILY_ANALYZER_VERSION,
    OPEN_REDIRECT_METHOD,
    analyze_open_redirect_signal,
)
from family_analyzers.router import analyzer_for_family, router_status


class OpenRedirectFamilyAnalyzerV875Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-REDIR-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-REDIR-FAMILY','RUN-REDIR-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details=None, *, source="location.search", sink="navigation", snippet="location.href = new URLSearchParams(location.search).get('next')", confidence=85):
        return analyze_open_redirect_signal(
            self.db,
            analysis_id="AN-REDIR-FAMILY",
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
        self.assertIsNotNone(analyzer_for_family("open_redirect"))
        self.assertIsNotNone(analyzer_for_family("ssrf"))
        self.assertIsNone(analyzer_for_family("file_upload"))

    def test_methodology_grounding_is_non_evidentiary(self):
        result = self.analyze()
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(OPEN_REDIRECT_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("WSTG-CLNT-04", meta["taxonomy"]["wstg"])
        self.assertIn("CWE-601", meta["taxonomy"]["cwe"])
        basis = {item for step in OPEN_REDIRECT_METHOD for item in step["basis"]}
        self.assertIn("WSTG-CLNT-04", basis)
        self.assertIn("CWE-601", basis)
        self.assertTrue(all(row["non_evidentiary"] for row in meta["writeup_patterns"]))
        observed = {row["type"] for row in result["support"]}
        self.assertNotIn("owasp-wstg-clnt-04-client-url-redirect", observed)
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])

    def test_static_source_and_navigation_sink_are_one_correlated_root(self):
        result = self.analyze()
        observed = {row["type"] for row in result["support"]}
        roots = {row.get("source_group") for row in result["support"]}
        self.assertIn("redirect_parameter", observed)
        self.assertIn("navigation_context", observed)
        self.assertEqual(roots, {"open_redirect_static_flow"})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_validation_absence_alone_is_not_confirmation(self):
        result = self.analyze({
            "redirect_runtime_observations": [{"navigation_validation_absent": True}]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("navigation_validation_absent", observed)
        self.assertNotIn("external_destination_accepted", observed)
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_allowlist_and_same_origin_controls_are_contradictions(self):
        result = self.analyze({
            "redirect_runtime_observations": [{
                "destination_allowlist_observed": True,
                "same_origin_navigation_enforced": True,
                "requested_destination": "https://example.com/dashboard",
                "redirect_observed": True,
            }]
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("destination_allowlist_observed", contradictions)
        self.assertIn("same_origin_navigation_enforced", contradictions)
        self.assertFalse(result["direct"])

    def test_same_origin_destination_is_not_direct(self):
        result = self.analyze({
            "redirect_runtime_observations": [{
                "requested_destination": "https://example.com/account",
                "user_controlled_destination": True,
                "redirect_observed": True,
            }]
        })
        self.assertNotIn("external_destination_accepted", {row["type"] for row in result["support"]})
        self.assertIn("same_origin_navigation_enforced", {row["type"] for row in result["contradict"]})
        self.assertFalse(result["direct"])

    def test_relative_destination_is_not_direct(self):
        result = self.analyze({
            "redirect_runtime_observations": [{
                "requested_destination": "/dashboard",
                "user_controlled_destination": True,
                "redirect_observed": True,
            }]
        })
        self.assertNotIn("external_destination_accepted", {row["type"] for row in result["support"]})
        self.assertFalse(result["direct"])

    def test_external_navigation_without_user_control_is_not_direct(self):
        result = self.analyze({
            "redirect_runtime_observations": [{
                "final_destination": "https://controlled.example/landing",
                "redirect_observed": True,
                "navigation_validation_absent": True,
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("external_navigation_observed", observed)
        self.assertNotIn("external_destination_accepted", observed)
        self.assertFalse(result["direct"])

    def test_external_user_controlled_destination_is_direct_condition(self):
        result = self.analyze({
            "redirect_runtime_observations": [{
                "requested_destination": "https://controlled.example/landing",
                "final_destination": "https://controlled.example/landing",
                "user_controlled_destination": True,
                "redirect_observed": True,
                "navigation_validation_absent": True,
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("user_controlled_destination", observed)
        self.assertIn("navigation_validation_absent", observed)
        self.assertIn("external_destination_accepted", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "user_controlled_external_destination")
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_hostname_prefix_trick_is_parsed_as_external(self):
        result = self.analyze({
            "redirect_runtime_observations": [{
                "requested_destination": "https://example.com.evil.test/landing",
                "trusted_hosts": ["example.com"],
                "user_controlled_destination": True,
                "redirect_observed": True,
                "navigation_validation_absent": True,
            }]
        })
        self.assertIn("external_destination_accepted", {row["type"] for row in result["support"]})
        self.assertTrue(result["direct"])

    def test_static_candidate_path_retains_open_redirect_as_hidden_hypothesis(self):
        now = utc_now()
        self.db.execute(
            """INSERT INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "AN-REDIR-FAMILY", "example.com", "RUN-REDIR-FAMILY", "https://example.com/app.js",
                "location.search", "navigation", 90, "location.href = params.get('next')", now,
            ),
        )
        count = bug_candidates._static_candidates(self.db, "AN-REDIR-FAMILY", "RUN-REDIR-FAMILY", "example.com")
        self.assertEqual(count, 0)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='open_redirect'",
            ("AN-REDIR-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertFalse(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "open_redirect")
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='open_redirect'",
            ("AN-REDIR-FAMILY",),
        )
        self.assertIsNone(candidate)

    def test_static_path_promotes_only_with_independent_runtime_external_redirect(self):
        now = utc_now()
        js_url = "https://example.com/redirect.js"
        self.db.execute(
            """INSERT INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "AN-REDIR-FAMILY", "example.com", "RUN-REDIR-FAMILY", js_url,
                "location.search", "navigation", 92, "location.href = params.get('next')", now,
            ),
        )
        self.db.execute(
            """INSERT INTO semantic_js_units(analysis_id,target,run_id,js_url,unit_type,unit_key,value_json,confidence,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "AN-REDIR-FAMILY", "example.com", "RUN-REDIR-FAMILY", js_url,
                "redirect_runtime_observation", "controlled-external-runtime",
                json.dumps({
                    "requested_destination": "https://controlled.example/landing",
                    "final_destination": "https://controlled.example/landing",
                    "user_controlled_destination": True,
                    "redirect_observed": True,
                    "navigation_validation_absent": True,
                }),
                95, now,
            ),
        )
        count = bug_candidates._static_candidates(self.db, "AN-REDIR-FAMILY", "RUN-REDIR-FAMILY", "example.com")
        self.assertEqual(count, 1)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='open_redirect'",
            ("AN-REDIR-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("external_destination_accepted", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertTrue(admission["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='open_redirect'",
            ("AN-REDIR-FAMILY",),
        )
        self.assertIsNotNone(candidate)
        candidate_support = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("external_destination_accepted", candidate_support)


if __name__ == "__main__":
    unittest.main()
