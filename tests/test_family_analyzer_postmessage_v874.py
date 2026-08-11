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
from family_analyzers.postmessage_trust import (
    POSTMESSAGE_FAMILY_ANALYZER_VERSION,
    POSTMESSAGE_METHOD,
    analyze_postmessage_trust_signal,
)
from family_analyzers.router import analyzer_for_family, router_status


class PostMessageTrustFamilyAnalyzerV874Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-MSG-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-MSG-FAMILY','RUN-MSG-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details=None, *, sink="innerHTML", snippet="onmessage = e => out.innerHTML = e.data", confidence=85):
        return analyze_postmessage_trust_signal(
            self.db,
            analysis_id="AN-MSG-FAMILY",
            target="example.com",
            js_url="https://example.com/app.js",
            endpoint="https://example.com/app.js",
            method="GET",
            source_kind="postMessage",
            sink_kind=sink,
            snippet=snippet,
            confidence=confidence,
            details=dict(details or {}),
            business_context="general",
        )

    def test_router_registers_eight_dedicated_families_without_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered_count"], 8)
        self.assertEqual(status["pending_count"], 13)
        self.assertEqual(status["registered"], [
            "broken_object_authorization",
            "broken_function_authorization",
            "mass_assignment",
            "authentication_session",
            "account_enumeration",
            "dom_xss",
            "postmessage_trust",
            "open_redirect",
        ])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("postmessage_trust"))
        self.assertIsNotNone(analyzer_for_family("open_redirect"))
        self.assertIsNone(analyzer_for_family("ssrf"))

    def test_methodology_grounding_is_non_evidentiary(self):
        result = self.analyze()
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(POSTMESSAGE_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("WSTG-CLNT-11", meta["taxonomy"]["wstg"])
        self.assertIn("CWE-346", meta["taxonomy"]["cwe"])
        basis = {item for step in POSTMESSAGE_METHOD for item in step["basis"]}
        self.assertIn("WSTG-CLNT-11", basis)
        self.assertIn("CWE-346", basis)
        self.assertTrue(all(row["non_evidentiary"] for row in meta["writeup_patterns"]))
        observed = {row["type"] for row in result["support"]}
        self.assertNotIn("owasp-wstg-clnt-11-web-messaging", observed)
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])

    def test_static_handler_and_sink_are_one_correlated_root(self):
        result = self.analyze()
        observed = {row["type"] for row in result["support"]}
        roots = {row.get("source_group") for row in result["support"]}
        self.assertIn("postmessage_source", observed)
        self.assertIn("message_handler", observed)
        self.assertIn("sensitive_sink", observed)
        self.assertEqual(roots, {"postmessage_static_flow"})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_origin_validation_absence_is_not_confirmation(self):
        result = self.analyze({
            "postmessage_runtime_observations": [{
                "origin_validation_absent": True,
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("origin_validation_absent", observed)
        self.assertNotIn("untrusted_message_accepted", observed)
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_exact_origin_control_is_contradiction(self):
        result = self.analyze({
            "postmessage_runtime_observations": [{
                "origin_check_observed": True,
                "trusted_origin_only": True,
            }]
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("origin_check_observed", contradictions)
        self.assertIn("trusted_origin_only", contradictions)
        self.assertFalse(result["direct"])

    def test_untrusted_handler_acceptance_without_sensitive_effect_is_not_direct(self):
        result = self.analyze({
            "postmessage_runtime_observations": [{
                "message_origin": "https://untrusted.example",
                "trusted_origins": ["https://example.com"],
                "message_accepted": True,
                "origin_validation_absent": True,
                "sensitive_sink_reached": False,
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("untrusted_message_reached_handler", observed)
        self.assertNotIn("untrusted_message_accepted", observed)
        self.assertFalse(result["direct"])

    def test_untrusted_message_to_sensitive_consumer_is_direct_condition(self):
        result = self.analyze({
            "postmessage_runtime_observations": [{
                "message_origin": "https://untrusted.example",
                "trusted_origins": ["https://example.com"],
                "message_accepted": True,
                "origin_validation_absent": True,
                "sensitive_sink_reached": True,
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("origin_validation_absent", observed)
        self.assertIn("untrusted_message_accepted", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "untrusted_sender_to_sensitive_consumer")
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_trusted_origin_message_does_not_become_direct(self):
        result = self.analyze({
            "postmessage_runtime_observations": [{
                "message_origin": "https://example.com",
                "trusted_origins": ["https://example.com"],
                "message_accepted": True,
                "sensitive_sink_reached": True,
            }]
        })
        self.assertNotIn("untrusted_message_accepted", {row["type"] for row in result["support"]})
        self.assertFalse(result["direct"])

    def test_safe_text_consumer_does_not_emit(self):
        self.assertIsNone(self.analyze(sink="textContent", snippet="onmessage = e => out.textContent = e.data"))

    def test_static_candidate_path_retains_postmessage_as_hidden_hypothesis(self):
        now = utc_now()
        self.db.execute(
            """INSERT INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "AN-MSG-FAMILY", "example.com", "RUN-MSG-FAMILY", "https://example.com/app.js",
                "postMessage", "innerHTML", 90, "onmessage = e => out.innerHTML = e.data", now,
            ),
        )
        count = bug_candidates._static_candidates(self.db, "AN-MSG-FAMILY", "RUN-MSG-FAMILY", "example.com")
        self.assertEqual(count, 0)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='postmessage_trust'",
            ("AN-MSG-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertFalse(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "postmessage_trust")
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='postmessage_trust'",
            ("AN-MSG-FAMILY",),
        )
        self.assertIsNone(candidate)

    def test_static_path_promotes_only_with_independent_runtime_trust_failure(self):
        now = utc_now()
        js_url = "https://example.com/message.js"
        self.db.execute(
            """INSERT INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "AN-MSG-FAMILY", "example.com", "RUN-MSG-FAMILY", js_url,
                "postMessage", "innerHTML", 92, "onmessage = e => out.innerHTML = e.data", now,
            ),
        )
        self.db.execute(
            """INSERT INTO semantic_js_units(analysis_id,target,run_id,js_url,unit_type,unit_key,value_json,confidence,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "AN-MSG-FAMILY", "example.com", "RUN-MSG-FAMILY", js_url,
                "postmessage_runtime_observation", "controlled-untrusted-runtime",
                json.dumps({
                    "message_origin": "https://untrusted.example",
                    "trusted_origins": ["https://example.com"],
                    "message_accepted": True,
                    "origin_validation_absent": True,
                    "sensitive_sink_reached": True,
                }),
                95, now,
            ),
        )
        count = bug_candidates._static_candidates(self.db, "AN-MSG-FAMILY", "RUN-MSG-FAMILY", "example.com")
        self.assertEqual(count, 1)
        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='postmessage_trust'",
            ("AN-MSG-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        support = {item["type"] for item in json.loads(hypothesis["supporting_evidence_json"])}
        self.assertIn("untrusted_message_accepted", support)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertTrue(admission["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='postmessage_trust'",
            ("AN-MSG-FAMILY",),
        )
        self.assertIsNotNone(candidate)
        candidate_support = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("untrusted_message_accepted", candidate_support)


if __name__ == "__main__":
    unittest.main()
