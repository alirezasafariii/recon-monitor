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
from family_analyzers.router import analyzer_for_family, router_status
from family_analyzers.ssrf import (
    SSRF_FAMILY_ANALYZER_VERSION,
    SSRF_METHOD,
    analyze_ssrf_signal,
)


class SsrfFamilyAnalyzerV876Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-SSRF-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-SSRF-FAMILY','RUN-SSRF-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details=None, *, endpoint="https://example.com/api/preview", body_fields=None, query_fields=None, semantic_text="preview remote URL"):
        return analyze_ssrf_signal(
            self.db,
            analysis_id="AN-SSRF-FAMILY",
            target="example.com",
            endpoint=endpoint,
            method="POST",
            body_fields=list(["url"] if body_fields is None else body_fields),
            query_fields=list([] if query_fields is None else query_fields),
            details=dict(details or {}),
            business_context="general",
            semantic_text=semantic_text,
        )

    def _insert_alert_context(self, details: dict, *, endpoint="https://example.com/api/preview") -> int:
        schema = {
            "endpoint": endpoint,
            "method": "POST",
            "path_parameters": [],
            "query_parameters": [],
            "body_fields": ["url"],
            "object_identifiers": [],
            "authentication_hints": [],
            "is_endpoint": True,
        }
        now = utc_now()
        cursor = self.db.execute(
            """INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "example.com", f"ssrf-prod-{now}", "new_url", "info", 10, "preview endpoint",
                endpoint, json.dumps(details), "new", 1, now, now, "RUN-SSRF-FAMILY",
            ),
        )
        alert_id = int(cursor.lastrowid)
        self.db.execute(
            """INSERT INTO analysis_results(
            analysis_id,alert_id,target,source_run_id,category,original_score,adjusted_score,confidence,
            hypothesis,next_action,playbook_id,business_context,evidence_for_json,evidence_against_json,
            anomaly_score,baseline_json,feedback_json,duplicate_cluster,rule_ids_json,temporal_json,endpoint_schema_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "AN-SSRF-FAMILY", alert_id, "example.com", "RUN-SSRF-FAMILY", "new_url",
                50, 50, 88, "test", "review", "test", "general", "[]", "[]",
                0.0, "{}", "{}", "", "[]", "{}", json.dumps(schema), now,
            ),
        )
        return alert_id

    def _candidate_row_input(self, alert_id: int, details: dict, *, endpoint="https://example.com/api/preview") -> dict:
        schema = {
            "endpoint": endpoint,
            "method": "POST",
            "path_parameters": [],
            "query_parameters": [],
            "body_fields": ["url"],
            "object_identifiers": [],
            "authentication_hints": [],
            "is_endpoint": True,
        }
        return {
            "alert_id": alert_id,
            "target": "example.com",
            "endpoint_schema_json": json.dumps(schema),
            "details_json": json.dumps(details),
            "evidence_for_json": "[]",
            "evidence_against_json": "[]",
            "confidence": 88,
            "business_context": "general",
            "category": "new_url",
            "item": endpoint,
        }

    def test_router_registers_all_twenty_one_dedicated_families_without_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(status["registered_count"], 21)
        self.assertEqual(status["pending_count"], 0)
        self.assertEqual(status["registered"], [
  "broken_object_authorization", "broken_function_authorization", "mass_assignment",
  "authentication_session", "account_enumeration", "dom_xss", "postmessage_trust",
  "open_redirect", "ssrf", "file_upload", "path_traversal", "information_disclosure",
  "source_map_exposure", "secret_exposure", "graphql_authorization", "graphql_data_exposure",
  "business_logic", "race_condition", "websocket_authorization", "cors_misconfiguration",
  "sensitive_caching",
        ])
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("ssrf"))
        self.assertIsNotNone(analyzer_for_family("file_upload"))
        self.assertIsNotNone(analyzer_for_family("path_traversal"))
        self.assertIsNotNone(analyzer_for_family("information_disclosure"))
        self.assertIsNotNone(analyzer_for_family("source_map_exposure"))
        self.assertIsNotNone(analyzer_for_family("secret_exposure"))
        self.assertIsNotNone(analyzer_for_family("graphql_authorization"))

    def test_methodology_grounding_is_non_evidentiary(self):
        result = self.analyze()
        self.assertIsNotNone(result)
        meta = result["family_analyzer"]
        self.assertEqual(SSRF_FAMILY_ANALYZER_VERSION, "1.0.0")
        self.assertIn("WSTG-INPV-19", meta["taxonomy"]["wstg"])
        self.assertIn("CWE-918", meta["taxonomy"]["cwe"])
        basis = {item for step in SSRF_METHOD for item in step["basis"]}
        self.assertIn("WSTG-INPV-19", basis)
        self.assertIn("CWE-918", basis)
        self.assertTrue(all(row["non_evidentiary"] for row in meta["writeup_patterns"]))
        observed = {row["type"] for row in result["support"]}
        self.assertNotIn("owasp-wstg-inpv-19-ssrf", observed)
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])
        self.assertFalse(meta["active_validation_performed"])
        self.assertFalse(meta["internal_or_metadata_probing_performed"])

    def test_structural_destination_and_server_feature_are_one_evidence_root(self):
        result = self.analyze()
        observed = {row["type"] for row in result["support"]}
        roots = {row.get("source_group") for row in result["support"]}
        self.assertTrue({"remote_destination", "url_parameter", "server_feature", "server_fetch_semantic"} <= observed)
        self.assertEqual(roots, {"ssrf_structural_surface"})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_browser_side_fetch_is_a_blocking_false_positive_signal(self):
        result = self.analyze({
            "ssrf_runtime_observations": [{
                "execution_location": "browser",
                "user_controlled_destination": True,
                "browser_side_fetch_observed": True,
                "server_fetch_observed": False,
            }]
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("browser_side_fetch_observed", contradictions)
        self.assertIn("server_fetch_not_observed", contradictions)
        self.assertNotIn("server_fetch_observed", {row["type"] for row in result["support"]})
        self.assertFalse(result["direct"])

    def test_destination_controls_are_contradictions_and_block_direct_promotion(self):
        result = self.analyze({
            "ssrf_runtime_observations": [{
                "execution_location": "server",
                "user_controlled_destination": True,
                "server_fetch_observed": True,
                "destination_allowlist_enforced": True,
                "private_network_blocked": True,
            }]
        })
        contradictions = {row["type"] for row in result["contradict"]}
        self.assertIn("destination_validation_observed", contradictions)
        self.assertNotIn("server_fetch_observed", {row["type"] for row in result["support"]})
        self.assertFalse(result["direct"])
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])

    def test_server_fetch_without_user_control_is_capability_not_ssrf_direct_evidence(self):
        result = self.analyze({
            "ssrf_runtime_observations": [{
                "execution_location": "server",
                "user_controlled_destination": False,
                "server_fetch_observed": True,
                "requested_destination": "https://fixed.example/resource",
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("server_fetch_capability_observed", observed)
        self.assertNotIn("server_fetch_observed", observed)
        self.assertFalse(result["direct"])

    def test_user_controlled_server_fetch_is_potential_finding_evidence_not_confirmation(self):
        result = self.analyze({
            "ssrf_runtime_observations": [{
                "execution_location": "server",
                "user_controlled_destination": True,
                "server_fetch_observed": True,
                "destination_validation_absent": True,
                "requested_destination": "https://controlled.example/ssrf-marker",
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("server_fetch_observed", observed)
        self.assertIn("destination_validation_absent", observed)
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertTrue(result["family_analyzer"]["confirmation_missing"])
        self.assertEqual(result["variant"], "user_controlled_server_fetch")

    def test_controlled_callback_requires_server_attribution_and_correlation(self):
        unknown = self.analyze({
            "ssrf_runtime_observations": [{
                "execution_location": "unknown",
                "user_controlled_destination": True,
                "callback_received": True,
                "callback_token_match": True,
                "controlled_destination": True,
            }]
        })
        self.assertNotIn("controlled_callback_observed", {row["type"] for row in unknown["support"]})
        self.assertFalse(unknown["direct"])

        server = self.analyze({
            "ssrf_runtime_observations": [{
                "execution_location": "server",
                "user_controlled_destination": True,
                "callback_received": True,
                "callback_token_match": True,
                "controlled_destination": True,
            }]
        })
        self.assertIn("controlled_callback_observed", {row["type"] for row in server["support"]})
        self.assertTrue(server["direct"])
        self.assertFalse(server["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_destination_policy_bypass_is_stricter_confirmation_condition(self):
        result = self.analyze({
            "ssrf_runtime_observations": [{
                "execution_location": "server",
                "user_controlled_destination": True,
                "server_fetch_observed": True,
                "destination_validation_absent": True,
                "destination_policy_bypass_observed": True,
                "requested_destination": "https://controlled.example/ssrf-marker",
            }]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("server_fetch_observed", observed)
        self.assertIn("destination_policy_bypass_observed", observed)
        self.assertTrue(result["direct"])
        self.assertEqual(result["variant"], "destination_policy_bypass")
        self.assertEqual(result["family_analyzer"]["confirmation_missing"], [])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_policy_bypass_from_different_observation_cannot_hitchhike_on_prior_fetch(self):
        result = self.analyze({
            "ssrf_runtime_observations": [
                {
                    "execution_location": "server",
                    "user_controlled_destination": True,
                    "server_fetch_observed": True,
                    "requested_destination": "https://controlled.example/marker",
                },
                {
                    "execution_location": "browser",
                    "destination_policy_bypass_observed": True,
                    "browser_side_fetch_observed": True,
                },
            ]
        })
        observed = {row["type"] for row in result["support"]}
        self.assertIn("server_fetch_observed", observed)
        self.assertNotIn("destination_policy_bypass_observed", observed)
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

    def test_literal_private_destination_is_classified_offline_without_resolution_or_probe(self):
        result = self.analyze({
            "ssrf_runtime_observations": [{
                "execution_location": "server",
                "user_controlled_destination": True,
                "server_fetch_observed": True,
                "requested_destination": "http://169.254.169.254/example",
            }]
        })
        context = result["family_analyzer"]["destination_context"][0]
        self.assertEqual(context["host_kind"], "link_local")
        self.assertTrue(context["restricted_literal"])
        self.assertFalse(result["family_analyzer"]["dns_resolution_performed"])
        self.assertFalse(result["family_analyzer"]["internal_or_metadata_probing_performed"])

    def test_candidate_engine_keeps_structural_ssrf_as_hidden_hypothesis(self):
        details: dict = {}
        alert_id = self._insert_alert_context(details)
        row = self._candidate_row_input(alert_id, details)
        bug_candidates._alert_candidates(self.db, "AN-SSRF-FAMILY", "RUN-SSRF-FAMILY", row)

        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='ssrf'",
            ("AN-SSRF-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertFalse(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "ssrf")
        self.assertTrue(admission["family_analyzer"]["structural_destination_and_feature_are_one_evidence_root"])
        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='ssrf'",
            ("AN-SSRF-FAMILY",),
        )
        self.assertIsNone(candidate)

    def test_candidate_engine_promotes_only_after_stored_server_fetch_observation(self):
        details = {
            "ssrf_runtime_observations": [{
                "execution_location": "server",
                "user_controlled_destination": True,
                "server_fetch_observed": True,
                "destination_validation_absent": True,
                "requested_destination": "https://controlled.example/marker",
            }]
        }
        alert_id = self._insert_alert_context(details)
        row = self._candidate_row_input(alert_id, details)
        bug_candidates._alert_candidates(self.db, "AN-SSRF-FAMILY", "RUN-SSRF-FAMILY", row)

        hypothesis = self.db.one(
            "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='ssrf'",
            ("AN-SSRF-FAMILY",),
        )
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertTrue(admission["admitted"])
        self.assertEqual(admission["family_analyzer"]["family"], "ssrf")
        self.assertTrue(admission["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(admission["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])

        candidate = self.db.one(
            "SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='ssrf'",
            ("AN-SSRF-FAMILY",),
        )
        self.assertIsNotNone(candidate)
        support = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("server_fetch_observed", support)
        missing = json.loads(candidate["missing_evidence_json"])
        self.assertFalse(any("Family-specific evidence gate is incomplete" in str(item) for item in missing))


if __name__ == "__main__":
    unittest.main()
