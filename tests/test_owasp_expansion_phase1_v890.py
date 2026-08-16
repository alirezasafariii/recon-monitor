from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from bug_candidates import BUG_FAMILIES, CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION, generate_bug_candidates
from core import APP_VERSION, AppPaths, Database, utc_now
from family_analyzers.command_injection import analyze_command_injection_signal
from family_analyzers.api_expansion import (
    analyze_improper_inventory_management_signal, analyze_security_misconfiguration_signal,
    analyze_sensitive_business_flow_abuse_signal, analyze_unrestricted_resource_consumption_signal,
    analyze_unsafe_api_consumption_signal,
)
from family_analyzers.ldap_injection import analyze_ldap_injection_signal
from family_analyzers.nosql_injection import analyze_nosql_injection_signal
from family_analyzers.router import router_status
from family_analyzers.sql_injection import analyze_sql_injection_signal
from family_analyzers.ssti import analyze_ssti_signal
from family_reasoning import FAMILY_ORDER, confirmation_gaps, validation_level_for_family
from owasp_family_catalog import NEW_FAMILY_ORDER
from vulnerability_knowledge import BUG_PROFILES, knowledge_context


class OwaspExpansionPhase1V890Tests(unittest.TestCase):
    def test_phase1_remains_the_canonical_21_to_31_slice_inside_74_family_catalog(self):
        self.assertEqual(len(FAMILY_ORDER), 74)
        self.assertEqual(tuple(FAMILY_ORDER[21:31]), NEW_FAMILY_ORDER)
        self.assertEqual(set(BUG_FAMILIES), set(FAMILY_ORDER))
        status = router_status()
        self.assertEqual(status["registered_count"], 74)
        self.assertEqual(status["pending_count"], 0)
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertEqual(CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION, "4.0.0")

    def test_new_knowledge_profiles_are_non_evidentiary_context(self):
        for family in NEW_FAMILY_ORDER:
            self.assertIn(family, BUG_PROFILES)
            context = knowledge_context(family, [], endpoint="/api/test")
            self.assertEqual(context["role"], "classification_and_retrieval_only_not_target_evidence")
            self.assertEqual(context["primary_profile"]["label"], BUG_PROFILES[family]["label"])

    def test_injection_surfaces_do_not_confirm_without_controlled_behavior(self):
        result = analyze_sql_injection_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/search", method="GET",
            query_fields=["search"], semantic_text="server SQL SELECT query",
        )
        self.assertIsNotNone(result)
        self.assertFalse(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["payload_generated"])
        self.assertFalse(result["family_analyzer"]["active_request_performed"])

    def test_all_five_injection_analyzers_accept_only_benign_controlled_direct_evidence(self):
        cases = [
            (analyze_sql_injection_signal, "sql_query_influence_observed", ["search"], "SQL SELECT database query"),
            (analyze_nosql_injection_signal, "nosql_query_influence_observed", ["filter"], "MongoDB find query object"),
            (analyze_command_injection_signal, "command_execution_influence_observed", ["host"], "server subprocess ProcessBuilder"),
            (analyze_ssti_signal, "template_expression_evaluated", ["template"], "Jinja render_template template engine"),
            (analyze_ldap_injection_signal, "ldap_filter_influence_observed", ["username"], "LDAP directory search filter"),
        ]
        obs_keys = [
            "sql_injection_observations", "nosql_injection_observations", "command_injection_observations",
            "ssti_observations", "ldap_injection_observations",
        ]
        for (analyzer, decisive, fields, semantic), obs_key in zip(cases, obs_keys):
            details = {obs_key: [{"controlled_test_context": True, "benign_test_marker": True, decisive: True}]}
            result = analyzer(object(), analysis_id="AN", target="example.com", endpoint="/api/test", method="POST", body_fields=fields, details=details, semantic_text=semantic)
            self.assertIsNotNone(result)
            self.assertTrue(result["direct"], decisive)
            self.assertTrue(result["family_analyzer"]["promotion_ready_from_stored_target_evidence"], decisive)
            self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"], decisive)
            self.assertFalse(result["family_analyzer"]["payload_generated"])
            self.assertFalse(result["family_analyzer"]["dangerous_payload_used"])

    def test_resource_consumption_requires_limit_evidence_and_bounded_confirmation(self):
        potential = analyze_unrestricted_resource_consumption_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/api/export", method="POST",
            details={"resource_consuming_operation": True, "resource_limit_missing": True},
        )
        self.assertTrue(potential["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(potential["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        confirmed = analyze_unrestricted_resource_consumption_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/api/export", method="POST",
            details={
                "resource_consuming_operation": True,
                "resource_limit_missing": True,
                "resource_consumption_observations": [{
                    "controlled_test_context": True, "bounded_test": True, "within_authorized_budget": True,
                    "resource_limit_not_enforced": True,
                }],
            },
        )
        self.assertTrue(confirmed["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertFalse(confirmed["family_analyzer"]["load_test_performed"])
        self.assertFalse(confirmed["family_analyzer"]["concurrent_requests_performed"])

    def test_sensitive_business_flow_requires_explicit_business_policy(self):
        keyword_only = analyze_sensitive_business_flow_abuse_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/checkout/purchase", method="POST", details={}
        )
        self.assertFalse(keyword_only["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        potential = analyze_sensitive_business_flow_abuse_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/checkout/purchase", method="POST",
            details={"sensitive_business_flow": True, "business_abuse_rationale": "scarce test allocation", "abuse_control_missing": True},
        )
        self.assertTrue(potential["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(potential["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        confirmed = analyze_sensitive_business_flow_abuse_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/checkout/purchase", method="POST",
            details={
                "sensitive_business_flow": True, "business_abuse_rationale": "scarce test allocation", "abuse_control_missing": True,
                "business_flow_abuse_observations": [{
                    "controlled_test_context": True, "reversible_test_data": True,
                    "real_inventory_consumed": False, "business_limit_bypass_observed": True,
                }],
            },
        )
        self.assertTrue(confirmed["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertFalse(confirmed["family_analyzer"]["business_action_performed"])

    def test_security_misconfiguration_needs_concrete_observable_deviation(self):
        result = analyze_security_misconfiguration_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/debug", method="GET",
            details={"debug_mode_publicly_exposed": True},
        )
        self.assertTrue(result["direct"])
        self.assertTrue(result["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertFalse(result["family_analyzer"]["configuration_change_performed"])

    def test_inventory_drift_requires_authoritative_comparison_and_reachability_for_confirmation(self):
        potential = analyze_improper_inventory_management_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/api/v1/orders", method="GET",
            details={"inventory_drift_signal": True, "inventory_baseline": "approved v2 only"},
        )
        self.assertTrue(potential["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(potential["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        confirmed = analyze_improper_inventory_management_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/api/v1/orders", method="GET",
            details={"inventory_drift_signal": True, "inventory_baseline": "approved v2 only", "deprecated_api_publicly_reachable": True},
        )
        self.assertTrue(confirmed["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertFalse(confirmed["family_analyzer"]["scope_expansion_performed"])

    def test_unsafe_api_consumption_uses_target_side_evidence_only(self):
        potential = analyze_unsafe_api_consumption_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/api/quote", method="GET",
            details={"upstream_service": "pricing-provider", "downstream_sink": "quote response", "upstream_validation_missing": True},
        )
        self.assertTrue(potential["family_analyzer"]["promotion_ready_from_stored_target_evidence"])
        self.assertFalse(potential["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        confirmed = analyze_unsafe_api_consumption_signal(
            object(), analysis_id="AN", target="example.com", endpoint="/api/quote", method="GET",
            details={
                "upstream_service": "pricing-provider", "downstream_sink": "quote response", "upstream_validation_missing": True,
                "unsafe_api_consumption_observations": [{
                    "controlled_test_context": True,
                    "untrusted_upstream_data_reaches_sensitive_sink": True,
                    "third_party_probe_performed": False,
                }],
            },
        )
        self.assertTrue(confirmed["family_analyzer"]["confirmation_ready_from_stored_target_evidence"])
        self.assertFalse(confirmed["family_analyzer"]["third_party_probe_performed"])

    def test_confirmation_contracts_keep_promotion_separate_for_new_families(self):
        self.assertTrue(confirmation_gaps("sql_injection", {"sql_input", "sql_query_sink", "unsafe_sql_concatenation_observed"}))
        self.assertEqual(confirmation_gaps("sql_injection", {"sql_query_influence_observed"}), [])
        self.assertTrue(confirmation_gaps("unrestricted_resource_consumption", {"resource_consuming_operation", "resource_limit_missing"}))
        self.assertEqual(confirmation_gaps("unrestricted_resource_consumption", {"resource_limit_not_enforced"}), [])
        self.assertEqual(validation_level_for_family("unsafe_api_consumption"), "manual_only")

    def test_real_candidate_pipeline_promotes_sql_only_from_controlled_target_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now()
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-OWASP',?,'success',?,?,?,1)", (APP_VERSION, now, now, "example.com"))
                details = {
                    "method": "POST",
                    "body_fields": ["search"],
                    "sql_query_sink": True,
                    "sql_injection_observations": [{
                        "controlled_test_context": True,
                        "benign_test_marker": True,
                        "sql_query_influence_observed": True,
                    }],
                }
                alert_id, _, _ = db.upsert_alert("example.com", "owasp-sqli", "changed_endpoint", "HIGH", 80, "Search endpoint changed", "/api/search", details, "RUN-OWASP")
                db.set_alert_status(alert_id, "interesting", "controlled SQL evidence fixture")
                analysis = run_analysis(paths, db, "RUN-OWASP", "example.com")
                generate_bug_candidates(db, analysis["analysis_id"], "RUN-OWASP", "example.com")
                hypothesis = db.one("SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='sql_injection'", (analysis["analysis_id"],))
                candidate = db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='sql_injection'", (analysis["analysis_id"],))
                self.assertIsNotNone(hypothesis)
                self.assertIsNotNone(candidate)
            finally:
                db.close()


if __name__ == "__main__": unittest.main()
