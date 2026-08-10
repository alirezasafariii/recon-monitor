from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from dashboard import NAV_SECTIONS, _cluster_detail_context, _cluster_href, _investigation_cluster_detail_panel, _queue_item_card

SAMPLE_ITEM = {
    "cluster_id": "cluster-1", "target": "example.com", "queue_score": 86,
    "primary_bug": "BOLA / IDOR", "primary_family": "broken_object_authorization",
    "bug_proximity_score": 91, "target_evidence_confidence": 61, "hunt_priority": "HIGH",
    "cluster_strength": 84,
    "endpoints": ["/api/accounts/{accountId}/users/{userId}", "/api/accounts/{accountId}/orders/{orderId}"],
    "hypothesis_ids": ["h1", "h2"],
    "families": [{"family": "broken_object_authorization", "score": 91}, {"family": "information_disclosure", "score": 54}],
    "object_tokens": ["account", "user", "order"], "auth_boundaries": ["bearer_required", "mixed"],
    "why": ["shared object authorization surface"], "status": "investigation_queue_not_confirmed",
}


class FakeDB:
    def all(self, query, params=()):
        if "FROM analysis_hypotheses" in query:
            meta = {"primary": {
                "family": "broken_object_authorization", "bug_proximity_score": 91,
                "target_evidence_confidence": 61, "hunt_priority": "HIGH",
                "components": {"target_evidence": 61, "profile_compatibility": 88, "writeup_similarity": 70, "historical_feedback": 55, "correlation": 84, "llm_advisory": None},
                "evidence_gaps": ["one_of:ownership_mismatch|authorization_response_differential"],
                "why": ["strong target signals: object_identifier", "related-surface correlation: 84/100 (non-evidentiary)"],
            }}
            correlation = {
                "cluster_id": "cluster-1",
                "related_surfaces": [
                    {"endpoint": "/api/accounts/{accountId}/users/{userId}", "method": "GET", "auth_boundary": "bearer_required", "correlation_score": 100, "correlation_reasons": ["same normalized endpoint"]},
                    {"endpoint": "/api/accounts/{accountId}/orders/{orderId}", "method": "GET", "auth_boundary": "mixed", "correlation_score": 76, "correlation_reasons": ["shared object model: account", "auth-boundary differential: bearer_required -> mixed"]},
                ],
                "edges": [{"from": "/api/accounts/{accountId}/users/{userId}", "to": "/api/accounts/{accountId}/orders/{orderId}", "score": 76, "reasons": ["auth-boundary differential: bearer_required -> mixed"]}],
            }
            admission = json.dumps({"knowledge_context": {"meta_ranker": meta}, "correlation_context": correlation})
            return [
                {"hypothesis_id": "h1", "target": "example.com", "asset": "example.com", "endpoint": "/api/accounts/{accountId}/users/{userId}", "source_ref": "schema:users", "alert_id": 1, "bug_family": "broken_object_authorization", "bug_variant": "object_scope", "state": "shadow_partial", "summary": "User object surface", "supporting_evidence_json": json.dumps([{"type": "object_identifier", "source": "schema", "source_group": "schema", "text": "userId is visible", "weight": 20}]), "contradicting_evidence_json": "[]", "missing_evidence_json": json.dumps(["Cross-identity comparison"]), "decisive_signals_json": json.dumps(["object_identifier"]), "admission_json": admission, "promoted_candidate_id": "", "last_seen_at": "2026-08-10T00:00:00Z"},
                {"hypothesis_id": "h2", "target": "example.com", "asset": "example.com", "endpoint": "/api/accounts/{accountId}/orders/{orderId}", "source_ref": "schema:orders", "alert_id": 2, "bug_family": "broken_object_authorization", "bug_variant": "object_scope", "state": "promoted", "summary": "Order object surface", "supporting_evidence_json": json.dumps([{"type": "object_operation", "source": "endpoint", "source_group": "endpoint", "text": "GET object operation", "weight": 18}]), "contradicting_evidence_json": json.dumps([{"type": "auth_hint", "source": "client", "text": "Bearer auth is visible", "weight": -4}]), "missing_evidence_json": "[]", "decisive_signals_json": json.dumps(["object_operation"]), "admission_json": admission, "promoted_candidate_id": "c1", "last_seen_at": "2026-08-10T00:01:00Z"},
            ]
        if "FROM bug_candidates" in query:
            return [{"candidate_id": "c1", "bug_family": "broken_object_authorization", "bug_variant": "object_scope", "candidate_state": "plausible", "analyst_decision": "unreviewed", "priority_score": 79, "likelihood_score": 76, "evidence_strength": 66, "impact_potential": 84, "investigation_value": 82, "endpoint": "/api/accounts/{accountId}/orders/{orderId}", "summary": "Potential object authorization boundary", "safe_next_action": "Review authorized test objects only.", "updated_at": "2026-08-10T00:01:00Z"}]
        return []


class InvestigationDrilldownV865Tests(unittest.TestCase):
    def test_cluster_link_stays_inside_potential_findings(self):
        href = _cluster_href(SAMPLE_ITEM)
        self.assertTrue(href.startswith("/potential-findings?"))
        self.assertIn("cluster=cluster-1", href)
        self.assertIn("target=example.com", href)
        self.assertIn("#investigation-cluster-detail", href)
        card = _queue_item_card(SAMPLE_ITEM)
        self.assertIn("Open cluster", card)
        self.assertIn("cluster=cluster-1", card)

    def test_cluster_context_collects_target_evidence_findings_and_gaps(self):
        detail = _cluster_detail_context(FakeDB(), "a1", SAMPLE_ITEM)
        self.assertEqual(len(detail["hypotheses"]), 2)
        self.assertEqual(len(detail["candidates"]), 1)
        self.assertEqual(len(detail["support"]), 2)
        self.assertEqual(len(detail["contradict"]), 1)
        self.assertIn("Cross-identity comparison", detail["missing"])
        self.assertTrue(any(value.startswith("one_of:") for value in detail["missing"]))
        self.assertEqual(detail["correlation"]["cluster_id"], "cluster-1")
        self.assertEqual(detail["primary_meta"]["target_evidence_confidence"], 61)

    def test_drilldown_renders_complete_investigation_dossier(self):
        detail = _cluster_detail_context(FakeDB(), "a1", SAMPLE_ITEM)
        html = _investigation_cluster_detail_panel("a1", detail)
        for text in ["investigation-cluster-detail", "Investigation dossier", "Related Potential Findings", "Member hypotheses", "Evidence dossier", "Missing evidence", "Auth-boundary differentials", "bearer_required", "mixed", "Meta Ranker components", "Target evidence", "non-evidentiary", "not confirmed"]:
            self.assertIn(text.lower(), html.lower())

    def test_navigation_contract_remains_exactly_four_workspaces(self):
        self.assertEqual([(section_id, label) for section_id, label, _icon, _hint, _links in NAV_SECTIONS], [("recon", "01 · Recon"), ("analysis", "02 · Analysis"), ("findings", "03 · Potential Findings"), ("alerts", "04 · Alerts")])


if __name__ == "__main__":
    unittest.main()
