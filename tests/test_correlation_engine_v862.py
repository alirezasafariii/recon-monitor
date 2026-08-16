from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from correlation_engine import (
    build_correlation_context,
    canonical_object_token,
    correlation_family_scores,
    investigation_queue,
    normalize_endpoint,
)


class FakeDB:
    def __init__(self, *, contracts=None, relationships=None, boundaries=None, shapes=None, candidates=None, hypotheses=None):
        self.contracts = contracts or []
        self.relationships = relationships or []
        self.boundaries = boundaries or []
        self.shapes = shapes or []
        self.candidates = candidates or []
        self.hypotheses = hypotheses or []

    def all(self, query, params=()):
        if "FROM endpoint_contracts" in query:
            return self.contracts
        if "FROM parameter_relationships" in query:
            return self.relationships
        if "FROM authentication_boundaries" in query:
            return self.boundaries
        if "FROM response_shape_fingerprints" in query:
            return self.shapes
        if "FROM bug_candidates" in query:
            return self.candidates
        if "FROM analysis_hypotheses" in query:
            rows = self.hypotheses
            if "AND target=?" in query and len(params) > 1:
                rows = [row for row in rows if row.get("target") == params[1]]
            return rows
        return []


def fixture_db():
    contracts = [
        {
            "analysis_id": "a1", "target": "example.com", "alert_id": 1,
            "endpoint": "/api/accounts/{accountId}/users/{userId}", "method": "GET",
            "input_fields_json": json.dumps({"path": ["accountId", "userId"], "query": [], "body": []}),
            "output_fields_json": json.dumps(["user.id", "user.email", "accountId"]),
            "auth_boundary": "bearer_required", "confidence": 88,
        },
        {
            "analysis_id": "a1", "target": "example.com", "alert_id": 2,
            "endpoint": "/api/accounts/{accountId}/orders/{orderId}", "method": "GET",
            "input_fields_json": json.dumps({"path": ["accountId", "orderId"], "query": [], "body": []}),
            "output_fields_json": json.dumps(["order.id", "order.customerId", "accountId"]),
            "auth_boundary": "mixed", "confidence": 86,
        },
        {
            "analysis_id": "a1", "target": "example.com", "alert_id": 3,
            "endpoint": "/healthz", "method": "GET",
            "input_fields_json": json.dumps({"path": [], "query": [], "body": []}),
            "output_fields_json": json.dumps(["status"]),
            "auth_boundary": "public", "confidence": 70,
        },
    ]
    relationships = [
        {
            "analysis_id": "a1", "target": "example.com",
            "endpoint": "/api/accounts/{accountId}/users/{userId}",
            "parent_parameter": "accountId", "child_parameter": "userId",
            "relation": "contains", "confidence": 70,
        },
        {
            "analysis_id": "a1", "target": "example.com",
            "endpoint": "/api/accounts/{accountId}/orders/{orderId}",
            "parent_parameter": "accountId", "child_parameter": "orderId",
            "relation": "contains", "confidence": 70,
        },
    ]
    boundaries = [
        {"endpoint": "/api/accounts/{accountId}/users/{userId}", "boundary": "bearer_required", "confidence": 80},
        {"endpoint": "/api/accounts/{accountId}/orders/{orderId}", "boundary": "mixed", "confidence": 76},
        {"endpoint": "/healthz", "boundary": "public", "confidence": 70},
    ]
    shapes = [
        {
            "endpoint": "/api/accounts/{accountId}/users/{userId}",
            "keys_json": json.dumps(["user.id", "user.email", "accountId"]),
            "sensitive_keys_json": json.dumps(["user.email"]),
        },
        {
            "endpoint": "/api/accounts/{accountId}/orders/{orderId}",
            "keys_json": json.dumps(["order.id", "order.customerId", "accountId"]),
            "sensitive_keys_json": json.dumps(["order.customerId"]),
        },
    ]
    candidates = [
        {
            "candidate_id": "c1", "bug_family": "broken_object_authorization",
            "endpoint": "/api/accounts/{accountId}/orders/{orderId}",
            "alert_id": 2, "source_ref": "schema:orders", "investigation_value": 82,
            "candidate_state": "plausible",
        }
    ]
    return FakeDB(
        contracts=contracts,
        relationships=relationships,
        boundaries=boundaries,
        shapes=shapes,
        candidates=candidates,
    )


class CorrelationEngineV2Tests(unittest.TestCase):
    def test_normalization_and_object_tokens(self):
        self.assertEqual(normalize_endpoint("/api/orders/12345?userId=99"), "/api/orders/{n}?userid={value}")
        self.assertEqual(canonical_object_token("accountId"), "account")
        self.assertEqual(canonical_object_token("ownerId"), "user")

    def test_cross_endpoint_object_model_cluster(self):
        db = fixture_db()
        context = build_correlation_context(
            db,
            analysis_id="a1",
            target="example.com",
            endpoint="/api/accounts/{accountId}/users/{userId}",
            alert_id=1,
        )
        endpoints = {row["endpoint"] for row in context["related_surfaces"]}
        self.assertIn("/api/accounts/{accountId}/users/{userId}", endpoints)
        self.assertIn("/api/accounts/{accountId}/orders/{orderId}", endpoints)
        self.assertNotIn("/healthz", endpoints)
        self.assertIn("account", context["object_tokens"])
        self.assertGreaterEqual(context["family_scores"]["broken_object_authorization"], 50)
        self.assertTrue(context["safety"]["correlation_is_not_target_evidence"])

    def test_auth_boundary_difference_is_explainable(self):
        db = fixture_db()
        context = build_correlation_context(
            db,
            analysis_id="a1",
            target="example.com",
            endpoint="/api/accounts/{accountId}/users/{userId}",
        )
        edge_text = " ".join(
            reason
            for edge in context["edges"]
            for reason in edge["reasons"]
        )
        self.assertIn("auth-boundary differential", edge_text)

    def test_family_score_wrapper_returns_advisory_prior(self):
        db = fixture_db()
        scores = correlation_family_scores(
            db,
            analysis_id="a1",
            target="example.com",
            endpoint="/api/accounts/{accountId}/users/{userId}",
        )
        self.assertIn("broken_object_authorization", scores)
        self.assertLessEqual(scores["broken_object_authorization"], 88)

    def test_investigation_queue_deduplicates_cluster(self):
        db = fixture_db()
        meta = {
            "primary": {
                "family": "broken_object_authorization",
                "label": "BOLA / IDOR",
                "bug_proximity_score": 84,
                "target_evidence_confidence": 58,
                "hunt_priority": "HIGH",
                "why": ["shared object authorization surface"],
            },
            "rankings": [
                {"family": "broken_object_authorization", "bug_proximity_score": 84},
                {"family": "information_disclosure", "bug_proximity_score": 52},
            ],
        }
        db.hypotheses = [
            {
                "hypothesis_id": "h1", "target": "example.com", "asset": "example.com",
                "endpoint": "/api/accounts/{accountId}/users/{userId}", "source_ref": "schema:users",
                "alert_id": 1, "bug_family": "broken_object_authorization", "state": "shadow_partial",
                "summary": "user surface", "admission_json": json.dumps({"knowledge_context": {"meta_ranker": meta}}),
            },
            {
                "hypothesis_id": "h2", "target": "example.com", "asset": "example.com",
                "endpoint": "/api/accounts/{accountId}/orders/{orderId}", "source_ref": "schema:orders",
                "alert_id": 2, "bug_family": "broken_object_authorization", "state": "shadow_partial",
                "summary": "order surface", "admission_json": json.dumps({"knowledge_context": {"meta_ranker": meta}}),
            },
        ]
        queue = investigation_queue(db, "a1")
        self.assertEqual(len(queue), 1)
        self.assertEqual(set(queue[0]["hypothesis_ids"]), {"h1", "h2"})
        self.assertGreater(queue[0]["queue_score"], 0)
        self.assertEqual(queue[0]["status"], "investigation_queue_not_confirmed")


if __name__ == "__main__":
    unittest.main()
