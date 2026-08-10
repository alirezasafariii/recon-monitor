from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from bola_intelligence import BOLA_ENGINE_VERSION, BOLA_RULE_VERSION
from bug_candidates import _alert_candidates
from core import APP_VERSION, SCHEMA_VERSION, Database, utc_now
from hypothesis_admission import ADMISSION_ENGINE_VERSION, assess_admission


class BolaIntelligenceV850Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        self.analysis_id = "analysis-bola-v850"
        self.run_id = "run-bola-v850"
        self.target = "x.test"
        self.alert_seq = 0
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_count) VALUES(?,?,?,?,?,?)",
            (self.run_id, "8.5.0", "success", now, now, 1),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.analysis_id, self.run_id, self.target, "5.2.0", "2026.08.8.5", "analysis", "success", now, now, "{}"),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def row(
        self,
        endpoint: str,
        *,
        method: str = "GET",
        path=None,
        query=None,
        body=None,
        object_ids=None,
        details=None,
        category: str = "new_url",
        context: str = "general",
        is_endpoint: bool = True,
    ):
        self.alert_seq += 1
        schema = {
            "endpoint": endpoint,
            "method": method,
            "path": "/",
            "path_parameters": path or [],
            "query_parameters": query or [],
            "body_fields": body or [],
            "object_identifiers": object_ids or [],
            "content_type": "application/json",
            "authentication_hints": [],
            "is_endpoint": is_endpoint,
            "observation_kind": "endpoint" if is_endpoint else "infrastructure",
        }
        now = utc_now()
        cursor = self.db.execute(
            """INSERT INTO alerts(target,dedup_key,category,severity,risk_score,title,item,details_json,status,occurrences,first_seen,last_seen,last_run_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (self.target, f"bola-alert-{self.alert_seq}", category, "info", 10, "test", endpoint, json.dumps(details or {}), "new", 1, now, now, self.run_id),
        )
        return {
            "alert_id": int(cursor.lastrowid),
            "target": self.target,
            "endpoint_schema_json": json.dumps(schema),
            "details_json": json.dumps(details or {}),
            "evidence_for_json": "[]",
            "evidence_against_json": "[]",
            "confidence": 70,
            "business_context": context,
            "category": category,
            "item": endpoint,
        }

    def bola_candidate(self):
        return self.db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='broken_object_authorization'", (self.analysis_id,))

    def bola_hypothesis(self):
        return self.db.one("SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND bug_family='broken_object_authorization'", (self.analysis_id,))

    def test_version_contract(self):
        self.assertEqual(APP_VERSION, "8.5.0")
        self.assertEqual(SCHEMA_VERSION, 18)
        self.assertEqual(BOLA_ENGINE_VERSION, "2.0.0")
        self.assertEqual(BOLA_RULE_VERSION, "2026.08.8.5")
        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.0.0")

    def test_generic_object_id_is_retained_not_promoted(self):
        row = self.row("https://x.test/api/orders/{id}", path=["id"], object_ids=["id"])
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        self.assertIsNone(self.bola_candidate())
        hypothesis = self.bola_hypothesis()
        self.assertIsNotNone(hypothesis)
        admission = json.loads(hypothesis["admission_json"])
        self.assertFalse(admission["admitted"])
        self.assertIn(hypothesis["state"], {"shadow_signal", "shadow_partial", "shadow_contradicted"})
        self.assertTrue(any("unauthorized_object_response" in group or "cross_identity_object_access" in group for group in admission["required_missing"]))

    def test_spree_secondary_guard_pattern_promotes_only_from_target_evidence(self):
        row = self.row(
            "https://x.test/api/orders/{orderId}", path=["orderId"], object_ids=["orderId"],
            details={"status_code": 200, "secondary_guard_required": True, "secondary_guard_present": False},
            context="customer_data",
        )
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        candidate = self.bola_candidate()
        self.assertIsNotNone(candidate)
        types = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("object_access_without_secondary_guard", types)
        self.assertEqual(candidate["bug_variant"], "secondary_guard_gap")

    def test_zammad_authorization_expectation_differential_promotes(self):
        row = self.row(
            "https://x.test/api/ticket_related/{ticketId}", path=["ticketId"], object_ids=["ticketId"],
            details={"context_observations": [{"context": "agent_without_group_access", "expected_access": False, "status_code": 200}]},
            context="customer_data",
        )
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        candidate = self.bola_candidate()
        self.assertIsNotNone(candidate)
        types = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("unauthorized_object_response", types)
        self.assertIn("authorization_response_differential", types)
        self.assertEqual(candidate["bug_variant"], "authorization_differential")

    def test_wekan_parent_child_scope_mismatch_promotes(self):
        row = self.row(
            "https://x.test/api/boards/{boardId}/custom-fields/{customFieldId}",
            method="PUT", path=["boardId", "customFieldId"], object_ids=["boardId", "customFieldId"],
            details={"status_code": 200, "request_parent_id": "board-A", "object_parent_id": "board-B"},
        )
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        candidate = self.bola_candidate()
        self.assertIsNotNone(candidate)
        types = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("parent_child_scope_mismatch", types)
        self.assertEqual(candidate["bug_variant"], "parent_child_scope")

    def test_sentry_cross_tenant_pattern_promotes(self):
        row = self.row(
            "https://x.test/organizations/{orgId}/issues/{groupId}/events/latest/json/",
            path=["orgId", "groupId"], object_ids=["orgId", "groupId"],
            details={"status_code": 200, "request_org_id": "org-attacker", "object_org_id": "org-victim"},
            context="customer_data",
        )
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        candidate = self.bola_candidate()
        self.assertIsNotNone(candidate)
        types = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("cross_tenant_object_access", types)
        self.assertIn("identity_object_relation_conflict", types)
        self.assertEqual(candidate["bug_variant"], "cross_tenant_object")

    def test_cross_owner_pattern_promotes(self):
        row = self.row(
            "https://x.test/api/profiles/{profileId}", path=["profileId"], object_ids=["profileId"],
            details={"status_code": 200, "identity_id": "user-A", "object_owner_id": "user-B"},
            context="identity",
        )
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        candidate = self.bola_candidate()
        self.assertIsNotNone(candidate)
        types = {item["type"] for item in json.loads(candidate["supporting_evidence_json"])}
        self.assertIn("cross_identity_object_access", types)
        self.assertIn("ownership_mismatch", types)

    def test_explicit_unauthorized_denial_blocks_candidate_but_preserves_hypothesis(self):
        row = self.row(
            "https://x.test/api/orders/{orderId}", path=["orderId"], object_ids=["orderId"],
            details={"context_observations": [{"context": "other-owner", "expected_access": False, "status_code": 403}]},
        )
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        self.assertIsNone(self.bola_candidate())
        hypothesis = self.bola_hypothesis()
        self.assertIsNotNone(hypothesis)
        contradict = {item["type"] for item in json.loads(hypothesis["contradicting_evidence_json"])}
        self.assertIn("cross_context_denied", contradict)
        self.assertIn(hypothesis["state"], {"shadow_partial", "shadow_contradicted"})

    def test_public_or_shared_object_is_not_promoted_without_boundary_failure(self):
        row = self.row(
            "https://x.test/api/catalog/{id}", path=["id"], object_ids=["id"],
            details={"status_code": 200, "object_visibility": "shared"},
        )
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        self.assertIsNone(self.bola_candidate())
        hypothesis = self.bola_hypothesis()
        self.assertIsNotNone(hypothesis)
        contradict = {item["type"] for item in json.loads(hypothesis["contradicting_evidence_json"])}
        self.assertIn("public_or_shared_object", contradict)

    def test_knowledge_references_never_become_target_support(self):
        row = self.row("https://x.test/api/orders/{id}", path=["id"], object_ids=["id"])
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        hypothesis = self.bola_hypothesis()
        refs = json.loads(hypothesis["knowledge_references_json"])
        self.assertGreaterEqual(len(refs), 7)
        self.assertTrue(any(ref["source"] == "GitHub Security Lab" for ref in refs))
        support_text = json.dumps(json.loads(hypothesis["supporting_evidence_json"]))
        for forbidden in ("OWASP", "MITRE", "GitHub Security Lab", "GHSL-"):
            self.assertNotIn(forbidden, support_text)

    def test_dns_external_id_gateway_still_produces_no_bola_hypothesis(self):
        row = self.row(
            "nonmerchvendorprofile.anfcorp.com CNAME external-id-gateway.anfcorp.com",
            method="UNKNOWN", details={"rrtype": "CNAME"}, category="dns_change", is_endpoint=False,
        )
        _alert_candidates(self.db, self.analysis_id, self.run_id, row)
        self.assertIsNone(self.bola_candidate())
        self.assertIsNone(self.bola_hypothesis())

    def test_admission_requires_authorization_boundary_evidence(self):
        result = assess_admission(
            "broken_object_authorization",
            [
                {"type": "object_identifier", "source": "schema"},
                {"type": "object_operation", "source": "endpoint"},
            ],
            [],
        )
        self.assertFalse(result["admitted"])
        self.assertTrue(result["required_missing"])


if __name__ == "__main__":
    unittest.main()
