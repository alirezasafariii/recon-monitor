from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import bola_intelligence
import bug_candidates
from core import APP_VERSION, Database, utc_now
from family_analyzers.bola import (
    BOLA_FAMILY_ANALYZER_VERSION,
    BOLA_METHOD,
    analyze_bola_signal,
)
from family_analyzers.bola_core import analyze_bola_signal as core_analyze_bola_signal
from family_analyzers.router import analyzer_for_family, router_status


class BolaFamilyAnalyzerV868Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('RUN-BOLA-FAMILY',?,'success',?,?, 'example.com',1)",
            (APP_VERSION, now, now),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES('AN-BOLA-FAMILY','RUN-BOLA-FAMILY','example.com','8.6','family','analysis','success',?,?, '{}')",
            (now, now),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def analyze(self, details, endpoint="https://example.com/api/orders/{orderId}", ids=None, fields=None):
        return analyze_bola_signal(
            self.db,
            analysis_id="AN-BOLA-FAMILY",
            target="example.com",
            endpoint=endpoint,
            method="GET",
            object_ids=list(ids or ["orderId"]),
            structural_fields=list(fields or ["orderId"]),
            details=details,
            business_context="customer_data",
        )

    def test_production_compatibility_surface_routes_to_family_analyzer(self):
        self.assertIs(bola_intelligence.analyze_bola_signal, analyze_bola_signal)
        self.assertIs(bug_candidates._alert_candidates.__globals__["analyze_bola_signal"], analyze_bola_signal)
        self.assertEqual(bola_intelligence.BOLA_ENGINE_VERSION, "2.0.0")
        self.assertEqual(bola_intelligence.BOLA_RULE_VERSION, "2026.08.8.5")
        self.assertEqual(BOLA_FAMILY_ANALYZER_VERSION, "1.0.0")

    def test_router_is_explicit_and_has_no_generic_family_fallback(self):
        status = router_status()
        self.assertEqual(status["target_family_count"], 21)
        self.assertEqual(
            status["registered"],
            [
                "broken_object_authorization",
                "broken_function_authorization",
                "mass_assignment",
                "authentication_session",
                "account_enumeration",
                "dom_xss",
                "postmessage_trust",
            ],
        )
        self.assertEqual(status["registered_count"], 7)
        self.assertEqual(status["pending_count"], 14)
        self.assertFalse(status["generic_family_analyzer_fallback"])
        self.assertIsNotNone(analyzer_for_family("broken_object_authorization"))
        self.assertIsNotNone(analyzer_for_family("broken_function_authorization"))
        self.assertIsNotNone(analyzer_for_family("mass_assignment"))
        self.assertIsNotNone(analyzer_for_family("authentication_session"))
        self.assertIsNotNone(analyzer_for_family("account_enumeration"))
        self.assertIsNotNone(analyzer_for_family("dom_xss"))
        self.assertIsNotNone(analyzer_for_family("postmessage_trust"))
        self.assertIsNone(analyzer_for_family("ssrf"))

    def test_cwe_wstg_and_writeups_shape_reasoning_not_target_evidence(self):
        details = {
            "status_code": 200,
            "request_parent_id": "board-A",
            "object_parent_id": "board-B",
        }
        wrapped = self.analyze(
            details,
            endpoint="https://example.com/api/boards/{boardId}/custom-fields/{customFieldId}",
            ids=["boardId", "customFieldId"],
            fields=["boardId", "customFieldId"],
        )
        core = core_analyze_bola_signal(
            self.db,
            analysis_id="AN-BOLA-FAMILY",
            target="example.com",
            endpoint="https://example.com/api/boards/{boardId}/custom-fields/{customFieldId}",
            method="GET",
            object_ids=["boardId", "customFieldId"],
            structural_fields=["boardId", "customFieldId"],
            details=details,
            business_context="customer_data",
        )
        self.assertIsNotNone(wrapped)
        self.assertEqual(wrapped["support"], core["support"])
        self.assertEqual(wrapped["contradict"], core["contradict"])
        meta = wrapped["family_analyzer"]
        self.assertIn("CWE-639", meta["taxonomy"]["cwe"])
        self.assertIn("WSTG-ATHZ-04", meta["taxonomy"]["wstg"])
        method_basis = {basis for step in meta["methodology"] for basis in step["basis"]}
        self.assertIn("WSTG-ATHZ-02", method_basis)
        self.assertIn("WSTG-APIT-02", method_basis)
        refs = {row["id"] for row in meta["writeup_patterns"]}
        self.assertIn("ghsl-wekan-2026-044", refs)
        self.assertTrue(all(row["non_evidentiary"] for row in meta["writeup_patterns"]))
        self.assertTrue(meta["knowledge_does_not_change_target_evidence"])

    def test_cross_tenant_target_evidence_satisfies_confirmation_contract(self):
        result = self.analyze({
            "status_code": 200,
            "request_org_id": "org-attacker",
            "object_org_id": "org-victim",
        })
        meta = result["family_analyzer"]
        observed = {row["type"] for row in result["support"]}
        self.assertIn("cross_tenant_object_access", observed)
        self.assertEqual(meta["confirmation_missing"], [])
        self.assertTrue(meta["confirmation_ready_from_stored_target_evidence"])
        refs = {row["id"] for row in meta["writeup_patterns"]}
        self.assertIn("ghsl-sentry-2025-130", refs)

    def test_public_or_enforced_context_is_explained_as_false_positive_risk(self):
        result = self.analyze({
            "status_code": 200,
            "object_visibility": "shared",
            "ownership_enforced": True,
        })
        meta = result["family_analyzer"]
        triggered = {row["signal"] for row in meta["triggered_false_positive_checks"]}
        self.assertIn("public_or_shared_object", triggered)
        self.assertIn("ownership_enforcement_observed", triggered)
        self.assertFalse(meta["confirmation_ready_from_stored_target_evidence"])
        self.assertTrue(meta["confirmation_missing"])

    def test_methodology_has_separate_detection_boundary_comparison_and_contradiction_phases(self):
        ids = [step["id"] for step in BOLA_METHOD]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("BOLA-01-object-reference", ids)
        self.assertIn("BOLA-02-authorization-boundary", ids)
        self.assertIn("BOLA-03-horizontal-comparison", ids)
        self.assertIn("BOLA-04-behavioral-decision", ids)
        self.assertIn("BOLA-05-contradiction-check", ids)


if __name__ == "__main__":
    unittest.main()
