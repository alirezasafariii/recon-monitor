from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import AppPaths, Database
from family_analyzers.base import FamilyAnalyzerContext, clear_context_intelligence_bootstrap_cache
from family_analyzers.router import analyzer_for_family
from hypothesis_evidence_planner import plan_result_evidence
from temporal_intelligence import generate_temporal_intelligence
from workflow_state_intelligence import generate_workflow_state_intelligence


class TemporalWorkflowIntelligenceV963Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        clear_context_intelligence_bootstrap_cache()
        return temp, paths, db

    def _analysis(self, db: Database, analysis_id: str, run_id: str, target: str, when: str) -> None:
        db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES(?,?,?,?,?,'analysis','success',?,?, '{}')",
            (analysis_id, run_id, target, "6.0.0", "test", when, when),
        )

    def _contract(
        self,
        db: Database,
        analysis_id: str,
        run_id: str,
        target: str,
        endpoint: str,
        method: str,
        auth_boundary: str,
        when: str,
        *,
        alert_id: int,
        confidence: int = 85,
    ) -> None:
        db.execute(
            "INSERT INTO endpoint_contracts(analysis_id,target,source_run_id,alert_id,endpoint,method,input_fields_json,output_fields_json,auth_boundary,object_relations_json,confidence,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                analysis_id,
                target,
                run_id,
                alert_id,
                endpoint,
                method,
                '{"path":[],"query":[],"body":[]}',
                "[]",
                auth_boundary,
                "[]",
                confidence,
                when,
            ),
        )

    def _boundary(
        self,
        db: Database,
        analysis_id: str,
        target: str,
        endpoint: str,
        boundary: str,
        when: str,
        confidence: int = 88,
    ) -> None:
        db.execute(
            "INSERT INTO authentication_boundaries(analysis_id,target,endpoint,boundary,confidence,evidence_json,created_at) "
            "VALUES(?,?,?,?,?,'[]',?)",
            (analysis_id, target, endpoint, boundary, confidence, when),
        )

    def _shape(
        self,
        db: Database,
        analysis_id: str,
        target: str,
        endpoint: str,
        sensitive: list[str],
        when: str,
    ) -> None:
        keys = sorted(set(["status", *sensitive]))
        types = {key: "str" for key in keys}
        db.execute(
            "INSERT INTO response_shape_fingerprints(analysis_id,target,endpoint,status_code,shape_hash,keys_json,types_json,sensitive_keys_json,confidence,created_at) "
            "VALUES(?,?,?,200,?,?,?,?,90,?)",
            (
                analysis_id,
                target,
                endpoint,
                f"shape-{analysis_id}",
                json.dumps(keys),
                json.dumps(types),
                json.dumps(sensitive),
                when,
            ),
        )

    def test_multi_scan_memory_detects_recurrence_regression_growth_and_contract_expansion(self):
        temp, _paths, db = self.project()
        target = "example.test"
        endpoint = "https://example.test/api/account"
        try:
            snapshots = [
                ("A1", "R1", "2026-08-12T10:00:00Z", "GET", "session_required", []),
                ("A2", "R2", "2026-08-13T10:00:00Z", "GET", "session_required", []),
                ("A3", "R3", "2026-08-14T10:00:00Z", "POST", "public", ["email", "balance"]),
            ]
            for alert_id, (analysis_id, run_id, when, method, boundary, sensitive) in enumerate(snapshots, start=1):
                self._analysis(db, analysis_id, run_id, target, when)
                self._contract(
                    db,
                    analysis_id,
                    run_id,
                    target,
                    endpoint,
                    method,
                    boundary,
                    when,
                    alert_id=alert_id,
                )
                self._boundary(db, analysis_id, target, endpoint, boundary, when)
                self._shape(db, analysis_id, target, endpoint, sensitive, when)

            result = generate_temporal_intelligence(db, "A3", "R3", [target], history_limit=6)
            self.assertEqual(result["targets"][target]["history_depth"], 2)
            self.assertEqual(result["counts"]["recurrence"], 1)
            self.assertEqual(result["counts"]["auth_boundary_drift"], 1)
            self.assertEqual(result["counts"]["sensitive_growth"], 1)
            self.assertEqual(result["counts"]["contract_expansion"], 1)

            rows = [
                dict(row)
                for row in db.all(
                    "SELECT kind,evidence_json FROM protocol_findings WHERE analysis_id='A3' AND protocol='temporal' ORDER BY kind"
                )
            ]
            kinds = {str(row["kind"]) for row in rows}
            self.assertIn("temporal_endpoint_recurrence_surface", kinds)
            self.assertIn("temporal_auth_boundary_regression_surface", kinds)
            self.assertIn("temporal_sensitive_response_growth_surface", kinds)
            self.assertIn("temporal_contract_expansion_surface", kinds)
            for row in rows:
                evidence = json.loads(row["evidence_json"])
                self.assertTrue(evidence["context_only"])
                self.assertTrue(evidence["non_decisive"])
                self.assertFalse(evidence["active_request_performed"])
                self.assertTrue(evidence["independent_evidence_requires_distinct_stored_snapshots"])
        finally:
            db.close()
            temp.cleanup()

    def test_workflow_graph_groups_path_identifiers_and_models_multi_stage_resource(self):
        temp, _paths, db = self.project()
        target = "example.test"
        analysis_id = "WF-A1"
        run_id = "WF-R1"
        when = "2026-08-14T10:00:00Z"
        try:
            self._analysis(db, analysis_id, run_id, target, when)
            for alert_id, endpoint in enumerate((
                "https://example.test/api/orders/{id}/create",
                "https://example.test/api/orders/{id}/submit",
                "https://example.test/api/orders/{id}/approve",
                "https://example.test/api/orders/{id}/refund",
            ), start=1):
                self._contract(
                    db,
                    analysis_id,
                    run_id,
                    target,
                    endpoint,
                    "POST",
                    "session_required",
                    when,
                    alert_id=alert_id,
                )

            result = generate_workflow_state_intelligence(db, analysis_id, [target])
            self.assertEqual(result["counts"]["state_machines"], 1)
            self.assertGreaterEqual(result["counts"]["workflow_transition_edges"], 3)
            self.assertGreaterEqual(result["counts"]["privileged"], 2)
            self.assertGreaterEqual(result["counts"]["single_use_or_financial"], 2)

            row = db.one(
                "SELECT evidence_json FROM protocol_findings WHERE analysis_id=? AND protocol='workflow' "
                "AND kind='workflow_state_machine_surface' AND entity LIKE '%/approve' LIMIT 1",
                (analysis_id,),
            )
            self.assertIsNotNone(row)
            evidence = json.loads(row["evidence_json"])
            self.assertEqual(evidence["resource"], "orders")
            self.assertEqual(evidence["actions"], ["create", "submit", "approve", "refund"])
            self.assertTrue(evidence["context_only"])
            self.assertTrue(evidence["route_semantics_are_not_behavioral_proof"])
        finally:
            db.close()
            temp.cleanup()

    def test_family_context_consumes_workflow_graph_but_raw_surface_cannot_promote(self):
        temp, _paths, db = self.project()
        target = "example.test"
        analysis_id = "CTX-A1"
        run_id = "CTX-R1"
        when = "2026-08-14T10:00:00Z"
        approve_endpoint = "https://example.test/api/orders/{id}/approve"
        try:
            self._analysis(db, analysis_id, run_id, target, when)
            for alert_id, endpoint in enumerate((
                "https://example.test/api/orders/{id}/create",
                "https://example.test/api/orders/{id}/submit",
                approve_endpoint,
                "https://example.test/api/orders/{id}/refund",
            ), start=1):
                self._contract(
                    db,
                    analysis_id,
                    run_id,
                    target,
                    endpoint,
                    "POST",
                    "session_required",
                    when,
                    alert_id=alert_id,
                )

            context = FamilyAnalyzerContext(
                db=db,
                analysis_id=analysis_id,
                target=target,
                endpoint=approve_endpoint,
                method="POST",
                details={
                    "raw_surface_observation": True,
                    "active_request_performed": False,
                },
            )
            self.assertTrue(context.details.get("workflow_sequence_context"))
            self.assertIn("approve", context.details.get("workflow_markers", []))
            generated = context.details.get("_generated_context_intelligence", {})
            self.assertTrue(generated.get("context_only"))
            self.assertTrue(generated.get("non_decisive"))

            analyzer = analyzer_for_family("business_logic")
            self.assertIsNotNone(analyzer)
            result = analyzer.analyze(context)
            self.assertIsNotNone(result)
            self.assertFalse(result["direct"])
            self.assertTrue(result["family_analyzer"]["raw_context_only_promotion_blocked"])
            self.assertTrue(
                all(str(item.get("type") or "").startswith("context_only:") for item in result.get("support", []))
            )
            plan = result["family_analyzer"]["evidence_acquisition_plan"]
            self.assertTrue(plan["diagnostic_only"])
            self.assertFalse(plan["network_requests"])
            self.assertFalse(plan["creates_target_evidence"])
            self.assertFalse(plan["changes_admission"])
            self.assertEqual(
                db.one("SELECT COUNT(*) count FROM bug_candidates WHERE analysis_id=?", (analysis_id,))["count"],
                0,
            )
        finally:
            db.close()
            temp.cleanup()

    def test_evidence_planner_requires_controlled_or_manual_context_for_risky_gaps(self):
        controlled = plan_result_evidence(
            "broken_object_authorization",
            ["Behavior with another explicitly authorized test object"],
        )
        self.assertEqual(controlled["minimum_next_step_level"], "controlled")
        self.assertEqual(controlled["steps"][0]["kind"], "controlled_comparison")
        self.assertTrue(controlled["steps"][0]["requires_explicit_test_identity_or_resource"])
        self.assertFalse(controlled["steps"][0]["automatic"])

        manual = plan_result_evidence(
            "race_condition",
            ["Whether concurrent execution violates the state transition invariant"],
        )
        self.assertEqual(manual["minimum_next_step_level"], "manual_only")
        self.assertEqual(manual["steps"][0]["kind"], "manual_validation")
        self.assertFalse(manual["steps"][0]["automatic"])
        self.assertFalse(manual["network_requests"])
        self.assertFalse(manual["changes_admission"])


if __name__ == "__main__":
    unittest.main()
