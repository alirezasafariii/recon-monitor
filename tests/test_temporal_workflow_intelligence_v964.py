from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from controlled_evidence_executor import (
    analyzer_details_from_comparison,
    compare_controlled_captures,
    execute_stored_capture_comparison,
)
from core import AppPaths, Database
from temporal_intelligence import SNAPSHOT_DECAY, generate_temporal_intelligence
from workflow_state_intelligence import generate_workflow_state_intelligence


class TemporalWorkflowIntelligenceV964Tests(unittest.TestCase):
    def project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
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
        alert_id: int,
    ) -> None:
        db.execute(
            "INSERT INTO endpoint_contracts(analysis_id,target,source_run_id,alert_id,endpoint,method,input_fields_json,output_fields_json,auth_boundary,object_relations_json,confidence,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,90,?)",
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
    ) -> None:
        db.execute(
            "INSERT INTO authentication_boundaries(analysis_id,target,endpoint,boundary,confidence,evidence_json,created_at) "
            "VALUES(?,?,?,?,90,'[]',?)",
            (analysis_id, target, endpoint, boundary, when),
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
        db.execute(
            "INSERT INTO response_shape_fingerprints(analysis_id,target,endpoint,status_code,shape_hash,keys_json,types_json,sensitive_keys_json,confidence,created_at) "
            "VALUES(?,?,?,200,?,?,?,?,90,?)",
            (
                analysis_id,
                target,
                endpoint,
                f"shape-{analysis_id}",
                json.dumps(keys),
                json.dumps({key: "str" for key in keys}),
                json.dumps(sensitive),
                when,
            ),
        )

    def test_temporal_decay_tracks_persistent_protected_to_public_sequence(self):
        temp, _paths, db = self.project()
        target = "example.test"
        endpoint = "https://example.test/api/account"
        try:
            snapshots = [
                ("A1", "R1", "2026-08-11T10:00:00Z", "session_required"),
                ("A2", "R2", "2026-08-12T10:00:00Z", "session_required"),
                ("A3", "R3", "2026-08-13T10:00:00Z", "public"),
                ("A4", "R4", "2026-08-14T10:00:00Z", "public"),
            ]
            for alert_id, (analysis_id, run_id, when, boundary) in enumerate(snapshots, start=1):
                self._analysis(db, analysis_id, run_id, target, when)
                self._contract(db, analysis_id, run_id, target, endpoint, "GET", boundary, when, alert_id)
                self._boundary(db, analysis_id, target, endpoint, boundary, when)

            result = generate_temporal_intelligence(db, "A4", "R4", [target])
            self.assertEqual(result["snapshot_decay"], SNAPSHOT_DECAY)
            self.assertEqual(result["counts"]["persistent_auth_regression"], 1)

            row = db.one(
                "SELECT evidence_json FROM protocol_findings WHERE analysis_id='A4' AND protocol='temporal' "
                "AND kind='temporal_auth_boundary_regression_surface' AND entity=?",
                (endpoint,),
            )
            self.assertIsNotNone(row)
            evidence = json.loads(row["evidence_json"])
            self.assertEqual(evidence["snapshot_decay"], SNAPSHOT_DECAY)
            self.assertEqual(evidence["public_persistence_snapshots"], 2)
            self.assertEqual(evidence["latest_boundary"], "public")
            transitions = [item["transition"] for item in evidence["transition_sequence"]]
            self.assertEqual(transitions.count("protected_to_public"), 1)
            timeline = evidence["boundary_timeline"]
            weights = {item["analysis_id"]: item["weight"] for item in timeline}
            self.assertEqual(weights["A4"], 1.0)
            self.assertGreater(weights["A4"], weights["A3"])
            self.assertGreater(weights["A3"], weights["A2"])
            self.assertGreater(weights["A2"], weights["A1"])
            self.assertTrue(evidence["context_only"])
            self.assertTrue(evidence["non_decisive"])
            self.assertFalse(evidence["active_request_performed"])
        finally:
            db.close()
            temp.cleanup()

    def test_sensitive_growth_sequence_is_recency_weighted(self):
        temp, _paths, db = self.project()
        target = "example.test"
        endpoint = "https://example.test/api/profile"
        try:
            snapshots = [
                ("S1", "R1", "2026-08-12T10:00:00Z", []),
                ("S2", "R2", "2026-08-13T10:00:00Z", ["email"]),
                ("S3", "R3", "2026-08-14T10:00:00Z", ["email", "balance"]),
            ]
            for alert_id, (analysis_id, run_id, when, sensitive) in enumerate(snapshots, start=10):
                self._analysis(db, analysis_id, run_id, target, when)
                self._contract(db, analysis_id, run_id, target, endpoint, "GET", "session_required", when, alert_id)
                self._shape(db, analysis_id, target, endpoint, sensitive, when)

            result = generate_temporal_intelligence(db, "S3", "R3", [target])
            self.assertEqual(result["counts"]["sensitive_growth_sequence"], 1)
            row = db.one(
                "SELECT evidence_json FROM protocol_findings WHERE analysis_id='S3' AND protocol='temporal' "
                "AND kind='temporal_sensitive_response_growth_surface' AND entity=?",
                (endpoint,),
            )
            evidence = json.loads(row["evidence_json"])
            self.assertEqual(evidence["growth_event_count"], 2)
            self.assertGreater(evidence["weighted_growth_score"], 0)
            self.assertTrue(evidence["monotonic_non_decreasing"])
            self.assertEqual(evidence["new_sensitive_keys"], ["balance"])
        finally:
            db.close()
            temp.cleanup()

    def test_workflow_invariant_and_role_boundary_differential_remain_non_decisive(self):
        temp, _paths, db = self.project()
        target = "example.test"
        analysis_id = "WF2-A1"
        run_id = "WF2-R1"
        when = "2026-08-14T10:00:00Z"
        submit = "https://example.test/api/orders/{id}/submit"
        approve = "https://example.test/api/orders/{id}/approve"
        try:
            self._analysis(db, analysis_id, run_id, target, when)
            self._contract(db, analysis_id, run_id, target, submit, "POST", "role_gated_hint", when, 31)
            self._contract(db, analysis_id, run_id, target, approve, "POST", "public", when, 32)

            result = generate_workflow_state_intelligence(db, analysis_id, [target])
            self.assertGreaterEqual(result["counts"]["invariant_candidates"], 1)
            self.assertGreaterEqual(result["counts"]["role_boundary_differentials"], 1)

            invariant = db.one(
                "SELECT evidence_json FROM protocol_findings WHERE analysis_id=? AND protocol='workflow' "
                "AND kind='workflow_invariant_candidate_surface' AND entity=?",
                (analysis_id, approve),
            )
            differential = db.one(
                "SELECT evidence_json FROM protocol_findings WHERE analysis_id=? AND protocol='workflow' "
                "AND kind='workflow_role_boundary_differential_surface' AND entity=?",
                (analysis_id, approve),
            )
            self.assertIsNotNone(invariant)
            self.assertIsNotNone(differential)
            invariant_evidence = json.loads(invariant["evidence_json"])
            differential_evidence = json.loads(differential["evidence_json"])
            self.assertTrue(invariant_evidence["invariant_is_inferred_not_observed"])
            self.assertFalse(invariant_evidence["violation_observed"])
            self.assertTrue(differential_evidence["boundary_differential_only"])
            self.assertFalse(differential_evidence["authorization_failure_observed"])
            self.assertTrue(differential_evidence["context_only"])
            self.assertTrue(differential_evidence["non_decisive"])
        finally:
            db.close()
            temp.cleanup()

    def test_role_response_differential_requires_distinct_auth_and_response_contexts(self):
        temp, _paths, db = self.project()
        target = "example.test"
        analysis_id = "WF3-A1"
        run_id = "WF3-R1"
        when = "2026-08-14T10:00:00Z"
        endpoint = "https://example.test/api/admin/orders"
        try:
            self._analysis(db, analysis_id, run_id, target, when)
            for context, auth_state, status, shape, source in (
                ("admin", "admin", 200, "shape-admin", "capture:admin"),
                ("user", "user", 403, "shape-denied", "capture:user"),
            ):
                db.execute(
                    "INSERT INTO behavioral_observations(analysis_id,target,endpoint,context,auth_state,status_code,shape_hash,headers_json,source_ref,confidence,created_at) "
                    "VALUES(?,?,?,?,?,?,?,'{}',?,90,?)",
                    (analysis_id, target, endpoint, context, auth_state, status, shape, source, when),
                )

            result = generate_workflow_state_intelligence(db, analysis_id, [target])
            self.assertEqual(result["counts"]["role_response_differentials"], 1)
            row = db.one(
                "SELECT evidence_json FROM protocol_findings WHERE analysis_id=? AND protocol='workflow' "
                "AND kind='workflow_role_response_differential_surface' AND entity=?",
                (analysis_id, endpoint),
            )
            evidence = json.loads(row["evidence_json"])
            self.assertEqual(evidence["auth_states"], ["admin", "user"])
            self.assertTrue(evidence["status_delta"])
            self.assertTrue(evidence["shape_delta"])
            self.assertFalse(evidence["explicit_violation_observed"])
            self.assertTrue(evidence["response_differential_is_not_authorization_failure_proof"])
        finally:
            db.close()
            temp.cleanup()

    def test_controlled_capture_executor_fail_closed_and_builds_bola_context_only_after_valid_contract(self):
        endpoint = "https://example.test/api/orders/TEST-1"
        contract = {
            "family": "broken_object_authorization",
            "target": "example.test",
            "endpoint": endpoint,
            "expected_relation": "probe_must_not_expose_equivalent_data",
            "authorization_acknowledged": True,
            "test_owned": True,
            "reversible": True,
            "control_identity": "test-owner",
            "probe_identity": "test-peer",
            "resource_id": "TEST-1",
            "resource_owner_identity": "test-owner",
        }
        control = {
            "target": "example.test",
            "endpoint": endpoint,
            "identity_id": "test-owner",
            "resource_id": "TEST-1",
            "resource_owner_identity": "test-owner",
            "status_code": 200,
            "shape_hash": "shape-private-order",
            "sensitive_key_names": ["email", "balance"],
            "controlled_capture": True,
            "test_owned": True,
            "reversible": True,
        }
        probe = {
            **control,
            "identity_id": "test-peer",
        }

        blocked = compare_controlled_captures(contract, control, {**probe, "test_owned": False})
        self.assertEqual(blocked["status"], "blocked")
        self.assertIn("probe_test_owned_required", blocked["blocking_reasons"])
        self.assertFalse(blocked["network_requests"])

        result = compare_controlled_captures(contract, control, probe)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["classification"], "strengthened")
        self.assertFalse(result["confirms_vulnerability"])
        self.assertFalse(result["changes_admission"])
        self.assertFalse(result["credentials_stored"])
        details = analyzer_details_from_comparison(result)
        observation = details["context_observations"][0]
        self.assertFalse(observation["expected_access"])
        self.assertEqual(observation["identity_id"], "test-peer")
        self.assertEqual(observation["object_owner_id"], "test-owner")
        self.assertTrue(observation["controlled_test_context"])
        self.assertTrue(observation["reversible_test_data"])

    def test_stored_capture_execution_persists_only_non_decisive_differential(self):
        temp, _paths, db = self.project()
        target = "example.test"
        endpoint = "https://example.test/api/orders/TEST-2"
        case_id = "CASE-CONTROLLED-1"
        when = "2026-08-14T10:00:00Z"
        try:
            db.execute(
                "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,0,'new','','in_scope',0,?,?)",
                (case_id, "controlled-test", "CE-A1", "CE-R1", target, "Controlled test", "Controlled test", "broken_object_authorization", when, when),
            )
            base = {
                "target": target,
                "endpoint": endpoint,
                "resource_id": "TEST-2",
                "resource_owner_identity": "test-owner",
                "status_code": 200,
                "shape_hash": "shape-private-order",
                "sensitive_key_names": ["email"],
                "controlled_capture": True,
                "test_owned": True,
                "reversible": True,
            }
            for observation_id, identity in (("OBS-CONTROL", "test-owner"), ("OBS-PROBE", "test-peer")):
                payload = {**base, "identity_id": identity}
                db.execute(
                    "INSERT INTO imported_http_evidence(observation_id,case_id,target,source_type,source_file,observation_json,imported_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (observation_id, case_id, target, "controlled_test_capture", f"{observation_id}.json", json.dumps(payload), "analyst", when),
                )

            contract = {
                "family": "broken_object_authorization",
                "target": target,
                "endpoint": endpoint,
                "expected_relation": "probe_must_be_rejected",
                "authorization_acknowledged": True,
                "test_owned": True,
                "reversible": True,
                "control_identity": "test-owner",
                "probe_identity": "test-peer",
                "resource_id": "TEST-2",
                "resource_owner_identity": "test-owner",
            }
            result = execute_stored_capture_comparison(
                db,
                analysis_id="CE-A1",
                contract=contract,
                control_observation_id="OBS-CONTROL",
                probe_observation_id="OBS-PROBE",
            )
            self.assertEqual(result["classification"], "strengthened")
            self.assertTrue(result.get("persisted_diff_id"))
            row = db.one(
                "SELECT diff_kind,details_json FROM differential_findings WHERE diff_id=?",
                (result["persisted_diff_id"],),
            )
            self.assertEqual(row["diff_kind"], "controlled_test_capture_comparison")
            details = json.loads(row["details_json"])
            self.assertTrue(details["context_only"])
            self.assertTrue(details["non_decisive_until_family_reasoning"])
            self.assertTrue(details["comparison_does_not_equal_confirmation"])
            self.assertFalse(details["network_requests"])
            self.assertFalse(details["changes_admission"])
        finally:
            db.close()
            temp.cleanup()


    def test_stored_capture_comparison_rejects_cross_case_and_analysis_rebinding(self):
        temp, _paths, db = self.project()
        target = "example.test"
        endpoint = "https://example.test/api/orders/TEST-3"
        when = "2026-08-14T10:00:00Z"
        try:
            for case_id, analysis_id in (("CASE-BIND-A", "BIND-A1"), ("CASE-BIND-B", "BIND-A2")):
                db.execute(
                    "INSERT INTO security_cases(case_id,case_key,analysis_id,source_run_id,target,title,summary,primary_family,priority_score,state,assigned_to,scope_status,report_readiness,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,0,'new','','in_scope',0,?,?)",
                    (case_id, case_id.lower(), analysis_id, analysis_id + '-R', target, 'Bind test', 'Bind test', 'broken_object_authorization', when, when),
                )
            base = {
                "target": target, "endpoint": endpoint, "resource_id": "TEST-3",
                "resource_owner_identity": "owner", "status_code": 200, "shape_hash": "shape",
                "controlled_capture": True, "test_owned": True, "reversible": True,
            }
            captures = (
                ("OBS-BIND-CONTROL", "CASE-BIND-A", "owner"),
                ("OBS-BIND-PROBE", "CASE-BIND-A", "peer"),
                ("OBS-BIND-OTHER", "CASE-BIND-B", "peer"),
            )
            for observation_id, case_id, identity in captures:
                db.execute(
                    "INSERT INTO imported_http_evidence(observation_id,case_id,target,source_type,source_file,observation_json,imported_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (observation_id, case_id, target, 'controlled_test_capture', observation_id + '.json', json.dumps({**base, 'identity_id': identity}), 'analyst', when),
                )
            contract = {
                "family": "broken_object_authorization", "target": target, "endpoint": endpoint,
                "expected_relation": "probe_must_be_rejected", "authorization_acknowledged": True,
                "test_owned": True, "reversible": True, "control_identity": "owner",
                "probe_identity": "peer", "resource_id": "TEST-3", "resource_owner_identity": "owner",
            }
            wrong_analysis = execute_stored_capture_comparison(
                db, analysis_id="BIND-A2", contract=contract,
                control_observation_id="OBS-BIND-CONTROL", probe_observation_id="OBS-BIND-PROBE",
            )
            self.assertEqual(wrong_analysis["status"], "blocked")
            self.assertIn("analysis_case_mismatch", wrong_analysis["blocking_reasons"])

            cross_case = execute_stored_capture_comparison(
                db, analysis_id="BIND-A1", contract=contract,
                control_observation_id="OBS-BIND-CONTROL", probe_observation_id="OBS-BIND-OTHER",
            )
            self.assertEqual(cross_case["status"], "blocked")
            self.assertIn("capture_case_mismatch", cross_case["blocking_reasons"])
            self.assertEqual(
                db.one("SELECT COUNT(*) AS count FROM differential_findings WHERE analysis_id IN ('BIND-A1','BIND-A2')")["count"],
                0,
            )
        finally:
            db.close(); temp.cleanup()


if __name__ == "__main__":
    unittest.main()
