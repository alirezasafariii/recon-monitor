from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, AppPaths, Database, ReconError, json_dumps, utc_now
from graphql_data_exposure_admission_bridge import apply_graphql_data_exposure_admission
from graphql_data_exposure_differential import review_graphql_data_exposure_artifact
from hypothesis_admission import record_hypothesis


RUN_ID = "RUN-GQL-DATA-1"
ANALYSIS_ID = "AN-GQL-DATA-1"
TARGET = "example.test"
ENDPOINT = "https://app.example.test/graphql"


class GraphqlDataExposureFixture:
    def __init__(self, root: Path):
        self.root = root
        self.paths = AppPaths.from_root(root)
        self.paths.ensure()
        self.db = Database(self.paths.db)
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)",
            (RUN_ID, APP_VERSION, "success", now, now, TARGET),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ANALYSIS_ID, RUN_ID, TARGET, "graphql-data-test", "graphql-data-test", "analysis", "success", now, now, "{}"),
        )

    def close(self):
        self.db.close()

    def hypothesis(self, *, tag="base", structural=True, policy=True, blocking=False):
        support = []
        if structural:
            support.extend(
                [
                    {
                        "type": "sensitive_fields",
                        "source": "graphql_intelligence",
                        "source_group": f"graphql_static:{tag}",
                        "weight": 20,
                        "text": "Controlled fixture identifies potentially sensitive GraphQL field names.",
                    },
                    {
                        "type": "client_operation",
                        "source": "graphql_intelligence",
                        "source_group": f"graphql_static:{tag}",
                        "weight": 14,
                        "text": "Controlled fixture identifies a client-visible GraphQL query operation.",
                    },
                ]
            )
        if policy:
            support.append(
                {
                    "type": "field_policy_context",
                    "source": "stored_security_policy",
                    "source_group": f"graphql_policy:{tag}",
                    "weight": 15,
                    "text": "Controlled fixture records a documented role-specific field policy.",
                }
            )
        contradict = []
        if blocking:
            contradict.append(
                {
                    "type": "field_authorization_observed",
                    "source": "stored_control",
                    "source_group": f"graphql_control:{tag}",
                    "weight": -36,
                    "text": "Prior controlled evidence records field-level authorization enforcement.",
                }
            )
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="app.example.test",
            endpoint=f"{ENDPOINT}/{tag}",
            source_ref=f"fixture:graphql-data:{tag}",
            family="graphql_data_exposure",
            variant="sensitive_fields_with_policy_context",
            support=support,
            contradict=contradict,
            missing=["controlled field-policy response comparison"],
            rule_ids=["fixture-graphql-data"],
            summary="GraphQL data-exposure bridge fixture.",
        )

    def write_artifact(
        self,
        hypothesis_id: str,
        *,
        comparison_id="GQLD-SINGLE-1",
        comparison_mode="single_role_policy",
        tested_fields=None,
        restricted_fields=None,
        reference_fields=None,
        reference_authorized=False,
        authorization_observed=False,
        confounded=False,
    ):
        tested_fields = ["id", "ssn"] if tested_fields is None else list(tested_fields)
        restricted_fields = ["ssn"] if restricted_fields is None else list(restricted_fields)
        payload = {
            "version": "1.0.0",
            "comparison_id": comparison_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis_id,
            "comparison_mode": comparison_mode,
            "operation_name": "ViewerProfile",
            "operation_fingerprint": "a" * 64,
            "policy_source_fingerprint": "b" * 64,
            "policy_documented": True,
            "restricted_fields": restricted_fields,
            "tested_role": {
                "role_class": "restricted_test_role",
                "controlled_test_role": True,
                "observed_fields": tested_fields,
                "raw_field_values_stored": False,
                "raw_body_stored": False,
            },
            "reference_role_authorized_for_restricted_fields": reference_authorized,
            "field_authorization_observed": authorization_observed,
            "observed_at": utc_now(),
            "analyst_verified": True,
            "reviewed_by": "test-analyst",
            "controlled_test_roles_only": True,
            "real_user_data_used": False,
            "raw_field_values_stored": False,
            "raw_body_stored": False,
            "policy_ambiguous": confounded,
            "role_context_ambiguous": False,
            "partial_response_confounded": False,
            "graphql_error_confounded": False,
            "cache_confounded": False,
        }
        if comparison_mode == "role_differential":
            payload["reference_role"] = {
                "role_class": "authorized_test_role",
                "controlled_test_role": True,
                "observed_fields": list(reference_fields or ["id", "ssn"]),
                "raw_field_values_stored": False,
                "raw_body_stored": False,
            }
        path = self.root / f"{comparison_id}.json"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        return path

    def review(self, hypothesis_id: str, **kwargs):
        return review_graphql_data_exposure_artifact(
            self.db,
            artifact_path=self.write_artifact(hypothesis_id, **kwargs),
            actor="test",
        )


class GraphqlDataExposureDifferentialAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fx = GraphqlDataExposureFixture(Path(self.temp.name))

    def tearDown(self):
        self.fx.close()
        self.temp.cleanup()

    def test_restricted_field_returned_can_create_potential_finding(self):
        hypothesis = self.fx.hypothesis(tag="single")
        self.assertTrue(hypothesis["assessment"]["admitted"])
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)
        review = self.fx.review(
            hypothesis["hypothesis_id"], comparison_id="GQLD-SINGLE-PROMOTE"
        )
        self.assertEqual(review["signal_type"], "sensitive_graphql_response_observed")
        self.assertEqual(review["polarity"], "support")
        self.assertFalse(review["affects_admission"])

        result = apply_graphql_data_exposure_admission(
            self.fx.db, comparison_id="GQLD-SINGLE-PROMOTE", actor="test"
        )
        self.assertEqual(result["status"], "promoted")
        self.assertTrue(result["admitted"])
        self.assertTrue(result["candidate_id"])
        self.assertEqual(result["network_requests_executed"], 0)
        self.assertFalse(result["raw_field_values_stored"])
        self.assertFalse(result["vulnerability_confirmed"])

        candidate = self.fx.db.one(
            "SELECT bug_family,candidate_state,analyst_decision FROM bug_candidates WHERE candidate_id=?",
            (result["candidate_id"],),
        )
        self.assertEqual(str(candidate["bug_family"]), "graphql_data_exposure")
        self.assertNotEqual(str(candidate["candidate_state"]), "confirmed_by_analyst")
        self.assertEqual(str(candidate["analyst_decision"]), "unreviewed")
        linked = self.fx.db.one(
            "SELECT relation FROM candidate_evidence_links WHERE candidate_id=? AND evidence_id=?",
            (result["candidate_id"], result["evidence_id"]),
        )
        self.assertEqual(
            str(linked["relation"]),
            "controlled_graphql:sensitive_graphql_response_observed",
        )

    def test_role_differential_can_create_potential_finding(self):
        hypothesis = self.fx.hypothesis(tag="role-diff")
        review = self.fx.review(
            hypothesis["hypothesis_id"],
            comparison_id="GQLD-ROLE-DIFF",
            comparison_mode="role_differential",
            tested_fields=["id", "ssn"],
            reference_fields=["id", "ssn"],
            reference_authorized=True,
        )
        self.assertEqual(review["signal_type"], "field_authorization_differential")
        result = apply_graphql_data_exposure_admission(
            self.fx.db, comparison_id="GQLD-ROLE-DIFF", actor="test"
        )
        self.assertTrue(result["admitted"])
        self.assertTrue(result["candidate_id"])
        self.assertEqual(result["signal_type"], "field_authorization_differential")

    def test_safe_omission_or_authorization_control_does_not_promote(self):
        hypothesis = self.fx.hypothesis(tag="safe-omission")
        review = self.fx.review(
            hypothesis["hypothesis_id"],
            comparison_id="GQLD-SAFE-OMISSION",
            tested_fields=["id", "displayName"],
            restricted_fields=["ssn"],
        )
        self.assertEqual(review["signal_type"], "sensitive_fields_not_returned")
        self.assertEqual(review["polarity"], "contradict")
        result = apply_graphql_data_exposure_admission(
            self.fx.db, comparison_id="GQLD-SAFE-OMISSION", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")
        self.assertFalse(result["admitted"])

        controlled = self.fx.hypothesis(tag="auth-control")
        review = self.fx.review(
            controlled["hypothesis_id"],
            comparison_id="GQLD-AUTH-CONTROL",
            tested_fields=["id"],
            restricted_fields=["ssn"],
            authorization_observed=True,
        )
        self.assertEqual(review["signal_type"], "field_authorization_observed")
        result = apply_graphql_data_exposure_admission(
            self.fx.db, comparison_id="GQLD-AUTH-CONTROL", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")

    def test_confounded_or_missing_policy_context_fails_closed(self):
        hypothesis = self.fx.hypothesis(tag="confounded")
        review = self.fx.review(
            hypothesis["hypothesis_id"],
            comparison_id="GQLD-CONFOUNDED",
            confounded=True,
        )
        self.assertTrue(review["confounded"])
        self.assertEqual(review["signal_type"], "")
        result = apply_graphql_data_exposure_admission(
            self.fx.db, comparison_id="GQLD-CONFOUNDED", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")

        no_policy = self.fx.hypothesis(tag="no-policy", policy=False)
        self.fx.review(no_policy["hypothesis_id"], comparison_id="GQLD-NO-POLICY")
        result = apply_graphql_data_exposure_admission(
            self.fx.db, comparison_id="GQLD-NO-POLICY", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")
        self.assertEqual(result["reason"], "missing_documented_field_policy_context")

    def test_prior_blocking_control_prevents_bridge(self):
        hypothesis = self.fx.hypothesis(tag="blocked", blocking=True)
        self.fx.review(hypothesis["hypothesis_id"], comparison_id="GQLD-BLOCKED")
        result = apply_graphql_data_exposure_admission(
            self.fx.db, comparison_id="GQLD-BLOCKED", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")
        self.assertEqual(result["reason"], "blocking_graphql_field_control_present")
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

    def test_review_and_bridge_are_exactly_once_and_mutation_fails_closed(self):
        hypothesis = self.fx.hypothesis(tag="idempotent")
        path = self.fx.write_artifact(
            hypothesis["hypothesis_id"], comparison_id="GQLD-IDEMPOTENT"
        )
        first_review = review_graphql_data_exposure_artifact(
            self.fx.db, artifact_path=path, actor="test"
        )
        second_review = review_graphql_data_exposure_artifact(
            self.fx.db, artifact_path=path, actor="test"
        )
        self.assertEqual(second_review["status"], "already_applied")
        self.assertEqual(first_review["evidence_id"], second_review["evidence_id"])

        first = apply_graphql_data_exposure_admission(
            self.fx.db, comparison_id="GQLD-IDEMPOTENT", actor="test"
        )
        second = apply_graphql_data_exposure_admission(
            self.fx.db, comparison_id="GQLD-IDEMPOTENT", actor="test"
        )
        self.assertEqual(second["status"], "already_applied")
        self.assertEqual(first["candidate_id"], second["candidate_id"])
        self.assertEqual(
            int(self.fx.db.one("SELECT COUNT(*) FROM graphql_data_exposure_admission_bridge_runs")[0]),
            1,
        )

        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["tested_role"]["observed_fields"].append("billingPlan")
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "changed"):
            review_graphql_data_exposure_artifact(self.fx.db, artifact_path=path, actor="test")

    def test_raw_field_values_are_rejected(self):
        hypothesis = self.fx.hypothesis(tag="raw-values")
        path = self.fx.write_artifact(
            hypothesis["hypothesis_id"], comparison_id="GQLD-RAW-VALUES"
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["tested_role"]["field_values"] = {"ssn": "must-not-be-stored"}
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "raw values or secret material"):
            review_graphql_data_exposure_artifact(self.fx.db, artifact_path=path, actor="test")

    def test_sources_have_no_network_or_live_graphql_surface(self):
        for relative in (
            "app/graphql_data_exposure_differential.py",
            "app/graphql_data_exposure_admission_bridge.py",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            for forbidden in (
                "urllib.request",
                "requests.",
                "socket.",
                "urlopen(",
                "_perform_request(",
                "http.client",
                "aiohttp",
                "subprocess",
                "introspectionquery",
            ):
                self.assertNotIn(forbidden, source.lower())


if __name__ == "__main__":
    unittest.main()
