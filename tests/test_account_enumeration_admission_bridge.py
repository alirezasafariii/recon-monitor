from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from account_enumeration_admission_bridge import apply_account_enumeration_admission
from controlled_identity_differential import review_controlled_identity_artifact
from core import APP_VERSION, AppPaths, Database, json_dumps, utc_now
from hypothesis_admission import record_hypothesis


RUN_ID = "RUN-ENUM-BRIDGE-1"
ANALYSIS_ID = "AN-ENUM-BRIDGE-1"
TARGET = "example.test"
ENDPOINT = "https://app.example.test/recovery"


class AccountEnumerationBridgeFixture:
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
            (ANALYSIS_ID, RUN_ID, TARGET, "enum-bridge-test", "enum-bridge-test", "analysis", "success", now, now, "{}"),
        )

    def close(self):
        self.db.close()

    def hypothesis(self, *, family="account_enumeration", structural=True, blocking=False):
        support = []
        if structural:
            support = [
                {
                    "type": "identity_lookup",
                    "source": "endpoint_schema",
                    "source_group": "identity_input",
                    "weight": 20,
                    "text": "Controlled fixture identifies an identity lookup input.",
                },
                {
                    "type": "client_operation",
                    "source": "endpoint_contract",
                    "source_group": "identity_operation",
                    "weight": 12,
                    "text": "Controlled fixture identifies an account recovery operation.",
                },
            ]
        contradict = []
        if blocking:
            contradict.append(
                {
                    "type": "uniform_identity_response",
                    "source": "stored_comparison",
                    "source_group": "identity_response_previous",
                    "weight": -30,
                    "text": "Previous stored comparison observed a uniform response.",
                }
            )
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="app.example.test",
            endpoint=ENDPOINT,
            source_ref="fixture:account-enumeration",
            family=family,
            variant="identity_response_difference",
            support=support,
            contradict=contradict,
            missing=["controlled response differential"],
            rule_ids=["fixture-account-enumeration"],
            summary="Account Enumeration bridge fixture.",
        )

    def write_artifact(self, hypothesis_id: str, *, comparison_id="CID-ENUM-BRIDGE-1", uniform=False, confounded=False):
        existing_class = "accepted_test_state"
        absent_class = existing_class if uniform else "generic_test_failure"
        existing_shape = "b" * 64
        absent_shape = existing_shape if uniform else "c" * 64
        payload = {
            "version": "1.0.0",
            "comparison_id": comparison_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis_id,
            "operation_fingerprint": "a" * 64,
            "existing_test_identity": {
                "identity_class": "owned_test_existing",
                "controlled_identity": True,
                "identity_value_stored": False,
                "status_code": 200,
                "response_class": existing_class,
                "shape_hash": existing_shape,
            },
            "absent_test_identity": {
                "identity_class": "synthetic_test_absent",
                "controlled_identity": True,
                "identity_value_stored": False,
                "status_code": 200,
                "response_class": absent_class,
                "shape_hash": absent_shape,
            },
            "observed_at": utc_now(),
            "analyst_verified": True,
            "reviewed_by": "test-analyst",
            "controlled_identities_only": True,
            "real_user_data_used": False,
            "identity_values_stored": False,
            "raw_body_stored": False,
            "rate_limit_confounded": confounded,
            "challenge_confounded": False,
        }
        path = self.root / f"{comparison_id}.json"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        return path

    def review(self, hypothesis_id: str, *, comparison_id="CID-ENUM-BRIDGE-1", uniform=False, confounded=False):
        return review_controlled_identity_artifact(
            self.db,
            artifact_path=self.write_artifact(
                hypothesis_id,
                comparison_id=comparison_id,
                uniform=uniform,
                confounded=confounded,
            ),
            actor="test",
        )


class AccountEnumerationAdmissionBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fx = AccountEnumerationBridgeFixture(Path(self.temp.name))

    def tearDown(self):
        self.fx.close()
        self.temp.cleanup()

    def test_reviewed_controlled_difference_can_create_potential_finding(self):
        hypothesis = self.fx.hypothesis()
        self.assertFalse(hypothesis["assessment"]["admitted"])
        review = self.fx.review(hypothesis["hypothesis_id"])
        self.assertEqual(review["status"], "reviewed")
        self.assertTrue(review["material_response_difference"])

        result = apply_account_enumeration_admission(
            self.fx.db,
            comparison_id="CID-ENUM-BRIDGE-1",
            actor="test",
        )

        self.assertEqual(result["status"], "promoted")
        self.assertTrue(result["admitted"])
        self.assertTrue(result["candidate_id"])
        self.assertEqual(result["network_requests_executed"], 0)
        self.assertFalse(result["real_user_data_used"])
        self.assertFalse(result["identity_values_stored"])
        self.assertFalse(result["vulnerability_confirmed"])

        candidate = self.fx.db.one(
            "SELECT bug_family,candidate_state,analyst_decision FROM bug_candidates WHERE candidate_id=?",
            (result["candidate_id"],),
        )
        self.assertEqual(str(candidate["bug_family"]), "account_enumeration")
        self.assertNotEqual(str(candidate["candidate_state"]), "confirmed_by_analyst")
        self.assertEqual(str(candidate["analyst_decision"]), "unreviewed")
        linked = self.fx.db.one(
            "SELECT relation FROM candidate_evidence_links WHERE candidate_id=? AND evidence_id=?",
            (result["candidate_id"], result["evidence_id"]),
        )
        self.assertEqual(str(linked["relation"]), "controlled_identity_response_differential")

    def test_bridge_is_exactly_once(self):
        hypothesis = self.fx.hypothesis()
        self.fx.review(hypothesis["hypothesis_id"], comparison_id="CID-ENUM-IDEMPOTENT")
        first = apply_account_enumeration_admission(
            self.fx.db, comparison_id="CID-ENUM-IDEMPOTENT", actor="test"
        )
        second = apply_account_enumeration_admission(
            self.fx.db, comparison_id="CID-ENUM-IDEMPOTENT", actor="test"
        )
        self.assertEqual(second["status"], "already_applied")
        self.assertEqual(first["candidate_id"], second["candidate_id"])
        self.assertEqual(
            int(self.fx.db.one("SELECT COUNT(*) FROM account_enumeration_admission_bridge_runs")[0]),
            1,
        )
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 1)

    def test_uniform_or_confounded_review_is_not_eligible(self):
        hypothesis = self.fx.hypothesis()
        self.fx.review(
            hypothesis["hypothesis_id"],
            comparison_id="CID-ENUM-UNIFORM",
            uniform=True,
        )
        uniform = apply_account_enumeration_admission(
            self.fx.db, comparison_id="CID-ENUM-UNIFORM", actor="test"
        )
        self.assertEqual(uniform["status"], "not_eligible")
        self.assertFalse(uniform["admitted"])

        self.fx.review(
            hypothesis["hypothesis_id"],
            comparison_id="CID-ENUM-CONFOUNDED",
            confounded=True,
        )
        confounded = apply_account_enumeration_admission(
            self.fx.db, comparison_id="CID-ENUM-CONFOUNDED", actor="test"
        )
        self.assertEqual(confounded["status"], "not_eligible")
        self.assertFalse(confounded["admitted"])
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

    def test_wrong_family_or_missing_structural_context_fails_closed(self):
        wrong_family = self.fx.hypothesis(family="authentication_session")
        self.fx.review(wrong_family["hypothesis_id"], comparison_id="CID-ENUM-WRONG-FAMILY")
        result = apply_account_enumeration_admission(
            self.fx.db, comparison_id="CID-ENUM-WRONG-FAMILY", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")
        self.assertEqual(result["reason"], "hypothesis_family_mismatch")

        incomplete = self.fx.hypothesis(structural=False)
        self.fx.review(incomplete["hypothesis_id"], comparison_id="CID-ENUM-NO-STRUCTURE")
        result = apply_account_enumeration_admission(
            self.fx.db, comparison_id="CID-ENUM-NO-STRUCTURE", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")
        self.assertFalse(result["admitted"])
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

    def test_prior_blocking_contradiction_prevents_bridge(self):
        hypothesis = self.fx.hypothesis(blocking=True)
        self.fx.review(hypothesis["hypothesis_id"], comparison_id="CID-ENUM-BLOCKED")
        result = apply_account_enumeration_admission(
            self.fx.db, comparison_id="CID-ENUM-BLOCKED", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")
        self.assertEqual(result["reason"], "blocking_identity_contradiction_present")
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

    def test_bridge_source_has_no_network_transport(self):
        source = (ROOT / "app" / "account_enumeration_admission_bridge.py").read_text(encoding="utf-8")
        for forbidden in (
            "urllib.request", "requests.", "socket.", "urlopen(", "_perform_request(",
            "http.client", "aiohttp", "subprocess",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
