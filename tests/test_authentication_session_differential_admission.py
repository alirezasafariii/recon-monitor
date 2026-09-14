from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from authentication_session_admission_bridge import apply_authentication_session_admission
from authentication_session_differential import review_authentication_session_artifact
from core import APP_VERSION, AppPaths, Database, ReconError, json_dumps, utc_now
from hypothesis_admission import record_hypothesis


RUN_ID = "RUN-AUTH-LIFECYCLE-1"
ANALYSIS_ID = "AN-AUTH-LIFECYCLE-1"
TARGET = "example.test"
ENDPOINT = "https://app.example.test/session/logout"


class AuthSessionLifecycleFixture:
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
            (ANALYSIS_ID, RUN_ID, TARGET, "auth-lifecycle-test", "auth-lifecycle-test", "analysis", "success", now, now, "{}"),
        )

    def close(self):
        self.db.close()

    def hypothesis(self, *, structural=True, blocking=False, variant="auth_lifecycle"):
        support = []
        if structural:
            support = [
                {
                    "type": "authentication_surface",
                    "source": "endpoint_schema",
                    "source_group": "auth_surface_fixture",
                    "weight": 18,
                    "text": "Controlled fixture identifies a session lifecycle surface.",
                },
                {
                    "type": "client_operation",
                    "source": "endpoint_contract",
                    "source_group": "auth_operation_fixture",
                    "weight": 12,
                    "text": "Controlled fixture identifies a concrete authentication/session operation.",
                },
            ]
        contradict = []
        if blocking:
            contradict.append(
                {
                    "type": "session_rotation_observed",
                    "source": "stored_control",
                    "source_group": "prior_session_rotation",
                    "weight": -28,
                    "text": "Prior stored target evidence records correct session rotation.",
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
            source_ref="fixture:auth-lifecycle",
            family="authentication_session",
            variant=variant,
            support=support,
            contradict=contradict,
            missing=["controlled lifecycle comparison"],
            rule_ids=["fixture-auth-lifecycle"],
            summary="Authentication/session lifecycle bridge fixture.",
        )

    def write_artifact(
        self,
        hypothesis_id: str,
        *,
        lifecycle_id="ASL-LOGOUT-1",
        transition_type="logout_invalidation",
        before_access=True,
        after_access=True,
        before_authenticated=True,
        after_authenticated=True,
        before_fingerprint="",
        after_fingerprint="",
        after_status=200,
        after_expired=False,
        expected_after_access=False,
        expected_after_authenticated=False,
        rotation_expected=False,
        expiration_expected=False,
        confounded=False,
    ):
        payload = {
            "version": "1.0.0",
            "lifecycle_id": lifecycle_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis_id,
            "transition_type": transition_type,
            "operation_fingerprint": "a" * 64,
            "before": {
                "controlled_test_session": True,
                "raw_secret_material_stored": False,
                "status_code": 200,
                "authenticated": before_authenticated,
                "access_granted": before_access,
                "expired": False,
                "session_fingerprint": before_fingerprint,
            },
            "after": {
                "controlled_test_session": True,
                "raw_secret_material_stored": False,
                "status_code": after_status,
                "authenticated": after_authenticated,
                "access_granted": after_access,
                "expired": after_expired,
                "session_fingerprint": after_fingerprint,
            },
            "expected_after_access_granted": expected_after_access,
            "expected_after_authenticated": expected_after_authenticated,
            "rotation_expected": rotation_expected,
            "expiration_expected": expiration_expected,
            "observed_at": utc_now(),
            "analyst_verified": True,
            "reviewed_by": "test-analyst",
            "controlled_test_session_only": True,
            "real_user_data_used": False,
            "raw_secret_material_stored": False,
            "raw_body_stored": False,
            "rate_limit_confounded": confounded,
            "challenge_confounded": False,
            "clock_confounded": False,
            "policy_ambiguous": False,
        }
        path = self.root / f"{lifecycle_id}.json"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        return path

    def review(self, hypothesis_id: str, **kwargs):
        return review_authentication_session_artifact(
            self.db,
            artifact_path=self.write_artifact(hypothesis_id, **kwargs),
            actor="test",
        )


class AuthenticationSessionDifferentialAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fx = AuthSessionLifecycleFixture(Path(self.temp.name))

    def tearDown(self):
        self.fx.close()
        self.temp.cleanup()

    def test_logout_reuse_review_can_create_potential_finding(self):
        hypothesis = self.fx.hypothesis()
        self.assertFalse(hypothesis["assessment"]["admitted"])
        review = self.fx.review(hypothesis["hypothesis_id"], lifecycle_id="ASL-LOGOUT-PROMOTE")
        self.assertEqual(review["signal_type"], "session_reuse_after_logout")
        self.assertEqual(review["polarity"], "support")
        self.assertFalse(review["affects_admission"])

        result = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-LOGOUT-PROMOTE", actor="test"
        )
        self.assertEqual(result["status"], "promoted")
        self.assertTrue(result["admitted"])
        self.assertTrue(result["candidate_id"])
        self.assertEqual(result["signal_type"], "session_reuse_after_logout")
        self.assertEqual(result["network_requests_executed"], 0)
        self.assertFalse(result["raw_secret_material_stored"])
        self.assertFalse(result["vulnerability_confirmed"])

        candidate = self.fx.db.one(
            "SELECT bug_family,candidate_state,analyst_decision FROM bug_candidates WHERE candidate_id=?",
            (result["candidate_id"],),
        )
        self.assertEqual(str(candidate["bug_family"]), "authentication_session")
        self.assertNotEqual(str(candidate["candidate_state"]), "confirmed_by_analyst")
        self.assertEqual(str(candidate["analyst_decision"]), "unreviewed")
        linked = self.fx.db.one(
            "SELECT relation FROM candidate_evidence_links WHERE candidate_id=? AND evidence_id=?",
            (result["candidate_id"], result["evidence_id"]),
        )
        self.assertEqual(str(linked["relation"]), "controlled_auth_session:session_reuse_after_logout")

    def test_required_rotation_failure_is_direct_but_correct_rotation_is_not_eligible(self):
        hypothesis = self.fx.hypothesis()
        failed = self.fx.review(
            hypothesis["hypothesis_id"],
            lifecycle_id="ASL-ROTATION-FAILED",
            transition_type="token_rotation",
            before_fingerprint="b" * 64,
            after_fingerprint="b" * 64,
            rotation_expected=True,
            expected_after_access=True,
            expected_after_authenticated=True,
        )
        self.assertEqual(failed["signal_type"], "token_not_rotated")
        promoted = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-ROTATION-FAILED", actor="test"
        )
        self.assertTrue(promoted["admitted"])
        self.assertTrue(promoted["candidate_id"])

        other = self.fx.hypothesis(variant="auth_lifecycle_rotation_safe")
        safe = self.fx.review(
            other["hypothesis_id"],
            lifecycle_id="ASL-ROTATION-SAFE",
            transition_type="token_rotation",
            before_fingerprint="c" * 64,
            after_fingerprint="d" * 64,
            rotation_expected=True,
            expected_after_access=True,
            expected_after_authenticated=True,
        )
        self.assertEqual(safe["signal_type"], "session_rotation_observed")
        self.assertEqual(safe["polarity"], "contradict")
        result = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-ROTATION-SAFE", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")
        self.assertFalse(result["admitted"])

    def test_expired_session_rejection_is_control_evidence_not_promotion(self):
        hypothesis = self.fx.hypothesis()
        review = self.fx.review(
            hypothesis["hypothesis_id"],
            lifecycle_id="ASL-EXPIRATION-SAFE",
            transition_type="expiration",
            after_access=False,
            after_authenticated=False,
            after_status=401,
            after_expired=True,
            expected_after_access=False,
            expected_after_authenticated=False,
            expiration_expected=True,
        )
        self.assertEqual(review["signal_type"], "expired_session_rejected")
        self.assertEqual(review["polarity"], "contradict")
        result = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-EXPIRATION-SAFE", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

    def test_unexpected_expired_access_maps_to_authentication_state_violation(self):
        hypothesis = self.fx.hypothesis()
        review = self.fx.review(
            hypothesis["hypothesis_id"],
            lifecycle_id="ASL-EXPIRATION-FAIL",
            transition_type="expiration",
            after_access=True,
            after_authenticated=True,
            after_status=200,
            after_expired=True,
            expected_after_access=False,
            expected_after_authenticated=False,
            expiration_expected=True,
        )
        self.assertEqual(review["signal_type"], "authentication_state_violation")
        result = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-EXPIRATION-FAIL", actor="test"
        )
        self.assertTrue(result["admitted"])
        self.assertTrue(result["candidate_id"])

    def test_review_and_bridge_are_exactly_once_and_mutation_fails_closed(self):
        hypothesis = self.fx.hypothesis()
        path = self.fx.write_artifact(hypothesis["hypothesis_id"], lifecycle_id="ASL-IDEMPOTENT")
        first_review = review_authentication_session_artifact(self.fx.db, artifact_path=path, actor="test")
        second_review = review_authentication_session_artifact(self.fx.db, artifact_path=path, actor="test")
        self.assertEqual(second_review["status"], "already_applied")
        self.assertEqual(first_review["evidence_id"], second_review["evidence_id"])

        first = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-IDEMPOTENT", actor="test"
        )
        second = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-IDEMPOTENT", actor="test"
        )
        self.assertEqual(second["status"], "already_applied")
        self.assertEqual(first["candidate_id"], second["candidate_id"])
        self.assertEqual(
            int(self.fx.db.one("SELECT COUNT(*) FROM authentication_session_admission_bridge_runs")[0]),
            1,
        )

        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["after"]["status_code"] = 204
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "changed"):
            review_authentication_session_artifact(self.fx.db, artifact_path=path, actor="test")

    def test_confounded_missing_structure_or_prior_blocking_control_fails_closed(self):
        hypothesis = self.fx.hypothesis()
        review = self.fx.review(
            hypothesis["hypothesis_id"],
            lifecycle_id="ASL-CONFOUNDED",
            confounded=True,
        )
        self.assertTrue(review["confounded"])
        result = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-CONFOUNDED", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")

        no_structure = self.fx.hypothesis(
            structural=False, variant="auth_lifecycle_no_structure"
        )
        self.fx.review(no_structure["hypothesis_id"], lifecycle_id="ASL-NO-STRUCTURE")
        result = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-NO-STRUCTURE", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")

        blocked = self.fx.hypothesis(
            blocking=True, variant="auth_lifecycle_blocked"
        )
        self.fx.review(blocked["hypothesis_id"], lifecycle_id="ASL-PRIOR-BLOCK")
        result = apply_authentication_session_admission(
            self.fx.db, lifecycle_id="ASL-PRIOR-BLOCK", actor="test"
        )
        self.assertEqual(result["status"], "not_eligible")
        self.assertEqual(result["reason"], "blocking_authentication_contradiction_present")

    def test_raw_secret_or_identity_fields_are_rejected(self):
        hypothesis = self.fx.hypothesis()
        path = self.fx.write_artifact(hypothesis["hypothesis_id"], lifecycle_id="ASL-RAW-SECRET")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["after"]["token"] = "must-not-be-stored"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "raw secret or identity material"):
            review_authentication_session_artifact(self.fx.db, artifact_path=path, actor="test")

    def test_sources_have_no_network_or_live_auth_surface(self):
        for relative in (
            "app/authentication_session_differential.py",
            "app/authentication_session_admission_bridge.py",
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
            ):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
