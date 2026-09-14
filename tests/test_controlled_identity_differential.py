from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from controlled_identity_differential import review_controlled_identity_artifact
from core import APP_VERSION, AppPaths, Database, ReconError, json_dumps, utc_now
from hypothesis_admission import record_hypothesis


RUN_ID = "RUN-CONTROLLED-IDENTITY-1"
ANALYSIS_ID = "AN-CONTROLLED-IDENTITY-1"
TARGET = "example.test"


class ControlledIdentityFixture:
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
            (ANALYSIS_ID, RUN_ID, TARGET, "controlled-id-test", "controlled-id-test", "analysis", "success", now, now, "{}"),
        )

    def close(self):
        self.db.close()

    def hypothesis(self):
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="app.example.test",
            endpoint="https://app.example.test/recovery",
            source_ref="fixture:controlled-identity",
            family="authentication_session",
            variant="identity_surface_review",
            support=[
                {
                    "type": "authentication_surface",
                    "source": "fixture",
                    "source_group": "stored:identity-surface",
                    "weight": 10,
                    "text": "Stored fixture identifies an authentication surface.",
                }
            ],
            contradict=[],
            missing=["behavioral_validation_needed"],
            rule_ids=["fixture-controlled-identity"],
            summary="Controlled identity review fixture.",
        )

    def write_artifact(self, hypothesis_id: str, *, comparison_id="CID-TEST-1", **updates):
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
                "response_class": "accepted_test_state",
                "shape_hash": "b" * 64,
            },
            "absent_test_identity": {
                "identity_class": "synthetic_test_absent",
                "controlled_identity": True,
                "identity_value_stored": False,
                "status_code": 200,
                "response_class": "generic_test_failure",
                "shape_hash": "c" * 64,
            },
            "observed_at": utc_now(),
            "analyst_verified": True,
            "reviewed_by": "test-analyst",
            "controlled_identities_only": True,
            "real_user_data_used": False,
            "identity_values_stored": False,
            "raw_body_stored": False,
            "rate_limit_confounded": False,
            "challenge_confounded": False,
        }
        payload.update(updates)
        path = self.root / f"{comparison_id}.json"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        return path


class ControlledIdentityDifferentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fx = ControlledIdentityFixture(Path(self.temp.name))

    def tearDown(self):
        self.fx.close()
        self.temp.cleanup()

    def test_material_controlled_difference_is_review_evidence_only(self):
        hypothesis = self.fx.hypothesis()
        before = self.fx.db.one(
            "SELECT supporting_evidence_json,admission_json,promoted_candidate_id FROM analysis_hypotheses WHERE hypothesis_id=?",
            (hypothesis["hypothesis_id"],),
        )
        path = self.fx.write_artifact(hypothesis["hypothesis_id"])

        result = review_controlled_identity_artifact(self.fx.db, artifact_path=path, actor="test")

        self.assertEqual(result["status"], "reviewed")
        self.assertTrue(result["material_response_difference"])
        self.assertFalse(result["confounded"])
        self.assertFalse(result["affects_admission"])
        self.assertFalse(result["affects_candidate_promotion"])
        self.assertEqual(result["network_requests_executed"], 0)
        self.assertFalse(result["identity_values_stored"])
        self.assertFalse(result["vulnerability_confirmed"])

        evidence = self.fx.db.one(
            "SELECT evidence_type,polarity,source_kind,directness FROM evidence_records WHERE evidence_id=?",
            (result["evidence_id"],),
        )
        self.assertEqual(str(evidence["evidence_type"]), "controlled_identity_response_difference")
        self.assertEqual(str(evidence["polarity"]), "support")
        self.assertEqual(str(evidence["source_kind"]), "analyst_verified_controlled_identity")
        self.assertEqual(str(evidence["directness"]), "direct")

        after = self.fx.db.one(
            "SELECT supporting_evidence_json,admission_json,promoted_candidate_id FROM analysis_hypotheses WHERE hypothesis_id=?",
            (hypothesis["hypothesis_id"],),
        )
        self.assertEqual(str(before["supporting_evidence_json"]), str(after["supporting_evidence_json"]))
        self.assertEqual(str(before["admission_json"]), str(after["admission_json"]))
        self.assertEqual(str(before["promoted_candidate_id"] or ""), str(after["promoted_candidate_id"] or ""))
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

    def test_review_is_idempotent_and_mutation_fails_closed(self):
        hypothesis = self.fx.hypothesis()
        path = self.fx.write_artifact(hypothesis["hypothesis_id"], comparison_id="CID-IDEMPOTENT")
        first = review_controlled_identity_artifact(self.fx.db, artifact_path=path, actor="test")
        second = review_controlled_identity_artifact(self.fx.db, artifact_path=path, actor="test")
        self.assertEqual(second["status"], "already_applied")
        self.assertEqual(first["evidence_id"], second["evidence_id"])

        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["absent_test_identity"]["response_class"] = "different_test_failure"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "changed"):
            review_controlled_identity_artifact(self.fx.db, artifact_path=path, actor="test")

    def test_real_user_or_stored_identity_values_are_rejected(self):
        hypothesis = self.fx.hypothesis()
        real_user = self.fx.write_artifact(
            hypothesis["hypothesis_id"],
            comparison_id="CID-REAL-USER",
            real_user_data_used=True,
        )
        with self.assertRaisesRegex(ReconError, "real-user"):
            review_controlled_identity_artifact(self.fx.db, artifact_path=real_user, actor="test")

        path = self.fx.write_artifact(hypothesis["hypothesis_id"], comparison_id="CID-STORED-ID")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["existing_test_identity"]["email"] = "redacted@example.invalid"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "must not store identity values"):
            review_controlled_identity_artifact(self.fx.db, artifact_path=path, actor="test")

    def test_confounded_or_uniform_comparison_cannot_be_direct_support(self):
        hypothesis = self.fx.hypothesis()
        confounded = self.fx.write_artifact(
            hypothesis["hypothesis_id"],
            comparison_id="CID-CONFOUNDED",
            rate_limit_confounded=True,
        )
        result = review_controlled_identity_artifact(self.fx.db, artifact_path=confounded, actor="test")
        self.assertTrue(result["confounded"])
        evidence = self.fx.db.one(
            "SELECT polarity,directness FROM evidence_records WHERE evidence_id=?",
            (result["evidence_id"],),
        )
        self.assertEqual(str(evidence["polarity"]), "contradict")
        self.assertEqual(str(evidence["directness"]), "contextual")

        uniform = self.fx.write_artifact(hypothesis["hypothesis_id"], comparison_id="CID-UNIFORM")
        payload = json.loads(uniform.read_text(encoding="utf-8"))
        payload["absent_test_identity"]["response_class"] = payload["existing_test_identity"]["response_class"]
        payload["absent_test_identity"]["shape_hash"] = payload["existing_test_identity"]["shape_hash"]
        uniform.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        result = review_controlled_identity_artifact(self.fx.db, artifact_path=uniform, actor="test")
        self.assertFalse(result["material_response_difference"])
        evidence = self.fx.db.one(
            "SELECT polarity,directness FROM evidence_records WHERE evidence_id=?",
            (result["evidence_id"],),
        )
        self.assertEqual(str(evidence["polarity"]), "contradict")
        self.assertEqual(str(evidence["directness"]), "contextual")

    def test_source_has_no_network_or_admission_mutation_surface(self):
        source = (ROOT / "app" / "controlled_identity_differential.py").read_text(encoding="utf-8")
        for forbidden in (
            "urllib.request", "requests.", "socket.", "urlopen(", "_perform_request(",
            "record_hypothesis(", "mark_promoted(", "INSERT INTO bug_candidates", "UPDATE bug_candidates",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
