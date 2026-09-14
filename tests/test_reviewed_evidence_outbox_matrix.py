from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from authentication_session_differential import review_authentication_session_artifact
from controlled_identity_differential import review_controlled_identity_artifact
from core import APP_VERSION, AppPaths, Config, Database, Logger, json_dumps, utc_now
from finding_notification_outbox import deliver_finding_notification_outbox
from graphql_data_exposure_differential import review_graphql_data_exposure_artifact
from hypothesis_admission import record_hypothesis
from material_classification_review import review_material_classification_artifact
from reviewed_evidence_dispatcher import dispatch_reviewed_evidence


RUN_ID = "RUN-OUTBOX-MATRIX-1"
ANALYSIS_ID = "AN-OUTBOX-MATRIX-1"
TARGET = "example.test"


class ReviewedEvidenceOutboxMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.paths = AppPaths.from_root(self.root)
        self.paths.ensure()
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n', encoding="utf-8")
        self.config = Config(self.paths)
        self.db = Database(self.paths.db)
        self.logger = Logger(self.paths, verbose=False)
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)",
            (RUN_ID, APP_VERSION, "success", now, now, TARGET),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ANALYSIS_ID, RUN_ID, TARGET, "outbox-matrix", "outbox-matrix", "analysis", "success", now, now, "{}"),
        )

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _ctx(self):
        return SimpleNamespace(paths=self.paths, config=self.config, db=self.db, logger=self.logger)

    def _hypothesis(self, family: str, endpoint: str, support: list[dict], variant: str):
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="app.example.test",
            endpoint=endpoint,
            source_ref=f"fixture:outbox-matrix:{family}",
            family=family,
            variant=variant,
            support=support,
            contradict=[],
            missing=["controlled reviewed evidence"],
            rule_ids=[f"fixture-{family}"],
            summary=f"{family} outbox matrix fixture.",
        )

    def _write(self, name: str, payload: dict) -> Path:
        path = self.root / f"{name}.json"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        return path

    def _review_account(self) -> str:
        hypothesis = self._hypothesis(
            "account_enumeration",
            "https://app.example.test/recovery",
            [
                {"type": "identity_lookup", "source": "fixture", "source_group": "identity-input", "weight": 20, "text": "Controlled identity lookup input."},
                {"type": "client_operation", "source": "fixture", "source_group": "identity-operation", "weight": 12, "text": "Controlled recovery operation."},
            ],
            "identity_response_difference",
        )
        review_id = "CID-OUTBOX-MATRIX"
        payload = {
            "version": "1.0.0",
            "comparison_id": review_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis["hypothesis_id"],
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
        review_controlled_identity_artifact(
            self.db, artifact_path=self._write(review_id, payload), actor="test"
        )
        return review_id

    def _review_auth(self) -> str:
        hypothesis = self._hypothesis(
            "authentication_session",
            "https://app.example.test/session/logout",
            [
                {"type": "authentication_surface", "source": "fixture", "source_group": "auth-surface", "weight": 18, "text": "Controlled session surface."},
                {"type": "client_operation", "source": "fixture", "source_group": "auth-operation", "weight": 12, "text": "Controlled logout operation."},
            ],
            "auth_lifecycle",
        )
        review_id = "ASL-OUTBOX-MATRIX"
        payload = {
            "version": "1.0.0",
            "lifecycle_id": review_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis["hypothesis_id"],
            "transition_type": "logout_invalidation",
            "operation_fingerprint": "d" * 64,
            "before": {
                "controlled_test_session": True,
                "raw_secret_material_stored": False,
                "status_code": 200,
                "authenticated": True,
                "access_granted": True,
                "expired": False,
                "session_fingerprint": "",
            },
            "after": {
                "controlled_test_session": True,
                "raw_secret_material_stored": False,
                "status_code": 200,
                "authenticated": True,
                "access_granted": True,
                "expired": False,
                "session_fingerprint": "",
            },
            "expected_after_access_granted": False,
            "expected_after_authenticated": False,
            "rotation_expected": False,
            "expiration_expected": False,
            "observed_at": utc_now(),
            "analyst_verified": True,
            "reviewed_by": "test-analyst",
            "controlled_test_session_only": True,
            "real_user_data_used": False,
            "raw_secret_material_stored": False,
            "raw_body_stored": False,
            "rate_limit_confounded": False,
            "challenge_confounded": False,
            "clock_confounded": False,
            "policy_ambiguous": False,
        }
        review_authentication_session_artifact(
            self.db, artifact_path=self._write(review_id, payload), actor="test"
        )
        return review_id

    def _review_graphql(self) -> str:
        hypothesis = self._hypothesis(
            "graphql_data_exposure",
            "https://app.example.test/graphql",
            [
                {"type": "sensitive_fields", "source": "fixture", "source_group": "graphql-fields", "weight": 20, "text": "Sensitive field metadata."},
                {"type": "client_operation", "source": "fixture", "source_group": "graphql-operation", "weight": 14, "text": "Client GraphQL operation."},
                {"type": "field_policy_context", "source": "fixture", "source_group": "graphql-policy", "weight": 15, "text": "Documented field policy."},
            ],
            "sensitive_fields_with_policy_context",
        )
        review_id = "GQLD-OUTBOX-MATRIX"
        payload = {
            "version": "1.0.0",
            "comparison_id": review_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis["hypothesis_id"],
            "comparison_mode": "single_role_policy",
            "operation_name": "ViewerProfile",
            "operation_fingerprint": "e" * 64,
            "policy_source_fingerprint": "f" * 64,
            "policy_documented": True,
            "restricted_fields": ["ssn"],
            "tested_role": {
                "role_class": "restricted_test_role",
                "controlled_test_role": True,
                "observed_fields": ["id", "ssn"],
                "raw_field_values_stored": False,
                "raw_body_stored": False,
            },
            "reference_role_authorized_for_restricted_fields": False,
            "field_authorization_observed": False,
            "observed_at": utc_now(),
            "analyst_verified": True,
            "reviewed_by": "test-analyst",
            "controlled_test_roles_only": True,
            "real_user_data_used": False,
            "raw_field_values_stored": False,
            "raw_body_stored": False,
            "policy_ambiguous": False,
            "role_context_ambiguous": False,
            "partial_response_confounded": False,
            "graphql_error_confounded": False,
            "cache_confounded": False,
        }
        review_graphql_data_exposure_artifact(
            self.db, artifact_path=self._write(review_id, payload), actor="test"
        )
        return review_id

    def _review_material(self) -> str:
        hypothesis = self._hypothesis(
            "secret_exposure",
            "https://app.example.test/assets/app.js",
            [
                {"type": "secret_pattern", "source": "fixture", "source_group": "material-pattern", "weight": 20, "text": "Redacted material-shaped indicator."},
                {"type": "context", "source": "fixture", "source_group": "material-context", "weight": 18, "text": "Client-delivered source context."},
            ],
            "material_surface",
        )
        review_id = "MCR-OUTBOX-MATRIX"
        payload = {
            "version": "1.0.0",
            "review_id": review_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis["hypothesis_id"],
            "material_class": "structured_key_material",
            "classification": "confirmed_structure",
            "classification_fingerprint": "1" * 64,
            "source_artifact_fingerprint": "2" * 64,
            "client_delivered_context": True,
            "analyst_verified": True,
            "redacted": True,
            "observed_at": utc_now(),
            "reviewed_by": "test-analyst",
            "classification_ambiguous": False,
            "source_context_ambiguous": False,
            "provider_validation_performed": False,
            "network_request_performed": False,
        }
        review_material_classification_artifact(
            self.db, artifact_path=self._write(review_id, payload), actor="test"
        )
        return review_id

    @staticmethod
    def _success_transport(config, logger, message: str):
        return {"delivered": True, "channel": "fixture", "channels": ["fixture"], "error": ""}

    def test_all_four_review_families_queue_and_deliver_through_one_outbox(self) -> None:
        review_ids = [
            self._review_account(),
            self._review_auth(),
            self._review_graphql(),
            self._review_material(),
        ]
        expected_families = {
            "account_enumeration",
            "authentication_session",
            "graphql_data_exposure",
            "secret_exposure",
        }
        candidate_ids = []
        for review_id in review_ids:
            result = dispatch_reviewed_evidence(self._ctx(), review_id=review_id, actor="test")
            self.assertTrue(result["candidate_id"])
            self.assertTrue(result["notification_delivery_deferred_to_outbox_worker"])
            self.assertEqual(str(result["notification_events"][0]["status"]), "queued")
            self.assertEqual(str(result["notification_events"][0]["outbox_status"]), "queued")
            candidate_ids.append(result["candidate_id"])

        self.assertEqual(int(self.db.one("SELECT COUNT(*) AS n FROM notification_events WHERE event_type='potential_finding'")["n"]), 4)
        self.assertEqual(int(self.db.one("SELECT COUNT(*) AS n FROM finding_notification_outbox WHERE status='queued'")["n"]), 4)
        self.assertEqual(int(self.db.one("SELECT COUNT(*) AS n FROM notification_deliveries")["n"]), 0)

        worker = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            target=TARGET,
            transport=self._success_transport,
            now="2099-01-01T00:00:00Z",
        )
        self.assertEqual(worker["delivered"], 4)
        self.assertEqual(int(self.db.one("SELECT COUNT(*) AS n FROM finding_notification_outbox WHERE status='delivered'")["n"]), 4)
        self.assertEqual(int(self.db.one("SELECT COUNT(*) AS n FROM notification_deliveries WHERE status='delivered'")["n"]), 4)
        rows = self.db.all(
            "SELECT bug_family FROM bug_candidates WHERE candidate_id IN (?,?,?,?)",
            tuple(candidate_ids),
        )
        self.assertEqual({str(row["bug_family"]) for row in rows}, expected_families)

        replay = deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            target=TARGET,
            transport=self._success_transport,
            now="2099-01-01T01:00:00Z",
        )
        self.assertEqual(replay["due"], 0)
        self.assertEqual(int(self.db.one("SELECT COUNT(*) AS n FROM notification_deliveries WHERE status='delivered'")["n"]), 4)


if __name__ == "__main__":
    unittest.main()
