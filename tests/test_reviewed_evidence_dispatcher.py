from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import APP_VERSION, AppPaths, Config, Database, Logger, ReconError, json_dumps, utc_now
from finding_notification_outbox import deliver_finding_notification_outbox
from graphql_data_exposure_differential import review_graphql_data_exposure_artifact
from hypothesis_admission import record_hypothesis
from material_classification_review import review_material_classification_artifact
from reviewed_evidence_dispatcher import dispatch_reviewed_evidence


RUN_ID = "RUN-DISPATCH-1"
ANALYSIS_ID = "AN-DISPATCH-1"
TARGET = "example.test"


class DispatcherFixture:
    def __init__(self, root: Path):
        self.root = root
        self.paths = AppPaths.from_root(root)
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
            (ANALYSIS_ID, RUN_ID, TARGET, "dispatcher-test", "dispatcher-test", "analysis", "success", now, now, "{}"),
        )

    def close(self) -> None:
        self.db.close()

    def ctx(self):
        return SimpleNamespace(paths=self.paths, config=self.config, db=self.db, logger=self.logger)

    @staticmethod
    def success_transport(config, logger, message: str):
        return {"delivered": True, "channel": "fixture", "channels": ["fixture"], "error": ""}

    def deliver(self):
        return deliver_finding_notification_outbox(
            config=self.config,
            logger=self.logger,
            db=self.db,
            target=TARGET,
            transport=self.success_transport,
            now="2099-01-01T00:00:00Z",
        )

    def material_hypothesis(self, tag: str):
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="app.example.test",
            endpoint=f"https://app.example.test/assets/{tag}.js",
            source_ref=f"fixture:dispatcher:material:{tag}",
            family="secret_exposure",
            variant="material_surface",
            support=[
                {"type": "secret_pattern", "source": "fixture", "source_group": f"pattern:{tag}", "weight": 20, "text": "Redacted material-shaped indicator."},
                {"type": "context", "source": "fixture", "source_group": f"client:{tag}", "weight": 18, "text": "Client-delivered source context."},
            ],
            contradict=[],
            missing=["reviewed redacted structure"],
            rule_ids=["fixture-dispatch-material"],
            summary="Dispatcher material fixture.",
        )

    def review_material(self, hypothesis_id: str, review_id: str):
        payload = {
            "version": "1.0.0",
            "review_id": review_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis_id,
            "material_class": "structured_key_material",
            "classification": "confirmed_structure",
            "classification_fingerprint": "a" * 64,
            "source_artifact_fingerprint": "b" * 64,
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
        path = self.root / f"{review_id}.json"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        return review_material_classification_artifact(self.db, artifact_path=path, actor="test")

    def graphql_hypothesis(self, tag: str):
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="app.example.test",
            endpoint=f"https://app.example.test/graphql/{tag}",
            source_ref=f"fixture:dispatcher:graphql:{tag}",
            family="graphql_data_exposure",
            variant="sensitive_fields_with_policy_context",
            support=[
                {"type": "sensitive_fields", "source": "graphql_intelligence", "source_group": f"graphql_static:{tag}", "weight": 20, "text": "Controlled fixture identifies sensitive field metadata."},
                {"type": "client_operation", "source": "graphql_intelligence", "source_group": f"graphql_operation:{tag}", "weight": 14, "text": "Controlled fixture identifies a client operation."},
                {"type": "field_policy_context", "source": "stored_security_policy", "source_group": f"graphql_policy:{tag}", "weight": 15, "text": "Controlled fixture records documented field policy."},
            ],
            contradict=[],
            missing=["controlled field-policy response comparison"],
            rule_ids=["fixture-dispatch-graphql"],
            summary="Dispatcher GraphQL fixture.",
        )

    def review_graphql(self, hypothesis_id: str, comparison_id: str):
        payload = {
            "version": "1.0.0",
            "comparison_id": comparison_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis_id,
            "comparison_mode": "single_role_policy",
            "operation_name": "ViewerProfile",
            "operation_fingerprint": "c" * 64,
            "policy_source_fingerprint": "d" * 64,
            "policy_documented": True,
            "restricted_fields": ["ssn"],
            "tested_role": {"role_class": "restricted_test_role", "controlled_test_role": True, "observed_fields": ["id", "ssn"], "raw_field_values_stored": False, "raw_body_stored": False},
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
        path = self.root / f"{comparison_id}.json"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        return review_graphql_data_exposure_artifact(self.db, artifact_path=path, actor="test")


class ReviewedEvidenceDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fx = DispatcherFixture(Path(self.temp.name))

    def tearDown(self) -> None:
        self.fx.close()
        self.temp.cleanup()

    def _dispatch(self, review_id: str, review_kind: str = ""):
        return dispatch_reviewed_evidence(
            self.fx.ctx(), review_id=review_id, review_kind=review_kind, actor="test"
        )

    def test_material_review_queues_then_worker_delivers_exactly_once(self) -> None:
        hypothesis = self.fx.material_hypothesis("material")
        review_id = "MCR-DISPATCH-MATERIAL"
        review = self.fx.review_material(hypothesis["hypothesis_id"], review_id)
        self.assertEqual(review["signal_type"], "credential_material_confirmed")
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

        first = self._dispatch(review_id)
        self.assertEqual(first["review_kind"], "material_classification")
        self.assertEqual(first["status"], "completed")
        self.assertTrue(first["candidate_id"])
        self.assertEqual(first["candidate_transitions"][0]["transition"], "new")
        self.assertEqual(len(first["notification_events"]), 1)
        self.assertEqual(str(first["notification_events"][0]["status"]), "queued")
        self.assertEqual(str(first["notification_events"][0]["outbox_status"]), "queued")
        self.assertTrue(first["notification_delivery_deferred_to_outbox_worker"])
        self.assertFalse(first["notification_delivery_may_use_configured_outbound_transports"])
        self.assertFalse(first["vulnerability_confirmed"])

        delivery = self.fx.deliver()
        self.assertEqual(delivery["delivered"], 1)
        second = self._dispatch(review_id)
        self.assertTrue(second["replayed"])
        self.assertEqual(second["attempts"], 2)
        self.assertEqual(second["candidate_id"], first["candidate_id"])
        self.assertEqual(second["bridge"]["status"], "already_applied")
        self.assertEqual(second["candidate_transitions"], [])
        self.assertEqual(len(second["notification_events"]), 1)
        self.assertEqual(str(second["notification_events"][0]["status"]), "delivered")
        self.assertEqual(str(second["notification_events"][0]["outbox_status"]), "delivered")

        events = self.fx.db.one("SELECT COUNT(*) AS n FROM notification_events WHERE event_type='potential_finding'")
        deliveries = self.fx.db.one("SELECT COUNT(*) AS n FROM notification_deliveries")
        dispatcher = self.fx.db.one(
            "SELECT attempts,event_ids_json,status FROM reviewed_evidence_dispatch_runs WHERE review_id=?",
            (review_id,),
        )
        self.assertEqual(int(events["n"]), 1)
        self.assertEqual(int(deliveries["n"]), 1)
        self.assertEqual(int(dispatcher["attempts"]), 2)
        self.assertEqual(str(dispatcher["status"]), "completed")
        self.assertEqual(len(json.loads(str(dispatcher["event_ids_json"]))), 1)

    def test_graphql_review_uses_same_queue_and_worker(self) -> None:
        hypothesis = self.fx.graphql_hypothesis("graphql")
        review_id = "GQLD-DISPATCH-GRAPHQL"
        review = self.fx.review_graphql(hypothesis["hypothesis_id"], review_id)
        self.assertEqual(review["signal_type"], "sensitive_graphql_response_observed")

        result = self._dispatch(review_id)
        self.assertEqual(result["review_kind"], "graphql_data_exposure")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["candidate_id"])
        self.assertEqual(result["candidate_transitions"][0]["transition"], "new")
        self.assertEqual(str(result["notification_events"][0]["status"]), "queued")
        self.assertEqual(self.fx.deliver()["delivered"], 1)
        candidate = self.fx.db.one(
            "SELECT bug_family FROM bug_candidates WHERE candidate_id=?",
            (result["candidate_id"],),
        )
        self.assertEqual(str(candidate["bug_family"]), "graphql_data_exposure")

    def test_kind_prefix_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(ReconError, "does not match"):
            dispatch_reviewed_evidence(
                self.fx.ctx(),
                review_id="MCR-WRONG-KIND",
                review_kind="graphql_data_exposure",
                actor="test",
            )

    def test_dispatcher_source_has_no_target_or_transport_network_client(self) -> None:
        source = (ROOT / "app/reviewed_evidence_dispatcher.py").read_text(encoding="utf-8").lower()
        for forbidden in (
            "urllib.request",
            "requests.",
            "socket.",
            "urlopen(",
            "http.client",
            "aiohttp",
            "telegramnotifier",
            "_send_notify_cli",
            "subprocess.run",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("notification_delivery_deferred_to_outbox_worker", source)


if __name__ == "__main__":
    unittest.main()
