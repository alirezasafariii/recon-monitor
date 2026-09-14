from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, AppPaths, Database, ReconError, json_dumps, utc_now
from hypothesis_admission import record_hypothesis
from material_classification_review import review_material_classification_artifact

RUN_ID = "RUN-MATERIAL-1"
ANALYSIS_ID = "AN-MATERIAL-1"
TARGET = "example.test"


class Fixture:
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
            (ANALYSIS_ID, RUN_ID, TARGET, "material-test", "material-test", "analysis", "success", now, now, "{}"),
        )

    def close(self):
        self.db.close()

    def hypothesis(self, tag: str = "base"):
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="app.example.test",
            endpoint=f"https://app.example.test/assets/{tag}.js",
            source_ref=f"fixture:material:{tag}",
            family="secret_exposure",
            variant="material_surface",
            support=[
                {"type": "secret_pattern", "source": "fixture", "source_group": f"pattern:{tag}", "weight": 20, "text": "Redacted material-shaped indicator."},
                {"type": "context", "source": "fixture", "source_group": f"client:{tag}", "weight": 18, "text": "Client-delivered source context."},
            ],
            contradict=[],
            missing=["reviewed redacted structure"],
            rule_ids=["fixture-material-review"],
            summary="Material classification review fixture.",
        )

    def write(self, hypothesis_id: str, *, review_id="MCR-1", classification="confirmed_structure", material_class="structured_key_material", client_delivered=True, ambiguous=False):
        payload = {
            "version": "1.0.0",
            "review_id": review_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis_id,
            "material_class": material_class,
            "classification": classification,
            "classification_fingerprint": "a" * 64,
            "source_artifact_fingerprint": "b" * 64,
            "client_delivered_context": client_delivered,
            "analyst_verified": True,
            "redacted": True,
            "observed_at": utc_now(),
            "reviewed_by": "test-analyst",
            "classification_ambiguous": ambiguous,
            "source_context_ambiguous": False,
            "provider_validation_performed": False,
            "network_request_performed": False,
        }
        path = self.root / f"{review_id}.json"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        return path


class MaterialClassificationReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self.temp.name))

    def tearDown(self):
        self.fx.close()
        self.temp.cleanup()

    def test_confirmed_redacted_structure_is_direct_but_non_promoting(self):
        hypothesis = self.fx.hypothesis("confirmed")
        result = review_material_classification_artifact(
            self.fx.db,
            artifact_path=self.fx.write(hypothesis["hypothesis_id"], review_id="MCR-CONFIRMED"),
            actor="test",
        )
        self.assertEqual(result["signal_type"], "credential_material_confirmed")
        self.assertEqual(result["polarity"], "support")
        self.assertFalse(result["affects_admission"])
        self.assertFalse(result["affects_candidate_promotion"])
        self.assertEqual(result["network_requests_executed"], 0)
        self.assertFalse(result["provider_validation_performed"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)
        evidence = self.fx.db.one("SELECT directness,source_kind FROM evidence_records WHERE evidence_id=?", (result["evidence_id"],))
        self.assertEqual(str(evidence["directness"]), "direct")
        self.assertEqual(str(evidence["source_kind"]), "analyst_verified_redacted_classification")

    def test_controls_do_not_become_support(self):
        hypothesis = self.fx.hypothesis("controls")
        placeholder = review_material_classification_artifact(
            self.fx.db,
            artifact_path=self.fx.write(hypothesis["hypothesis_id"], review_id="MCR-PLACEHOLDER", classification="placeholder"),
            actor="test",
        )
        self.assertEqual(placeholder["signal_type"], "placeholder")
        self.assertEqual(placeholder["polarity"], "contradict")

        public = review_material_classification_artifact(
            self.fx.db,
            artifact_path=self.fx.write(hypothesis["hypothesis_id"], review_id="MCR-PUBLIC", classification="intended_public_identifier"),
            actor="test",
        )
        self.assertEqual(public["signal_type"], "intended_public_client_identifier")
        self.assertEqual(public["polarity"], "contradict")
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

    def test_missing_context_or_ambiguity_fails_closed(self):
        hypothesis = self.fx.hypothesis("closed")
        no_context = review_material_classification_artifact(
            self.fx.db,
            artifact_path=self.fx.write(hypothesis["hypothesis_id"], review_id="MCR-NO-CONTEXT", client_delivered=False),
            actor="test",
        )
        self.assertEqual(no_context["signal_type"], "")
        self.assertEqual(no_context["polarity"], "contradict")

        ambiguous = review_material_classification_artifact(
            self.fx.db,
            artifact_path=self.fx.write(hypothesis["hypothesis_id"], review_id="MCR-AMBIGUOUS", ambiguous=True),
            actor="test",
        )
        self.assertEqual(ambiguous["signal_type"], "")
        self.assertTrue(ambiguous["confounded"])

    def test_review_is_idempotent_and_mutation_fails_closed(self):
        hypothesis = self.fx.hypothesis("immutable")
        path = self.fx.write(hypothesis["hypothesis_id"], review_id="MCR-IDEMPOTENT")
        first = review_material_classification_artifact(self.fx.db, artifact_path=path, actor="test")
        second = review_material_classification_artifact(self.fx.db, artifact_path=path, actor="test")
        self.assertEqual(second["status"], "already_applied")
        self.assertEqual(first["evidence_id"], second["evidence_id"])
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["material_class"] = "provider_token_material"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "changed"):
            review_material_classification_artifact(self.fx.db, artifact_path=path, actor="test")

    def test_non_contract_fields_and_online_validation_flags_are_rejected(self):
        hypothesis = self.fx.hypothesis("reject")
        path = self.fx.write(hypothesis["hypothesis_id"], review_id="MCR-EXTRA")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["unexpected_value"] = "not-allowed"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "non-contract fields"):
            review_material_classification_artifact(self.fx.db, artifact_path=path, actor="test")

        path = self.fx.write(hypothesis["hypothesis_id"], review_id="MCR-ONLINE")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["provider_validation_performed"] = True
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "offline-only"):
            review_material_classification_artifact(self.fx.db, artifact_path=path, actor="test")

    def test_source_has_no_network_or_provider_client_surface(self):
        source = (ROOT / "app/material_classification_review.py").read_text(encoding="utf-8").lower()
        for forbidden in ("urllib.request", "requests.", "socket.", "urlopen(", "http.client", "aiohttp", "subprocess"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
