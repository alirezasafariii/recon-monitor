from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, AppPaths, Database, json_dumps, utc_now
from hypothesis_admission import record_hypothesis
from material_classification_admission_bridge import apply_material_classification_admission
from material_classification_review import review_material_classification_artifact

RUN_ID = "RUN-MATERIAL-ADMISSION-1"
ANALYSIS_ID = "AN-MATERIAL-ADMISSION-1"
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
            (ANALYSIS_ID, RUN_ID, TARGET, "material-admission-test", "material-admission-test", "analysis", "success", now, now, "{}"),
        )

    def close(self) -> None:
        self.db.close()

    def hypothesis(self, tag: str, *, pattern: bool = True, context: bool = True, blocker: str = ""):
        support = []
        if pattern:
            support.append({
                "type": "secret_pattern",
                "source": "fixture",
                "source_group": f"pattern:{tag}",
                "weight": 20,
                "text": "Redacted material-shaped indicator.",
            })
        if context:
            support.append({
                "type": "context",
                "source": "fixture",
                "source_group": f"client:{tag}",
                "weight": 18,
                "text": "Client-delivered source context.",
            })
        contradict = []
        if blocker:
            contradict.append({
                "type": blocker,
                "source": "fixture",
                "source_group": f"blocker:{tag}",
                "weight": -40,
                "text": "Canonical control evidence.",
            })
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="app.example.test",
            endpoint=f"https://app.example.test/assets/{tag}.js",
            source_ref=f"fixture:material-admission:{tag}",
            family="secret_exposure",
            variant="material_surface",
            support=support,
            contradict=contradict,
            missing=["reviewed redacted structure"],
            rule_ids=["fixture-material-admission"],
            summary="Material admission fixture.",
        )

    def review(
        self,
        hypothesis_id: str,
        *,
        review_id: str,
        classification: str = "confirmed_structure",
    ):
        payload = {
            "version": "1.0.0",
            "review_id": review_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis_id,
            "material_class": "structured_key_material",
            "classification": classification,
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


class MaterialClassificationAdmissionBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self.temp.name))

    def tearDown(self) -> None:
        self.fx.close()
        self.temp.cleanup()

    def test_reviewed_structure_promotes_only_through_canonical_admission(self) -> None:
        hypothesis = self.fx.hypothesis("promote")
        review = self.fx.review(hypothesis["hypothesis_id"], review_id="MCR-ADMIT-PROMOTE")
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

        result = apply_material_classification_admission(
            self.fx.db,
            review_id="MCR-ADMIT-PROMOTE",
            actor="test",
        )
        self.assertTrue(result["admitted"])
        self.assertTrue(result["candidate_id"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertFalse(result["provider_validation_performed"])
        self.assertFalse(result["raw_value_stored"])

        candidate = self.fx.db.one(
            "SELECT bug_family FROM bug_candidates WHERE id=?",
            (result["candidate_id"],),
        )
        self.assertEqual(str(candidate["bug_family"]), "secret_exposure")
        link = self.fx.db.one(
            "SELECT evidence_id FROM candidate_evidence_links WHERE candidate_id=? AND evidence_id=?",
            (result["candidate_id"], review["evidence_id"]),
        )
        self.assertIsNotNone(link)

        stored = self.fx.db.one(
            "SELECT supporting_evidence_json FROM analysis_hypotheses WHERE hypothesis_id=?",
            (hypothesis["hypothesis_id"],),
        )
        self.assertNotIn("live_secret_context", str(stored["supporting_evidence_json"]))

    def test_bridge_is_exactly_once(self) -> None:
        hypothesis = self.fx.hypothesis("once")
        self.fx.review(hypothesis["hypothesis_id"], review_id="MCR-ADMIT-ONCE")
        first = apply_material_classification_admission(self.fx.db, review_id="MCR-ADMIT-ONCE", actor="test")
        second = apply_material_classification_admission(self.fx.db, review_id="MCR-ADMIT-ONCE", actor="test")
        self.assertEqual(second["status"], "already_applied")
        self.assertEqual(first["candidate_id"], second["candidate_id"])
        count = self.fx.db.one(
            "SELECT COUNT(*) AS n FROM material_classification_admission_bridge_runs WHERE review_id=?",
            ("MCR-ADMIT-ONCE",),
        )
        self.assertEqual(int(count["n"]), 1)

    def test_missing_independent_structure_fails_closed(self) -> None:
        hypothesis = self.fx.hypothesis("missing-context", context=False)
        self.fx.review(hypothesis["hypothesis_id"], review_id="MCR-ADMIT-MISSING")
        result = apply_material_classification_admission(self.fx.db, review_id="MCR-ADMIT-MISSING", actor="test")
        self.assertEqual(result["status"], "not_eligible")
        self.assertEqual(result["reason"], "missing_client_delivery_context")
        self.assertEqual(result["candidate_id"], "")

    def test_control_classification_never_promotes(self) -> None:
        hypothesis = self.fx.hypothesis("control")
        self.fx.review(
            hypothesis["hypothesis_id"],
            review_id="MCR-ADMIT-CONTROL",
            classification="placeholder",
        )
        result = apply_material_classification_admission(self.fx.db, review_id="MCR-ADMIT-CONTROL", actor="test")
        self.assertEqual(result["status"], "not_eligible")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["candidate_id"], "")

    def test_existing_canonical_blocker_fails_closed(self) -> None:
        hypothesis = self.fx.hypothesis("blocked", blocker="placeholder")
        self.fx.review(hypothesis["hypothesis_id"], review_id="MCR-ADMIT-BLOCKED")
        result = apply_material_classification_admission(self.fx.db, review_id="MCR-ADMIT-BLOCKED", actor="test")
        self.assertEqual(result["status"], "not_eligible")
        self.assertEqual(result["reason"], "blocking_material_contradiction_present")
        self.assertEqual(result["candidate_id"], "")

    def test_bridge_source_has_no_network_or_validation_client(self) -> None:
        source = (ROOT / "app/material_classification_admission_bridge.py").read_text(encoding="utf-8").lower()
        for forbidden in ("urllib.request", "requests.", "socket.", "urlopen(", "http.client", "aiohttp", "subprocess"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
