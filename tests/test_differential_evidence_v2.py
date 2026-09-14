from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, AppPaths, Database, ReconError, json_dumps, utc_now
from differential_evidence import OPEN_REDIRECT_CONTROLLED_DESTINATION
from differential_evidence_adapter import adapt_differential_evidence
from hypothesis_admission import record_hypothesis


RUN_ID = "RUN-DIFFERENTIAL-V2-1"
ANALYSIS_ID = "AN-DIFFERENTIAL-V2-1"
TARGET = "example.test"
ENDPOINT = "https://app.example.test/redirect"


class DifferentialFixture:
    def __init__(self, root: Path):
        self.root = root
        self.paths = AppPaths.from_root(root)
        self.paths.ensure()
        self.db = Database(self.paths.db)
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES(?,?,?,?,?,?,1)",
            (RUN_ID, APP_VERSION, "success", now, now, TARGET),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ANALYSIS_ID, RUN_ID, TARGET, "diff-v2-test", "diff-v2-test", "analysis", "success", now, now, "{}"),
        )

    def close(self):
        self.db.close()

    def hypothesis(self, *, structural: bool = True):
        support = []
        if structural:
            support = [
                {
                    "type": "redirect_parameter",
                    "source": "javascript_dataflow",
                    "source_group": "stored:open-redirect-static",
                    "weight": 18,
                    "text": "Stored static analysis identifies a user-controlled redirect destination source.",
                },
                {
                    "type": "navigation_context",
                    "source": "javascript_dataflow",
                    "source_group": "stored:open-redirect-static",
                    "weight": 20,
                    "text": "Stored static analysis identifies a navigation sink for the same flow.",
                },
            ]
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="app.example.test",
            endpoint=ENDPOINT,
            source_ref="fixture:open-redirect",
            family="open_redirect",
            variant="static_source_to_navigation_sink",
            support=support,
            contradict=[],
            missing=["external_destination_accepted"],
            rule_ids=["fixture-open-redirect"],
            summary="Open Redirect differential evidence fixture.",
        )

    def write_artifact(self, hypothesis_id: str, *, differential_id="DEV-OPEN-REDIRECT-1", **updates):
        payload = {
            "version": "2.0.0",
            "kind": "open_redirect_expected_observed",
            "differential_id": differential_id,
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis_id,
            "family": "open_redirect",
            "parameter_name": "next",
            "controlled_destination": OPEN_REDIRECT_CONTROLLED_DESTINATION,
            "baseline": {"status_code": 302, "location": "/home"},
            "probe": {"status_code": 302, "location": OPEN_REDIRECT_CONTROLLED_DESTINATION},
            "observed_at": utc_now(),
            "analyst_verified": True,
            "reviewed_by": "test-analyst",
            "raw_body_stored": False,
            "redirect_followed": False,
            "external_destination_connection": False,
        }
        payload.update(updates)
        path = self.root / f"{differential_id}.json"
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        return path


class DifferentialEvidenceV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fx = DifferentialFixture(Path(self.temp.name))

    def tearDown(self):
        self.fx.close()
        self.temp.cleanup()

    def test_verified_open_redirect_differential_can_promote_potential_finding(self):
        hypothesis = self.fx.hypothesis(structural=True)
        self.assertFalse(hypothesis["assessment"]["admitted"])
        path = self.fx.write_artifact(hypothesis["hypothesis_id"])

        result = adapt_differential_evidence(self.fx.db, artifact_path=path, actor="test")

        self.assertEqual(result["status"], "applied")
        self.assertTrue(result["admitted"])
        self.assertTrue(result["candidate_id"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertEqual(result["network_requests_executed_by_adapter"], 0)
        candidate = self.fx.db.one(
            "SELECT bug_family,candidate_state FROM bug_candidates WHERE candidate_id=?",
            (result["candidate_id"],),
        )
        self.assertEqual(str(candidate["bug_family"]), "open_redirect")
        evidence = self.fx.db.one(
            "SELECT source_kind,evidence_type,directness FROM evidence_records WHERE evidence_id=?",
            (result["evidence_id"],),
        )
        self.assertEqual(str(evidence["source_kind"]), "analyst_verified_differential")
        self.assertEqual(str(evidence["evidence_type"]), "external_destination_accepted")
        self.assertEqual(str(evidence["directness"]), "direct")

        repeated = adapt_differential_evidence(self.fx.db, artifact_path=path, actor="test")
        self.assertEqual(repeated["status"], "already_applied")
        self.assertEqual(
            int(self.fx.db.one("SELECT COUNT(*) FROM differential_evidence_adapter_runs")[0]),
            1,
        )

    def test_direct_differential_requires_prior_structural_hypothesis_context(self):
        hypothesis = self.fx.hypothesis(structural=False)
        path = self.fx.write_artifact(hypothesis["hypothesis_id"], differential_id="DEV-NO-STRUCTURE")
        with self.assertRaisesRegex(ReconError, "structural"):
            adapt_differential_evidence(self.fx.db, artifact_path=path, actor="test")
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM bug_candidates")[0]), 0)

    def test_unverified_or_followed_redirect_artifact_fails_closed(self):
        hypothesis = self.fx.hypothesis(structural=True)
        unverified = self.fx.write_artifact(
            hypothesis["hypothesis_id"],
            differential_id="DEV-UNVERIFIED",
            analyst_verified=False,
        )
        with self.assertRaisesRegex(ReconError, "analyst verification"):
            adapt_differential_evidence(self.fx.db, artifact_path=unverified, actor="test")

        followed = self.fx.write_artifact(
            hypothesis["hypothesis_id"],
            differential_id="DEV-FOLLOWED",
            redirect_followed=True,
        )
        with self.assertRaisesRegex(ReconError, "must not follow"):
            adapt_differential_evidence(self.fx.db, artifact_path=followed, actor="test")

    def test_wrong_destination_and_stale_artifacts_fail_closed(self):
        hypothesis = self.fx.hypothesis(structural=True)
        wrong = self.fx.write_artifact(
            hypothesis["hypothesis_id"],
            differential_id="DEV-WRONG-DEST",
            controlled_destination="https://example.org/",
        )
        with self.assertRaisesRegex(ReconError, "controlled destination"):
            adapt_differential_evidence(self.fx.db, artifact_path=wrong, actor="test")

        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        stale = self.fx.write_artifact(
            hypothesis["hypothesis_id"],
            differential_id="DEV-STALE",
            observed_at=old,
        )
        with self.assertRaisesRegex(ReconError, "freshness"):
            adapt_differential_evidence(self.fx.db, artifact_path=stale, actor="test")

    def test_mutated_artifact_after_application_is_rejected(self):
        hypothesis = self.fx.hypothesis(structural=True)
        path = self.fx.write_artifact(hypothesis["hypothesis_id"], differential_id="DEV-MUTABLE")
        adapt_differential_evidence(self.fx.db, artifact_path=path, actor="test")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["baseline"]["status_code"] = 200
        path.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReconError, "changed"):
            adapt_differential_evidence(self.fx.db, artifact_path=path, actor="test")

    def test_adapter_source_has_no_network_transport_surface(self):
        for name in ("differential_evidence.py", "differential_evidence_adapter.py"):
            source = (ROOT / "app" / name).read_text(encoding="utf-8")
            for forbidden in ("urllib.request", "requests.", "socket.", "urlopen(", "_perform_request("):
                self.assertNotIn(forbidden, source)

    def test_cli_parser_exposes_offline_differential_adapt(self):
        import recon_monitor

        parser = recon_monitor.build_parser()
        args = parser.parse_args(
            [
                "validation",
                "differential-adapt",
                "--evidence-file",
                "/tmp/differential.json",
            ]
        )
        self.assertEqual(args.command, "validation")
        self.assertEqual(args.action, "differential-adapt")
        self.assertEqual(args.evidence_file, "/tmp/differential.json")


if __name__ == "__main__":
    unittest.main()
