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
from hypothesis_admission import record_hypothesis
from typed_evidence_adapter import adapt_validation_runner_execution


RUN_ID = "RUN-TYPED-EVIDENCE-1"
ANALYSIS_ID = "AN-TYPED-EVIDENCE-1"
TARGET = "example.test"


class TypedEvidenceFixture:
    def __init__(self, root: Path):
        self.root = root
        self.paths = AppPaths.from_root(root)
        self.paths.ensure()
        self.run_dir = self.paths.output / TARGET / RUN_ID
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.db = Database(self.paths.db)
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES(?,?,?,?,?,?,1)",
            (RUN_ID, APP_VERSION, "success", now, now, TARGET),
        )
        self.db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,started_at,finished_at,run_dir,baseline) "
            "VALUES(?,?,?,?,?,?,?,0)",
            (RUN_ID, TARGET, "typed-evidence-policy", "success", now, now, str(self.run_dir)),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ANALYSIS_ID, RUN_ID, TARGET, "typed-test", "typed-test", "analysis", "success", now, now, "{}"),
        )

    def close(self):
        self.db.close()

    def hypothesis(self, family, endpoint, support=None, contradict=None, variant="typed_adapter"):
        return record_hypothesis(
            self.db,
            analysis_id=ANALYSIS_ID,
            source_run_id=RUN_ID,
            target=TARGET,
            alert_id=None,
            asset="api.example.test",
            endpoint=endpoint,
            source_ref=f"fixture:{family}:{endpoint}",
            family=family,
            variant=variant,
            support=list(support or []),
            contradict=list(contradict or []),
            missing=["typed passive-live confirmation"],
            rule_ids=["fixture-typed-adapter"],
            summary=f"{family} typed evidence fixture.",
        )

    def write_execution(
        self,
        *,
        execution_id,
        hypothesis_id,
        family,
        endpoint,
        observations,
        finished_at=None,
    ):
        finished_at = finished_at or utc_now()
        payload = {
            "version": "1.0.0",
            "rule_version": "fixture",
            "execution_id": execution_id,
            "contract_id": "VDR-FIXTURE",
            "run_id": RUN_ID,
            "analysis_id": ANALYSIS_ID,
            "target": TARGET,
            "hypothesis_id": hypothesis_id,
            "family": family,
            "validation_level": "passive_live",
            "status": "completed",
            "stopped_reason": "",
            "observations": observations,
            "network_requests_executed": len(observations),
            "raw_bodies_stored": False,
            "typed_evidence_emitted": False,
            "observation_only": True,
            "affects_admission": False,
            "affects_candidate_promotion": False,
            "requires_evidence_adapter": True,
            "automatic_execution": False,
            "started_at": finished_at,
            "finished_at": finished_at,
        }
        path = self.run_dir / "validation-runner-executions.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json_dumps(payload) + "\n")
        return payload

    @staticmethod
    def observation(
        endpoint,
        *,
        method="GET",
        status=200,
        headers=None,
        shape=None,
        sensitive_keys=None,
        sensitive_categories=None,
        observed_at=None,
    ):
        return {
            "sequence": 1,
            "request_purpose": "fixture",
            "method": method,
            "url": endpoint,
            "status_code": status,
            "headers": dict(headers or {}),
            "content_type": "application/json",
            "response_bytes": 64,
            "body_sha256": "deadbeef",
            "response_shape": shape if shape is not None else {"ok": "boolean"},
            "shape_hash": "shapehash",
            "sensitive_key_names": list(sensitive_keys or []),
            "sensitive_pattern_categories": list(sensitive_categories or []),
            "redirect_outside_scope": False,
            "raw_body_stored": False,
            "error": "",
            "observed_at": observed_at or utc_now(),
        }


class TypedEvidenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fx = TypedEvidenceFixture(Path(self.temp.name))

    def tearDown(self):
        self.fx.close()
        self.temp.cleanup()

    def adapt(self, execution_id, **kwargs):
        return adapt_validation_runner_execution(
            self.fx.paths,
            self.fx.db,
            scan_run_id=RUN_ID,
            target=TARGET,
            execution_id=execution_id,
            actor="test",
            **kwargs,
        )

    def test_cors_direct_signal_can_promote_only_with_independent_prior_context(self):
        endpoint = "https://api.example.test/private"
        hypothesis = self.fx.hypothesis(
            "cors_misconfiguration",
            endpoint,
            support=[
                {"type": "cors_header", "source_group": "stored:headers", "source": "headers", "weight": 20},
                {"type": "sensitive_context", "source_group": "stored:business", "source": "business", "weight": 18},
            ],
        )
        self.assertFalse(hypothesis["assessment"]["admitted"])
        self.fx.write_execution(
            execution_id="VEX-CORS-1",
            hypothesis_id=hypothesis["hypothesis_id"],
            family="cors_misconfiguration",
            endpoint=endpoint,
            observations=[
                self.fx.observation(
                    endpoint,
                    headers={"access-control-allow-origin": "https://safe-validation.invalid"},
                )
            ],
        )

        result = self.adapt("VEX-CORS-1")
        self.assertEqual(result["status"], "applied")
        self.assertIn("untrusted_origin_allowed", result["support_types"])
        self.assertTrue(result["admitted"])
        self.assertTrue(result["candidate_id"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertEqual(result["network_requests_executed_by_adapter"], 0)
        candidate = self.fx.db.one(
            "SELECT candidate_id,bug_family FROM bug_candidates WHERE candidate_id=?",
            (result["candidate_id"],),
        )
        self.assertEqual(str(candidate["bug_family"]), "cors_misconfiguration")
        evidence = self.fx.db.one(
            "SELECT evidence_type,root_fingerprint,summary FROM evidence_records "
            "WHERE source_kind='passive_live_validation' AND polarity='support'"
        )
        self.assertIsNotNone(evidence)
        self.assertIn("untrusted_origin_allowed", str(evidence["summary"]))

        before_seen = int(
            self.fx.db.one("SELECT seen_count FROM analysis_hypotheses WHERE hypothesis_id=?", (hypothesis["hypothesis_id"],))[0]
        )
        before_evidence = int(self.fx.db.one("SELECT COUNT(*) FROM evidence_records")[0])
        repeated = self.adapt("VEX-CORS-1")
        self.assertEqual(repeated["status"], "already_applied")
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM evidence_records")[0]), before_evidence)
        self.assertEqual(
            int(self.fx.db.one("SELECT seen_count FROM analysis_hypotheses WHERE hypothesis_id=?", (hypothesis["hypothesis_id"],))[0]),
            before_seen,
        )

    def test_one_execution_cannot_fake_independent_sources(self):
        endpoint = "https://api.example.test/account"
        hypothesis = self.fx.hypothesis("cors_misconfiguration", endpoint)
        self.fx.write_execution(
            execution_id="VEX-CORS-ONE-ROOT",
            hypothesis_id=hypothesis["hypothesis_id"],
            family="cors_misconfiguration",
            endpoint=endpoint,
            observations=[
                self.fx.observation(
                    endpoint,
                    headers={"access-control-allow-origin": "*"},
                    sensitive_keys=["profile.email"],
                )
            ],
        )
        result = self.adapt("VEX-CORS-ONE-ROOT")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["candidate_id"], "")
        row = self.fx.db.one("SELECT admission_json FROM analysis_hypotheses WHERE hypothesis_id=?", (hypothesis["hypothesis_id"],))
        admission = json.loads(row["admission_json"])
        self.assertEqual(admission["independent_sources"], 1)
        roots = {
            str(row["root_fingerprint"])
            for row in self.fx.db.all("SELECT root_fingerprint FROM evidence_records WHERE source_kind='passive_live_validation'")
        }
        self.assertEqual(len(roots), 1)

    def test_information_disclosure_metadata_does_not_overpromote(self):
        endpoint = "https://api.example.test/profile"
        hypothesis = self.fx.hypothesis(
            "information_disclosure",
            endpoint,
            support=[
                {"type": "sensitive_marker", "source_group": "stored:semantic", "source": "semantic", "weight": 14},
                {"type": "stored_evidence", "source_group": "stored:artifact", "source": "artifact", "weight": 8},
            ],
        )
        self.fx.write_execution(
            execution_id="VEX-INFO-1",
            hypothesis_id=hypothesis["hypothesis_id"],
            family="information_disclosure",
            endpoint=endpoint,
            observations=[self.fx.observation(endpoint, sensitive_keys=["user.email", "account.id"])],
        )
        result = self.adapt("VEX-INFO-1")
        self.assertFalse(result["admitted"])
        self.assertEqual(result["candidate_id"], "")
        self.assertNotIn("sensitive_response_observed", result["support_types"])
        self.assertNotIn("private_field_publicly_observed", result["support_types"])
        self.assertIsNone(
            self.fx.db.one("SELECT candidate_id FROM bug_candidates WHERE bug_family='information_disclosure'")
        )

    def test_cache_controls_are_typed_as_contradiction_without_new_promotion(self):
        endpoint = "https://api.example.test/account"
        hypothesis = self.fx.hypothesis(
            "sensitive_caching",
            endpoint,
            support=[
                {"type": "cache_header", "source_group": "stored:headers", "source": "headers", "weight": 20},
                {"type": "sensitive_context", "source_group": "stored:context", "source": "context", "weight": 18},
            ],
        )
        self.fx.write_execution(
            execution_id="VEX-CACHE-1",
            hypothesis_id=hypothesis["hypothesis_id"],
            family="sensitive_caching",
            endpoint=endpoint,
            observations=[
                self.fx.observation(
                    endpoint,
                    headers={"cache-control": "private, no-store", "vary": "Authorization"},
                    sensitive_keys=["account.email"],
                )
            ],
        )
        result = self.adapt("VEX-CACHE-1")
        self.assertIn("private_cache_control_observed", result["contradiction_types"])
        self.assertIn("user_specific_vary_observed", result["contradiction_types"])
        self.assertFalse(result["admitted"])
        self.assertEqual(result["admission_state"], "shadow_contradicted")
        self.assertEqual(result["candidate_id"], "")
        self.assertIsNone(self.fx.db.one("SELECT candidate_id FROM bug_candidates WHERE bug_family='sensitive_caching'"))

    def test_source_map_confirmation_requires_independent_internal_structure(self):
        endpoint = "https://static.example.test/app.js.map"
        hypothesis = self.fx.hypothesis(
            "source_map_exposure",
            endpoint,
            support=[
                {"type": "source_map", "source_group": "stored:js-reference", "source": "javascript_metadata", "weight": 18},
                {"type": "internal_sources", "source_group": "stored:map-structure", "source": "source_map_metadata", "weight": 24},
            ],
        )
        self.fx.write_execution(
            execution_id="VEX-MAP-1",
            hypothesis_id=hypothesis["hypothesis_id"],
            family="source_map_exposure",
            endpoint=endpoint,
            observations=[
                self.fx.observation(
                    endpoint,
                    status=200,
                    shape={"version": "number", "sources": ["string"], "names": ["string"]},
                )
            ],
        )
        result = self.adapt("VEX-MAP-1")
        self.assertIn("source_map_publicly_reachable", result["support_types"])
        self.assertTrue(result["admitted"])
        self.assertTrue(result["candidate_id"])

        endpoint2 = "https://static.example.test/other.js.map"
        hypothesis2 = self.fx.hypothesis(
            "source_map_exposure",
            endpoint2,
            support=[{"type": "source_map", "source_group": "stored:js-reference-2", "source": "javascript_metadata", "weight": 18}],
        )
        self.fx.write_execution(
            execution_id="VEX-MAP-NO-INTERNAL",
            hypothesis_id=hypothesis2["hypothesis_id"],
            family="source_map_exposure",
            endpoint=endpoint2,
            observations=[self.fx.observation(endpoint2, status=200, shape={"version": "number", "sources": ["string"]})],
        )
        result2 = self.adapt("VEX-MAP-NO-INTERNAL")
        self.assertNotIn("source_map_publicly_reachable", result2["support_types"])
        self.assertFalse(result2["admitted"])
        self.assertEqual(result2["candidate_id"], "")

    def test_stale_execution_fails_closed_without_evidence(self):
        endpoint = "https://api.example.test/stale"
        hypothesis = self.fx.hypothesis("information_disclosure", endpoint)
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.fx.write_execution(
            execution_id="VEX-STALE-1",
            hypothesis_id=hypothesis["hypothesis_id"],
            family="information_disclosure",
            endpoint=endpoint,
            observations=[self.fx.observation(endpoint, sensitive_keys=["email"], observed_at=old)],
            finished_at=old,
        )
        with self.assertRaises(ReconError):
            self.adapt("VEX-STALE-1")
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM evidence_records WHERE source_kind='passive_live_validation'")[0]), 0)
        self.assertEqual(int(self.fx.db.one("SELECT COUNT(*) FROM typed_evidence_adapter_runs")[0]), 0)

    def test_mutated_artifact_after_apply_fails_closed(self):
        endpoint = "https://api.example.test/mutable"
        hypothesis = self.fx.hypothesis("information_disclosure", endpoint)
        self.fx.write_execution(
            execution_id="VEX-MUTABLE-1",
            hypothesis_id=hypothesis["hypothesis_id"],
            family="information_disclosure",
            endpoint=endpoint,
            observations=[self.fx.observation(endpoint, sensitive_keys=["email"])],
        )
        self.adapt("VEX-MUTABLE-1")
        path = self.fx.run_dir / "validation-runner-executions.jsonl"
        row = json.loads(path.read_text(encoding="utf-8").strip())
        row["observations"][0]["headers"]["server"] = "mutated"
        path.write_text(json_dumps(row) + "\n", encoding="utf-8")
        with self.assertRaises(ReconError):
            self.adapt("VEX-MUTABLE-1")

    def test_adapter_source_has_no_transport_surface(self):
        source = (ROOT / "app" / "typed_evidence_adapter.py").read_text(encoding="utf-8")
        for forbidden in ("urllib.request", "requests.", "socket.", "_perform_request(", "urlopen("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
