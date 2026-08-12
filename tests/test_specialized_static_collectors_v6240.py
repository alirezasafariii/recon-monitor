from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from bug_candidates import _static_candidates
from core import AppPaths, Database, json_dumps, utc_now
from family_detectors import evaluate_family_detector, get_detector_spec
from hypothesis_admission import assess_admission
from static_family_collectors import STATIC_SPECIALIZED_FAMILIES, collect_specialized_static_observations, validate_static_specialized_collectors


class SpecializedStaticCollectors6240Tests(unittest.TestCase):
    def _seed(self, db: Database, analysis_id: str, run_id: str, target: str) -> None:
        now = utc_now()
        db.execute("INSERT OR REPLACE INTO source_map_intelligence(analysis_id,target,run_id,js_url,source_map_url,source_count,internal_source_count,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (analysis_id,target,run_id,"https://fixture.invalid/app.js","https://fixture.invalid/app.js.map",12,3,json_dumps(["src/auth.ts","src/api.ts","src/admin.ts"]),now))
        db.execute("INSERT OR REPLACE INTO secret_intelligence(analysis_id,target,run_id,js_url,secret_kind,value_fingerprint,confidence,assessment,reasons_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (analysis_id,target,run_id,"https://fixture.invalid/app.js","api_key","deadbeefcafefeed1234",82,"candidate",json_dumps(["redacted production indicator"]),now))
        db.execute("INSERT OR REPLACE INTO graphql_intelligence(analysis_id,target,run_id,js_url,operation_name,operation_type,identifiers_json,sensitive_fields_json,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (analysis_id,target,run_id,"https://fixture.invalid/app.js","query User($userId: ID!) { user(id:$userId){ email token } }","query",json_dumps(["userId"]),json_dumps(["user","token"]),88,now))
        db.execute("INSERT OR REPLACE INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (analysis_id,target,run_id,"https://fixture.invalid/app.js","location.search","websocket",70,"const ws = new WebSocket(url)",now))

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(STATIC_SPECIALIZED_FAMILIES), {"source_map_exposure","secret_exposure","graphql_authorization","graphql_data_exposure","websocket_authorization"})
        self.assertEqual(validate_static_specialized_collectors(), [])
        for family in STATIC_SPECIALIZED_FAMILIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
        self.assertEqual(get_detector_spec("source_map_exposure").writeups[0].url, "https://nvd.nist.gov/vuln/detail/CVE-2024-27257")
        self.assertEqual(get_detector_spec("source_map_exposure").writeups[0].relation, "exact")
        self.assertEqual(get_detector_spec("graphql_authorization").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2025-130_Sentry/")
        self.assertEqual(get_detector_spec("websocket_authorization").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2025-117_GHSL-2025-118_Outline/")

    def test_collector_emits_all_five_from_persisted_static_intelligence(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                self._seed(db, "analysis-624", "run-624", "fixture.invalid")
                rows = collect_specialized_static_observations(db, "analysis-624", "fixture.invalid")
                self.assertEqual({row.family for row in rows}, set(STATIC_SPECIALIZED_FAMILIES))
                self.assertTrue(all("static-collector-specialized-v1" in row.rules for row in rows))
                self.assertTrue(all(row.support for row in rows))
            finally:
                db.close()

    def test_static_surfaces_do_not_promote_authorization_or_data_exposure_without_conditions(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                self._seed(db, "analysis-624", "run-624", "fixture.invalid")
                rows = collect_specialized_static_observations(db, "analysis-624", "fixture.invalid")
                by_family = {row.family: row for row in rows}
                for family in ("source_map_exposure", "graphql_authorization", "graphql_data_exposure", "websocket_authorization"):
                    row = by_family[family]
                    extraction = evaluate_family_detector(family, row.support, row.contradict, channel="candidate")
                    assessment = assess_admission(family, extraction["support"], extraction["contradict"])
                    self.assertFalse(assessment["admitted"], (family, assessment, extraction))
                secret = by_family["secret_exposure"]
                extraction = evaluate_family_detector("secret_exposure", secret.support, secret.contradict, channel="candidate")
                self.assertTrue(assess_admission("secret_exposure", extraction["support"], extraction["contradict"])["admitted"])
            finally:
                db.close()

    def test_placeholder_secret_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); aid="analysis-624-placeholder"; target="fixture.invalid"
                db.execute("INSERT OR REPLACE INTO secret_intelligence(analysis_id,target,run_id,js_url,secret_kind,value_fingerprint,confidence,assessment,reasons_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (aid,target,"run","https://fixture.invalid/app.js","api_key","placeholder",20,"likely_placeholder",json_dumps(["placeholder"]),now))
                row = collect_specialized_static_observations(db, aid, target)[0]
                extraction = evaluate_family_detector("secret_exposure", row.support, row.contradict, channel="candidate")
                assessment = assess_admission("secret_exposure", extraction["support"], extraction["contradict"])
                self.assertFalse(assessment["admitted"], (assessment, extraction))
                self.assertIn("placeholder", {str(x.get("type") or "") for x in extraction["contradict"]})
            finally:
                db.close()

    def test_orchestrator_physically_removes_specialized_static_blocks(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_specialized_static_observations(db, analysis_id, target)", source)
        self.assertNotIn("# Source maps.", source)
        self.assertNotIn("# Secret candidates.", source)
        self.assertNotIn("# GraphQL operations.", source)
        self.assertNotIn('elif sink == "websocket":', source)

    def test_static_pipeline_records_grounded_hypotheses_and_secret_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                aid="analysis-624-pipeline"; run="run-624-pipeline"; target="fixture.invalid"; now=utc_now()
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_count) VALUES(?,?,?,?,?,?)", (run, "6.23.0", "success", now, now, 1))
                db.execute("INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (aid, run, target, "6.23.0", "2026.08.12.6.23", "analysis", "success", now, now, "{}"))
                self._seed(db, aid, run, target)
                _static_candidates(db, aid, run, target)
                hypotheses = db.all("SELECT bug_family,rule_ids_json FROM analysis_hypotheses WHERE analysis_id=?", (aid,))
                hidden = {str(row["bug_family"]) for row in hypotheses if "static-collector-specialized-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertTrue({"source_map_exposure","graphql_authorization","graphql_data_exposure","websocket_authorization"}.issubset(hidden), hypotheses)
                candidates = db.all("SELECT bug_family,rule_ids_json FROM bug_candidates WHERE analysis_id=?", (aid,))
                specialized = {str(row["bug_family"]) for row in candidates if "static-collector-specialized-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertIn("secret_exposure", specialized, candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
