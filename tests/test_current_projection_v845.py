from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, SCHEMA_VERSION, Database, utc_now
from workspace_v7 import attack_surface_graph, change_intelligence, target_memory


class CurrentProjectionV845Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "recon.db")
        self.target = "current.test"
        self.run_id = "run-shared"
        self.old_analysis = "analysis-old"
        self.current_analysis = "analysis-current"
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_count) VALUES(?,?,?,?,?,?)",
            (self.run_id, APP_VERSION, "partial", "2026-08-08T17:00:00Z", "2026-08-08T17:10:00Z", 2),
        )
        self.db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) VALUES(?,?,?,?,?,?,?,?,?)",
            (self.run_id, self.target, "p", "success", "report", "2026-08-08T17:00:00Z", "2026-08-08T17:09:00Z", self.tmp.name, 0),
        )
        for stage in ("subdomains", "dns", "urls", "javascript", "endpoint_validation", "fingerprint", "report"):
            self.db.execute(
                "INSERT INTO stage_runs(run_id,target,stage,status,attempt,started_at,finished_at,metrics_json) VALUES(?,?,?,?,1,?,?,?)",
                (self.run_id, self.target, stage, "success", now, now, "{}"),
            )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.old_analysis, self.run_id, self.target, "old", "old", "analysis", "success", "2026-08-08T17:20:00Z", "2026-08-08T17:21:00Z", "{}"),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.current_analysis, self.run_id, self.target, "new", "new", "analysis", "success", "2026-08-08T17:30:00Z", "2026-08-08T17:31:00Z", "{}"),
        )
        self._candidate("OLD-BOLA", self.old_analysis, "broken_object_authorization", 92)

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def _candidate(self, candidate_id: str, analysis_id: str, family: str, priority: int) -> None:
        now = utc_now()
        self.db.execute(
            """INSERT INTO bug_candidates(
            candidate_id,candidate_fingerprint,analysis_id,source_run_id,target,bug_family,bug_variant,title,summary,
            likelihood_score,evidence_strength,impact_potential,priority_score,candidate_state,safe_next_action,rule_version,
            evidence_coverage,exploitability_confidence,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                candidate_id, f"fp-{candidate_id}", analysis_id, self.run_id, self.target, family, "test",
                "BOLA / IDOR" if family == "broken_object_authorization" else family,
                "candidate used to verify projection isolation", 60, 60, 60, priority, "plausible", "review", "test",
                60, 30, now, now,
            ),
        )

    def test_version_and_schema(self) -> None:
        self.assertEqual(APP_VERSION, "8.4.5")
        self.assertEqual(SCHEMA_VERSION, 18)
        self.assertEqual(self.db.meta_get("schema_version"), "18")

    def test_change_intelligence_does_not_resurface_historical_candidate(self) -> None:
        result = change_intelligence(self.db, target=self.target, persist=False)
        self.assertEqual(result["analysis_id"], self.current_analysis)
        self.assertEqual([x for x in result["important"] if x.get("type") == "candidate"], [])

        self._candidate("CURRENT-BOLA", self.current_analysis, "broken_object_authorization", 81)
        result = change_intelligence(self.db, target=self.target, persist=False)
        candidate_ids = [x["candidate_id"] for x in result["important"] if x.get("type") == "candidate"]
        self.assertEqual(candidate_ids, ["CURRENT-BOLA"])

    def test_attack_surface_graph_projects_only_current_analysis_candidates(self) -> None:
        self._candidate("CURRENT-PATH", self.current_analysis, "path_traversal", 75)
        graph = attack_surface_graph(self.db, target=self.target)
        candidate_nodes = [n for n in graph["nodes"] if n.get("kind") == "candidate"]
        self.assertEqual([n["value"] for n in candidate_nodes], ["CURRENT-PATH"])

    def test_historical_target_memory_is_still_preserved(self) -> None:
        self._candidate("CURRENT-PATH", self.current_analysis, "path_traversal", 75)
        memory = target_memory(self.db, target=self.target, persist=False)
        history = {row["bug_family"]: row["c"] for row in memory["history"]["candidate_families"]}
        self.assertEqual(history.get("broken_object_authorization"), 1)
        self.assertEqual(history.get("path_traversal"), 1)


if __name__ == "__main__":
    unittest.main()
