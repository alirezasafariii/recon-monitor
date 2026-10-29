from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import analysis_engine
from analysis_audit import build_evidence_dossier
from analysis_engine import run_analysis
from candidate_intelligence import enhance_candidates, independent_evidence
from core import APP_VERSION, AppPaths, Database, json_dumps, utc_now
from security_reasoning import REASONING_RULE_VERSION, _materialize_evidence, _schema_assessment, apply_security_reasoning


class EvidenceGroupingTests(unittest.TestCase):
    def setUp(self):
        # All observations are synthetic stored evidence. These tests must not
        # resolve a target, launch a tool, or perform live validation.
        for target in ("socket.getaddrinfo", "socket.socket.connect", "subprocess.Popen"):
            guard = patch(target, side_effect=AssertionError("offline evidence test"))
            guard.start()
            self.addCleanup(guard.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.paths = AppPaths.from_root(Path(temp.name))
        self.paths.ensure()
        self.db = Database(self.paths.db)
        self.addCleanup(self.db.close)
        self.now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-GROUP',?,'success',?,?,?,1)",
            (APP_VERSION, self.now, self.now, "example.test"),
        )
        self.db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-GROUP','example.test','policy','success','report',?,?,?,1)",
            (self.now, self.now, str(self.paths.output / "RUN-GROUP")),
        )
        self.db.execute(
            "INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,status,started_at) "
            "VALUES('AN-GROUP','RUN-GROUP','example.test','test','test','success',?)",
            (self.now,),
        )

    def candidate(self, support=(), contradict=(), *, candidate_id="C-GROUP"):
        values = {
            "candidate_id": candidate_id, "candidate_fingerprint": candidate_id,
            "analysis_id": "AN-GROUP", "source_run_id": "RUN-GROUP", "target": "example.test",
            "bug_family": "ssrf", "bug_variant": "server_fetch", "title": "Stored fetch observation",
            "summary": "Stored observations only", "likelihood_score": 90, "evidence_strength": 90,
            "impact_potential": 80, "priority_score": 80, "observation_quality": 90,
            "candidate_state": "possible", "safe_next_action": "Review stored evidence",
            "rule_version": "test", "created_at": self.now, "updated_at": self.now,
            "supporting_evidence_json": json_dumps(list(support)),
            "contradicting_evidence_json": json_dumps(list(contradict)),
        }
        self.db.execute(
            f"INSERT INTO bug_candidates({','.join(values)}) VALUES({','.join('?' for _ in values)})",
            tuple(values.values()),
        )
        return dict(self.db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate_id,)))

    @staticmethod
    def facts():
        return [
            {"type": "url_parameter", "source": "endpoint_contract", "source_group": "stored_fetch",
             "text": "Remote fetch observation", "weight": 12, "direct": True},
            {"type": "server_fetch_semantic", "source": "endpoint_contract", "source_group": "stored_fetch",
             "text": "Remote fetch observation", "weight": 16, "direct": True},
            {"type": "server_fetch_observed", "source": "endpoint_contract", "source_group": "stored_fetch",
             "text": "Remote fetch observation", "weight": 28, "direct": True},
        ]

    def test_all_typed_facts_survive_one_source_group_without_mutating_input(self):
        facts = self.facts()
        original = copy.deepcopy(facts)
        retained, meta = independent_evidence(iter(facts))
        self.assertEqual({item["type"] for item in retained}, {item["type"] for item in facts})
        self.assertEqual(meta["independent_groups"], 1)
        self.assertEqual(meta["raw_signals"], 3)
        self.assertEqual(meta["double_counted_signals_suppressed"], 2)
        self.assertEqual(facts, original)

    def test_empty_and_legacy_source_fallback(self):
        retained, meta = independent_evidence([])
        self.assertEqual(retained, [])
        self.assertEqual(meta["independent_groups"], 0)
        retained, meta = independent_evidence([
            {"type": "url_parameter", "source": "HTTP", "weight": 8},
            {"type": "server_fetch_semantic", "source_group": "http", "weight": 10},
        ])
        self.assertEqual(len(retained), 2)
        self.assertEqual(meta["independent_groups"], 1)

    def test_enrichment_preserves_support_and_contradiction_types(self):
        support = self.facts()
        against = [
            {"type": "server_fetch_not_observed", "source_group": "stored_block", "weight": -30},
            {"type": "destination_restricted", "source_group": "stored_block", "weight": -10},
        ]
        candidate = self.candidate(support, against)
        enhance_candidates(self.db, "AN-GROUP")
        row = self.db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate["candidate_id"],))
        self.assertEqual({x["type"] for x in json.loads(row["supporting_evidence_json"])}, {x["type"] for x in support})
        self.assertEqual({x["type"] for x in json.loads(row["contradicting_evidence_json"])}, {x["type"] for x in against})
        groups = json.loads(row["evidence_groups_json"])
        self.assertEqual(groups["support"]["independent_groups"], 1)
        self.assertEqual(groups["against"]["independent_groups"], 1)

    def test_materialization_retains_types_with_identical_text_and_provenance(self):
        facts = self.facts()
        candidate = self.candidate(facts)
        support, _, meta = _materialize_evidence(self.db, candidate, facts, [])
        self.assertEqual({x["type"] for x in support}, {x["type"] for x in facts})
        self.assertEqual(meta["support_roots"], 1)
        self.assertEqual(len({x["evidence_id"] for x in support}), 3)
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM candidate_evidence_links")[0], 3)
        dossier = build_evidence_dossier(self.db, candidate["candidate_id"])
        self.assertEqual(dossier["confidence"]["independent_evidence_groups"], 1)
        self.assertTrue(all(x["snapshot_verified"] for x in dossier["supporting"]))
        self.assertEqual(len(dossier["supporting"]), 3)

    def test_same_type_different_observation_is_retained_and_repeated_materialization_is_stable(self):
        facts = [dict(self.facts()[0], text=f"Observed HTTP {status}", status_code=status) for status in (200, 403)]
        facts.append(dict(facts[0], raw_reference="second-observation", context="anonymous"))
        candidate = self.candidate(facts)
        first, _, _ = _materialize_evidence(self.db, candidate, facts, [])
        self.assertEqual(len(first), 3)
        second, _, _ = _materialize_evidence(self.db, candidate, first, [])
        self.assertEqual({x["evidence_id"] for x in first}, {x["evidence_id"] for x in second})
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM evidence_records")[0], 3)

    def test_exact_duplicates_are_audited_without_losing_a_distinct_fact(self):
        facts = self.facts()
        duplicate = dict(facts[0], weight=40)
        candidate = self.candidate(facts)
        support, _, meta = _materialize_evidence(self.db, candidate, [*facts, duplicate], [])
        self.assertEqual(len(support), 3)
        retained = next(x for x in support if x["type"] == "url_parameter")
        self.assertEqual(retained["weight"], 40)
        self.assertEqual(meta["independent_evidence"], 1)
        self.assertEqual(self.db.one("SELECT COUNT(*) FROM candidate_evidence_exclusions")[0], 1)

    def test_opposite_polarities_survive_for_same_fact(self):
        fact = self.facts()[0]
        candidate = self.candidate([fact], [fact])
        support, against, meta = _materialize_evidence(self.db, candidate, [fact], [fact])
        self.assertEqual(len(support), 1)
        self.assertEqual(len(against), 1)
        self.assertNotEqual(support[0]["evidence_id"], against[0]["evidence_id"])
        self.assertEqual(meta["support_roots"], 1)
        self.assertEqual(meta["contradict_roots"], 1)

    def test_shared_facts_remain_linked_to_each_candidate(self):
        facts = self.facts()
        first = self.candidate(facts, candidate_id="C-FIRST")
        second = self.candidate(facts, candidate_id="C-SECOND")
        _materialize_evidence(self.db, first, facts, [])
        _materialize_evidence(self.db, second, facts, [])
        for candidate in (first, second):
            dossier = build_evidence_dossier(self.db, candidate["candidate_id"])
            self.assertEqual(len(dossier["supporting"]), 3)
            self.assertTrue(all(x["snapshot_verified"] for x in dossier["supporting"]))

    def test_many_correlated_facts_do_not_satisfy_two_source_promotion(self):
        candidate = self.candidate(self.facts())
        with patch("security_reasoning._synthetic_evidence", return_value=([], [])):
            apply_security_reasoning(self.db, "AN-GROUP")
        row = self.db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate["candidate_id"],))
        self.assertEqual(row["precondition_state"], "complete")
        self.assertNotEqual(row["candidate_state"], "strong_candidate")
        trace = json.loads(row["reasoning_trace_json"])
        self.assertEqual(trace["evidence_lineage"]["support_roots"], 1)

    def test_distinct_source_can_support_promotion_while_correlated_types_cannot(self):
        support = [*self.facts(), dict(self.facts()[0], type="preview_operation")]
        self.candidate(support, candidate_id="C-ONE-SOURCE")
        other_source = dict(support[-1], source_group="independent_stored_observation")
        self.candidate([*support, other_source], candidate_id="C-TWO-SOURCES")
        with patch("security_reasoning._synthetic_evidence", return_value=([], [])):
            apply_security_reasoning(self.db, "AN-GROUP")
        first = self.db.one("SELECT * FROM bug_candidates WHERE candidate_id='C-ONE-SOURCE'")
        second = self.db.one("SELECT * FROM bug_candidates WHERE candidate_id='C-TWO-SOURCES'")
        self.assertGreaterEqual(first["calibrated_likelihood"], 76)
        self.assertNotEqual(first["candidate_state"], "strong_candidate")
        self.assertEqual(second["candidate_state"], "strong_candidate")
        self.assertEqual(first["precondition_state"], "complete")
        self.assertEqual(second["precondition_state"], "complete")

    def test_extra_irrelevant_correlated_facts_do_not_inflate_scores(self):
        base = self.facts()
        self.candidate(base, candidate_id="C-BASE")
        extra = [dict(base[0], type=f"context_{i}", text=f"Correlated context {i}") for i in range(8)]
        self.candidate([*base, *extra], candidate_id="C-EXTRA")
        with patch("security_reasoning._synthetic_evidence", return_value=([], [])):
            apply_security_reasoning(self.db, "AN-GROUP")
        scores = [tuple(row) for row in self.db.all(
            "SELECT calibrated_likelihood,evidence_strength,exploitability_confidence,observation_quality "
            "FROM bug_candidates WHERE analysis_id='AN-GROUP' ORDER BY candidate_id"
        )]
        self.assertEqual(scores[0], scores[1])

    def test_correlated_contradiction_repetition_is_not_counted_as_independent(self):
        negative = {"type": "host_allowlist", "source_group": "stored_control", "weight": -30,
                    "text": "Stored destination control"}
        extra = [dict(negative, type=f"control_context_{i}", text=f"Correlated control context {i}") for i in range(8)]
        self.candidate(self.facts(), [negative], candidate_id="C-BASE")
        self.candidate(self.facts(), [negative, *extra], candidate_id="C-EXTRA")
        with patch("security_reasoning._synthetic_evidence", return_value=([], [])):
            apply_security_reasoning(self.db, "AN-GROUP")
        scores = [tuple(row) for row in self.db.all(
            "SELECT calibrated_likelihood,evidence_strength,exploitability_confidence,observation_quality "
            "FROM bug_candidates WHERE analysis_id='AN-GROUP' ORDER BY candidate_id"
        )]
        self.assertEqual(scores[0], scores[1])
        candidate = self.db.one("SELECT contradicting_evidence_json FROM bug_candidates WHERE candidate_id='C-EXTRA'")
        self.assertEqual(len(json.loads(candidate[0])), 9)

    def test_previous_rule_cache_is_retained_but_not_reused(self):
        candidate = self.candidate(self.facts())
        with patch("security_reasoning._synthetic_evidence", return_value=([], [])):
            with patch("security_reasoning.REASONING_RULE_VERSION", "2026.08.8.4"):
                apply_security_reasoning(self.db, "AN-GROUP")
            apply_security_reasoning(self.db, "AN-GROUP")
        row = self.db.one("SELECT reasoning_trace_json,rule_version FROM bug_candidates WHERE candidate_id=?", (candidate["candidate_id"],))
        self.assertEqual(row["rule_version"], REASONING_RULE_VERSION)
        self.assertFalse(json.loads(row["reasoning_trace_json"]).get("cache", {}).get("reused", False))
        self.assertEqual({x[0] for x in self.db.all("SELECT rule_version FROM incremental_reasoning_cache")},
                         {"2026.08.8.4", REASONING_RULE_VERSION})

    def test_full_analysis_keeps_required_coverage_and_old_analysis_evidence(self):
        endpoint = "https://example.test/api/preview?url=https://controlled.invalid/"
        details = {
            "method": "GET", "status_code": 200, "query_parameters": ["url"],
            "ssrf_runtime_observations": [{
                "server_fetch_observed": True, "user_controlled_destination": True,
                "execution_location": "server", "requested_destination": "https://controlled.invalid/",
            }],
        }
        self.db.upsert_alert("example.test", "fetch-grouping", "new_endpoint", "HIGH", 90,
                             "Remote preview endpoint", endpoint, details, "RUN-GROUP")
        observed = []
        original = analysis_engine.enhance_candidates

        def capture(db, analysis_id, profile):
            row = db.one("SELECT supporting_evidence_json FROM bug_candidates WHERE analysis_id=? AND bug_family='ssrf'", (analysis_id,))
            self.assertIsNotNone(row)
            support = json.loads(row[0])
            observed.append((support, _schema_assessment("ssrf", support, [], [])))
            return original(db, analysis_id, profile)

        with patch.object(analysis_engine, "enhance_candidates", side_effect=capture):
            result = run_analysis(self.paths, self.db, "RUN-GROUP", "example.test")
        row = self.db.one("SELECT * FROM bug_candidates WHERE analysis_id=? AND bug_family='ssrf'", (result["analysis_id"],))
        self.assertEqual(observed[0][1]["required_coverage"], 100)
        support = json.loads(row["supporting_evidence_json"])
        self.assertTrue({x["type"] for x in observed[0][0]} <= {x["type"] for x in support})
        trace = json.loads(row["reasoning_trace_json"])
        self.assertEqual(trace["preconditions"]["required_coverage"], 100)
        self.assertEqual(row["precondition_state"], "complete")
        self.assertNotEqual(row["candidate_state"], "insufficient_evidence")
        self.assertNotEqual(row["candidate_state"], "confirmed_by_analyst")
        dossier = build_evidence_dossier(self.db, row["candidate_id"])
        self.assertTrue(dossier["supporting"])
        self.assertTrue(all(x["snapshot_verified"] for x in dossier["supporting"]))
        previous = [tuple(x) for x in self.db.all("SELECT evidence_id,snapshot_hash,snapshot_json FROM candidate_evidence_snapshots WHERE candidate_id=? ORDER BY evidence_id", (row["candidate_id"],))]
        run_analysis(self.paths, self.db, "RUN-GROUP", "example.test")
        self.assertEqual(previous, [tuple(x) for x in self.db.all("SELECT evidence_id,snapshot_hash,snapshot_json FROM candidate_evidence_snapshots WHERE candidate_id=? ORDER BY evidence_id", (row["candidate_id"],))])


if __name__ == "__main__":
    unittest.main()
