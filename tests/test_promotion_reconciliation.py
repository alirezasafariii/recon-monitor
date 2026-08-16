from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from bug_candidates import BUG_FAMILIES, _insert_candidate, set_bug_candidate_decision
from core import AppPaths, Database, utc_now
from hypothesis_admission import mark_promoted, record_hypothesis


class PromotionReconciliationTests(unittest.TestCase):
    def make_analysis(self, td: str):
        paths = AppPaths.from_root(Path(td))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('run-reconcile','8.6.0','success',?,?,?,1)",
            (now, now, "example.com"),
        )
        result = run_analysis(paths, db, "run-reconcile", "example.com")
        return paths, db, result["analysis_id"]

    @staticmethod
    def initial_support():
        return [
            {
                "type": "url_parameter",
                "source": "schema",
                "source_group": "schema",
                "weight": 12,
                "text": "Remote URL input is stored on the target surface.",
            },
            {
                "type": "server_fetch_semantic",
                "source": "semantic",
                "source_group": "semantic",
                "weight": 16,
                "text": "The operation has server-side fetch semantics.",
            },
            {
                "type": "server_fetch_observed",
                "source": "stored_response",
                "source_group": "stored_response",
                "weight": 28,
                "text": "Stored target evidence indicates a server-side fetch occurred.",
            },
        ]

    def promote_ssrf(self, db: Database, analysis_id: str):
        endpoint = "https://example.com/api/preview?url=https://controlled.invalid/"
        hypothesis = record_hypothesis(
            db,
            analysis_id=analysis_id,
            source_run_id="run-reconcile",
            target="example.com",
            alert_id=None,
            asset="example.com",
            endpoint=endpoint,
            source_ref="reconcile:ssrf",
            family="ssrf",
            variant="server_fetch",
            support=self.initial_support(),
            contradict=[],
            missing=["Destination policy behavior"],
            rule_ids=["test-promotion-reconciliation"],
            summary="Stored target evidence supports a server-side fetch candidate.",
        )
        self.assertTrue(hypothesis["assessment"]["admitted"])
        candidate_id = _insert_candidate(
            db,
            analysis_id=analysis_id,
            source_run_id="run-reconcile",
            target="example.com",
            alert_id=None,
            asset="example.com",
            endpoint=endpoint,
            source_ref="reconcile:ssrf",
            family="ssrf",
            variant="server_fetch",
            likelihood=82,
            evidence_strength=76,
            impact_potential=BUG_FAMILIES["ssrf"]["impact"],
            support=list(hypothesis["support"]),
            contradict=[],
            missing=list(hypothesis["missing"]),
            rule_ids=list(hypothesis["rule_ids"]),
            summary="Stored target evidence supports a server-side fetch candidate.",
        )
        mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)
        return endpoint, hypothesis["hypothesis_fingerprint"], candidate_id

    def add_blocking_contradiction(self, db: Database, analysis_id: str, endpoint: str):
        return record_hypothesis(
            db,
            analysis_id=analysis_id,
            source_run_id="run-reconcile",
            target="example.com",
            alert_id=None,
            asset="example.com",
            endpoint=endpoint,
            source_ref="reconcile:ssrf",
            family="ssrf",
            variant="server_fetch",
            support=[],
            contradict=[
                {
                    "type": "server_fetch_not_observed",
                    "source": "controlled_validation",
                    "source_group": "controlled_validation",
                    "weight": -30,
                    "text": "Controlled target evidence did not reproduce a server-side fetch.",
                }
            ],
            missing=["Resolve contradictory server-fetch observations"],
            rule_ids=["test-promotion-reconciliation-contradiction"],
            summary="New target evidence contradicts the previous automatic promotion.",
        )

    def test_unreviewed_promotion_requires_revalidation_and_can_be_restored(self):
        with tempfile.TemporaryDirectory() as td:
            _, db, analysis_id = self.make_analysis(td)
            try:
                endpoint, fingerprint, candidate_id = self.promote_ssrf(db, analysis_id)
                demoted = self.add_blocking_contradiction(db, analysis_id, endpoint)
                self.assertFalse(demoted["assessment"]["admitted"])
                self.assertEqual(demoted["assessment"]["state"], "shadow_contradicted")
                reconciliation = demoted["assessment"]["promotion_reconciliation"]
                self.assertEqual(reconciliation["status"], "needs_revalidation")

                hypothesis_row = db.one(
                    "SELECT state,promoted_candidate_id,admission_json FROM analysis_hypotheses "
                    "WHERE analysis_id=? AND hypothesis_fingerprint=?",
                    (analysis_id, fingerprint),
                )
                self.assertEqual(hypothesis_row["state"], "shadow_contradicted")
                self.assertEqual(hypothesis_row["promoted_candidate_id"], candidate_id)
                candidate = db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate_id,))
                self.assertEqual(candidate["candidate_state"], "needs_revalidation")
                self.assertEqual(candidate["analyst_decision"], "unreviewed")
                contradiction_types = {
                    item.get("type")
                    for item in json.loads(candidate["contradicting_evidence_json"])
                }
                self.assertIn("server_fetch_not_observed", contradiction_types)

                restored = record_hypothesis(
                    db,
                    analysis_id=analysis_id,
                    source_run_id="run-reconcile",
                    target="example.com",
                    alert_id=None,
                    asset="example.com",
                    endpoint=endpoint,
                    source_ref="reconcile:ssrf",
                    family="ssrf",
                    variant="server_fetch",
                    support=[
                        {
                            "type": "destination_policy_bypass_observed",
                            "source": "controlled_validation",
                            "source_group": "policy_validation",
                            "weight": 30,
                            "text": "Controlled target evidence establishes a destination policy bypass.",
                        }
                    ],
                    contradict=[],
                    missing=[],
                    rule_ids=["test-promotion-reconciliation-restore"],
                    summary="Stronger target evidence restores canonical admission.",
                )
                self.assertTrue(restored["assessment"]["admitted"])
                self.assertEqual(
                    restored["assessment"]["promotion_reconciliation"]["status"],
                    "admission_restored",
                )
                hypothesis_row = db.one(
                    "SELECT state FROM analysis_hypotheses WHERE analysis_id=? AND hypothesis_fingerprint=?",
                    (analysis_id, fingerprint),
                )
                self.assertEqual(hypothesis_row["state"], "promoted")
                candidate = db.one("SELECT candidate_state FROM bug_candidates WHERE candidate_id=?", (candidate_id,))
                self.assertEqual(candidate["candidate_state"], "strong_candidate")
            finally:
                db.close()

    def test_analyst_confirmation_is_preserved_but_hypothesis_reflects_contradiction(self):
        with tempfile.TemporaryDirectory() as td:
            _, db, analysis_id = self.make_analysis(td)
            try:
                endpoint, fingerprint, candidate_id = self.promote_ssrf(db, analysis_id)
                set_bug_candidate_decision(
                    db,
                    candidate_id,
                    "confirmed_by_analyst",
                    "Confirmed using authorized test infrastructure.",
                    actor="test",
                )
                result = self.add_blocking_contradiction(db, analysis_id, endpoint)
                self.assertFalse(result["assessment"]["admitted"])
                self.assertEqual(
                    result["assessment"]["promotion_reconciliation"]["status"],
                    "analyst_confirmation_preserved",
                )
                hypothesis_row = db.one(
                    "SELECT state,promoted_candidate_id FROM analysis_hypotheses "
                    "WHERE analysis_id=? AND hypothesis_fingerprint=?",
                    (analysis_id, fingerprint),
                )
                self.assertEqual(hypothesis_row["state"], "shadow_contradicted")
                self.assertEqual(hypothesis_row["promoted_candidate_id"], candidate_id)
                candidate = db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate_id,))
                self.assertEqual(candidate["analyst_decision"], "confirmed_by_analyst")
                self.assertEqual(candidate["candidate_state"], "confirmed_by_analyst")
                self.assertIn("authorized test infrastructure", candidate["analyst_note"])
                contradiction_types = {
                    item.get("type")
                    for item in json.loads(candidate["contradicting_evidence_json"])
                }
                self.assertIn("server_fetch_not_observed", contradiction_types)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
