from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    if old not in text:
        raise SystemExit(f"missing patch marker: {label}")
    return text.replace(old, new, 1)


# 1) Candidate state contract: automatic promotions may be demoted to a
# revalidation-required state without overwriting analyst decisions.
legacy = Path("app/bug_candidates_legacy_core.py")
legacy_text = legacy.read_text(encoding="utf-8")
legacy_text = replace_once(
    legacy_text,
    'AUTO_STATES = ("weak_signal", "possible", "plausible", "strong_candidate")',
    'AUTO_STATES = ("weak_signal", "possible", "plausible", "strong_candidate", "needs_revalidation")',
    label="AUTO_STATES",
)
legacy.write_text(legacy_text, encoding="utf-8")


# 2) Hypothesis/candidate lifecycle reconciliation.
admission = Path("app/hypothesis_admission.py")
admission_text = admission.read_text(encoding="utf-8")
helper = r'''

def _candidate_auto_state(likelihood_score: Any, evidence_strength: Any) -> str:
    try:
        likelihood = int(likelihood_score or 0)
    except (TypeError, ValueError):
        likelihood = 0
    try:
        strength = int(evidence_strength or 0)
    except (TypeError, ValueError):
        strength = 0
    if likelihood >= 75 and strength >= 60:
        return "strong_candidate"
    if likelihood >= 55:
        return "plausible"
    if likelihood >= 35:
        return "possible"
    return "weak_signal"


def _reconcile_promoted_candidate(
    db: Database,
    *,
    candidate_id: str,
    assessment: Mapping[str, Any],
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]],
    missing: Iterable[str],
) -> dict[str, Any]:
    """Reconcile a historical promotion with the latest canonical admission.

    Automatic admission may be revoked by newly stored target contradictions.
    The candidate remains linked for audit/history, but an unreviewed automatic
    candidate becomes ``needs_revalidation``. Explicit analyst decisions are
    never overwritten by this automatic reconciliation path.
    """
    row = db.one(
        "SELECT candidate_state,analyst_decision,likelihood_score,evidence_strength,"
        "supporting_evidence_json,contradicting_evidence_json,missing_evidence_json "
        "FROM bug_candidates WHERE candidate_id=?",
        (candidate_id,),
    )
    if not row:
        return {
            "status": "candidate_missing",
            "candidate_id": candidate_id,
            "admitted": bool(assessment.get("admitted")),
        }

    current_state = str(row["candidate_state"] or "")
    analyst_decision = str(row["analyst_decision"] or "unreviewed")
    admitted = bool(assessment.get("admitted"))
    merged_support = _merge(
        [*_loads(row["supporting_evidence_json"], []), *[dict(item) for item in support]]
    )
    merged_contradict = _merge(
        [*_loads(row["contradicting_evidence_json"], []), *[dict(item) for item in contradict]]
    )
    merged_missing = list(
        dict.fromkeys(
            [
                *[str(item) for item in _loads(row["missing_evidence_json"], []) if str(item).strip()],
                *[str(item) for item in missing if str(item).strip()],
            ]
        )
    )

    next_state = current_state
    status = "admission_valid" if admitted else "needs_revalidation"
    if admitted:
        if current_state == "needs_revalidation" and analyst_decision in {"unreviewed", "needs_more_evidence"}:
            next_state = _candidate_auto_state(row["likelihood_score"], row["evidence_strength"])
            status = "admission_restored"
    elif analyst_decision == "confirmed_by_analyst":
        next_state = "confirmed_by_analyst"
        status = "analyst_confirmation_preserved"
    elif analyst_decision in {"rejected", "duplicate", "out_of_scope"}:
        status = "analyst_terminal_decision_preserved"
    else:
        next_state = "needs_revalidation"

    if not admitted:
        reason = str(assessment.get("reason") or "").strip()
        if reason:
            marker = f"Canonical admission requires revalidation: {reason}"
            if marker not in merged_missing:
                merged_missing.append(marker)

    db.execute(
        "UPDATE bug_candidates SET candidate_state=?,supporting_evidence_json=?,"
        "contradicting_evidence_json=?,missing_evidence_json=?,updated_at=? WHERE candidate_id=?",
        (
            next_state,
            json_dumps(merged_support),
            json_dumps(merged_contradict),
            json_dumps(merged_missing),
            utc_now(),
            candidate_id,
        ),
    )
    return {
        "status": status,
        "candidate_id": candidate_id,
        "admitted": admitted,
        "candidate_state_before": current_state,
        "candidate_state_after": next_state,
        "analyst_decision": analyst_decision,
        "analyst_decision_preserved": True,
    }
'''
if "def _reconcile_promoted_candidate(" not in admission_text:
    admission_text = replace_once(
        admission_text,
        "\ndef record_hypothesis(\n",
        helper + "\ndef record_hypothesis(\n",
        label="record_hypothesis insertion",
    )

old_state = '    state = "promoted" if promoted_candidate_id else assessment["state"]\n'
new_state = '''    if promoted_candidate_id:\n        assessment["promotion_reconciliation"] = _reconcile_promoted_candidate(\n            db,\n            candidate_id=promoted_candidate_id,\n            assessment=assessment,\n            support=support,\n            contradict=contradict,\n            missing=missing,\n        )\n    state = (\n        "promoted"\n        if promoted_candidate_id and bool(assessment.get("admitted"))\n        else assessment["state"]\n    )\n'''
admission_text = replace_once(
    admission_text,
    old_state,
    new_state,
    label="sticky promoted state",
)
admission.write_text(admission_text, encoding="utf-8")


# 3) Dedicated regression coverage for automatic revocation/restoration and
# preservation of explicit analyst confirmation.
test = Path("tests/test_promotion_reconciliation.py")
test.write_text(
    r'''from __future__ import annotations

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
''',
    encoding="utf-8",
)
