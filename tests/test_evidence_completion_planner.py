from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from evidence_completion_planner import snapshot_evidence_completion_plan
from family_reasoning import FAMILY_REASONING


class FakeDB:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def all(self, sql, params=()):
        if "FROM analysis_hypotheses" not in sql:
            return []
        analysis_id, target = params
        return [
            row
            for row in self.rows
            if row.get("analysis_id") == analysis_id and row.get("target") == target
        ]


def evidence(signal: str, source_group: str, *, family_scope: str = ""):
    row = {"type": signal, "source_group": source_group, "text": signal}
    if family_scope:
        row["family_scope"] = family_scope
    return row


def hypothesis(
    family: str,
    *,
    state: str = "shadow_partial",
    admitted: bool = False,
    support=(),
    contradict=(),
    hypothesis_id: str = "H-1",
):
    blocking = sorted(
        set(FAMILY_REASONING[family].get("blocking_contradictions", ()))
        & {str(item.get("type") or "") for item in contradict}
    )
    return {
        "hypothesis_id": hypothesis_id,
        "analysis_id": "A-1",
        "target": "example.test",
        "bug_family": family,
        "state": state,
        "summary": f"{family} hypothesis",
        "asset": "app.example.test",
        "endpoint": "https://app.example.test/api/test",
        "supporting_evidence_json": json.dumps(list(support)),
        "contradicting_evidence_json": json.dumps(list(contradict)),
        "missing_evidence_json": json.dumps(["stored gap"]),
        "admission_json": json.dumps(
            {
                "admitted": admitted,
                "blocking_contradictions": blocking,
                "validation_level": FAMILY_REASONING[family]["validation_level"],
            }
        ),
    }


def signal(name: str, *, dimensions=(), collection="complete", status="not_observed"):
    return {
        "signal": name,
        "status": status,
        "support_count": 1 if status == "observed" else 0,
        "contradict_count": 0,
        "collection_dimensions": list(dimensions),
        "collection_status": {dimension: collection for dimension in dimensions},
        "reason": status,
    }


def group(*rows, status="unknown"):
    return {
        "status": status,
        "signals": list(rows),
        "support_observed": [
            row["signal"] for row in rows if row.get("status") == "observed"
        ],
        "reason": status,
    }


def family_coverage(
    family: str,
    *,
    promotion=(),
    confirmation=(),
    blocking=(),
    overrides=(),
):
    return {
        "label": FAMILY_REASONING[family]["label"],
        "category": FAMILY_REASONING[family]["category"],
        "promotion_required": list(promotion),
        "confirmation_required": list(confirmation),
        "blocking_contradictions": list(blocking),
        "override_signals": list(overrides),
        "validation_level": FAMILY_REASONING[family]["validation_level"],
    }


def coverage(family: str, family_row):
    return {"version": "1.0.0", "families": {family: family_row}}


def make_ctx(root: Path, rows=()):
    run_dir = root / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        db=FakeDB(rows),
        run_id="RUN-1",
        run_dir=run_dir,
        policy=SimpleNamespace(name="example.test"),
    )


def plan_for(result, hypothesis_id="H-1"):
    return next(plan for plan in result["plans"] if plan["hypothesis_id"] == hypothesis_id)


class EvidenceCompletionPlannerTests(unittest.TestCase):
    def test_passive_collection_gap_recommends_recollection_only(self):
        family = "ssrf"
        row = hypothesis(
            family,
            support=[evidence("url_parameter", "endpoint")],
        )
        family_row = family_coverage(
            family,
            promotion=[
                group(signal("url_parameter", dimensions=("urls",), status="observed"), status="observed"),
                group(
                    signal(
                        "server_request_function",
                        dimensions=("javascript",),
                        collection="partial",
                        status="not_collected",
                    ),
                    status="not_collected",
                ),
                group(signal("server_fetch_observed"), status="unknown"),
            ],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertEqual(plan["gap_type"], "passive_collection_gap")
        self.assertEqual(plan["recommended_action"], "repeat_passive_collection")
        self.assertEqual(plan["missing_collection_dimensions"], ["javascript"])
        self.assertFalse(plan["active_action_required"])
        self.assertFalse(plan["safe_to_execute_automatically"])
        self.assertIsNone(plan["execution_payload"])

    def test_controlled_family_unknown_gap_requires_authorized_preparation(self):
        family = "broken_object_authorization"
        row = hypothesis(family)
        family_row = family_coverage(
            family,
            promotion=[group(signal("cross_identity_object_access"), status="observed")],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertEqual(plan["gap_type"], "controlled_validation_needed")
        self.assertEqual(plan["recommended_action"], "prepare_controlled_validation")
        self.assertTrue(plan["active_action_required"])
        self.assertTrue(plan["live_target_interaction_required"])
        self.assertTrue(plan["authorization_required"])
        self.assertFalse(plan["executor_enabled"])

    def test_passive_live_family_becomes_behavioral_validation_needed(self):
        family = "authentication_session"
        row = hypothesis(family)
        family_row = family_coverage(
            family,
            promotion=[group(signal("authentication_state_violation"), status="unknown")],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertEqual(plan["gap_type"], "behavioral_validation_needed")
        self.assertEqual(plan["recommended_action"], "prepare_passive_live_validation")
        self.assertFalse(plan["active_action_required"])
        self.assertTrue(plan["authorization_required"])

    def test_manual_only_unknown_gap_stays_with_analyst(self):
        family = "ssrf"
        row = hypothesis(family)
        family_row = family_coverage(
            family,
            promotion=[group(signal("server_fetch_observed"), status="unknown")],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertEqual(FAMILY_REASONING[family]["validation_level"], "manual_only")
        self.assertEqual(plan["gap_type"], "analyst_review_needed")
        self.assertEqual(plan["recommended_action"], "manual_evidence_review")
        self.assertFalse(plan["live_target_interaction_required"])

    def test_contradiction_takes_precedence_over_completion(self):
        family = "broken_object_authorization"
        contradiction = "cross_context_denied"
        row = hypothesis(
            family,
            state="shadow_contradicted",
            contradict=[evidence(contradiction, "behavior")],
        )
        family_row = family_coverage(
            family,
            blocking=[signal(contradiction, status="observed")],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertEqual(plan["gap_type"], "contradictory_evidence_present")
        self.assertEqual(plan["recommended_action"], "review_contradictory_evidence")
        self.assertIn(contradiction, plan["blocking_contradictions"])
        self.assertFalse(plan["active_action_required"])

    def test_admitted_hypothesis_plans_confirmation_not_promotion(self):
        family = "broken_object_authorization"
        row = hypothesis(family, state="admitted", admitted=True)
        family_row = family_coverage(
            family,
            confirmation=[group(signal("unauthorized_object_response"), status="unknown")],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertEqual(plan["planning_phase"], "confirmation")
        self.assertEqual(plan["gap_type"], "controlled_validation_needed")

    def test_canonical_guidance_is_reused_without_policy_duplication(self):
        family = "broken_object_authorization"
        row = hypothesis(family)
        family_row = family_coverage(
            family,
            promotion=[
                group(signal("object_identifier", dimensions=("urls",), status="not_observed"), status="not_observed")
            ],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertEqual(plan["next_evidence"], list(FAMILY_REASONING[family]["next_evidence"]))
        self.assertEqual(
            [item["key"] for item in plan["case_requirements"]],
            [item["key"] for item in FAMILY_REASONING[family]["case_requirements"]],
        )
        first_group = plan["missing_evidence_groups"][0]
        object_row = next(
            item for item in first_group["alternatives"] if item["signal"] == "object_identifier"
        )
        self.assertEqual(object_row["status"], "not_observed")

    def test_sibling_hypothesis_evidence_cannot_fill_this_hypothesis(self):
        family = "broken_object_authorization"
        complete_support = [
            evidence("object_identifier", "endpoint"),
            evidence("object_operation", "operation"),
            evidence("cross_identity_object_access", "behavior"),
        ]
        h1 = hypothesis(family, hypothesis_id="H-1", support=complete_support)
        h2 = hypothesis(
            family,
            hypothesis_id="H-2",
            support=[evidence("object_operation", "operation")],
        )
        family_row = family_coverage(
            family,
            promotion=[
                group(signal("object_identifier", dimensions=("urls",), status="observed"), status="observed"),
                group(signal("object_operation", dimensions=("urls",), status="observed"), status="observed"),
                group(signal("cross_identity_object_access", status="observed"), status="observed"),
            ],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [h1, h2]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan2 = plan_for(result, "H-2")
        missing_signals = {
            item["signal"]
            for gap in plan2["missing_evidence_groups"]
            for item in gap["alternatives"]
        }
        self.assertIn("object_identifier", missing_signals)
        self.assertIn("cross_identity_object_access", missing_signals)
        self.assertIn("sibling hypotheses", result["isolation_semantics"])

    def test_independent_source_requirement_is_planned_explicitly(self):
        family = "broken_object_authorization"
        same_source = "single-source"
        support = [
            evidence("object_identifier", same_source),
            evidence("object_operation", same_source),
            evidence("cross_identity_object_access", same_source),
        ]
        row = hypothesis(family, support=support)
        family_row = family_coverage(
            family,
            promotion=[
                group(signal("object_identifier", dimensions=("urls",), status="observed"), status="observed"),
                group(signal("object_operation", dimensions=("urls",), status="observed"), status="observed"),
                group(signal("cross_identity_object_access", status="observed"), status="observed"),
            ],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertEqual(plan["independent_sources"], 1)
        self.assertEqual(plan["min_independent_sources"], FAMILY_REASONING[family]["min_independent_sources"])
        self.assertGreater(plan["independent_source_gap"], 0)
        self.assertEqual(plan["gap_type"], "independent_source_needed")
        self.assertEqual(plan["recommended_action"], "seek_independent_evidence_source")

    def test_cross_family_sources_are_quarantined_before_source_counting(self):
        family = "broken_object_authorization"
        support = [
            evidence("object_identifier", "local", family_scope=family),
            evidence("object_operation", "local", family_scope=family),
            evidence("cross_identity_object_access", "local", family_scope=family),
            evidence("object_identifier", "foreign-a", family_scope="ssrf"),
            evidence("object_operation", "foreign-b", family_scope="ssrf"),
        ]
        row = hypothesis(family, support=support)
        family_row = family_coverage(
            family,
            promotion=[
                group(signal("object_identifier", dimensions=("urls",), status="observed"), status="observed"),
                group(signal("object_operation", dimensions=("urls",), status="observed"), status="observed"),
                group(signal("cross_identity_object_access", status="observed"), status="observed"),
            ],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertEqual(plan["independent_sources"], 1)
        self.assertEqual(plan["source_groups"], ["local"])
        self.assertEqual(plan["evidence_scope"]["support"]["rejected_cross_family_count"], 2)
        self.assertEqual(plan["gap_type"], "independent_source_needed")

    def test_override_signal_prevents_blocking_contradiction_from_forcing_stop(self):
        family = "broken_object_authorization"
        contradiction = "cross_context_denied"
        override = "cross_identity_object_access"
        row = hypothesis(
            family,
            support=[
                evidence("object_identifier", "endpoint"),
                evidence("object_operation", "operation"),
                evidence(override, "behavior"),
            ],
            contradict=[evidence(contradiction, "behavior")],
        )
        family_row = family_coverage(
            family,
            blocking=[signal(contradiction, status="observed")],
            overrides=[signal(override, status="observed")],
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_evidence_completion_plan(
                make_ctx(Path(td), [row]),
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=False,
            )
        plan = plan_for(result)
        self.assertIn(contradiction, plan["blocking_contradictions"])
        self.assertIn(override, plan["override_signals_observed"])
        self.assertNotEqual(plan["gap_type"], "contradictory_evidence_present")

    def test_snapshot_persists_and_guardrails_are_global(self):
        family = "ssrf"
        row = hypothesis(family)
        family_row = family_coverage(family)
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td), [row])
            result = snapshot_evidence_completion_plan(
                ctx,
                analysis_id="A-1",
                evidence_coverage=coverage(family, family_row),
                persist=True,
            )
            output = Path(result["output"])
            self.assertTrue(output.exists())
            saved = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(saved["analysis_id"], "A-1")
        self.assertTrue(saved["diagnostic_only"])
        self.assertFalse(saved["affects_admission"])
        self.assertFalse(saved["affects_candidate_promotion"])
        self.assertFalse(saved["executes_validation"])
        self.assertIsNone(saved["numeric_score"])


if __name__ == "__main__":
    unittest.main()
