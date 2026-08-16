from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import TargetPolicy
from validation_eligibility import snapshot_validation_eligibility


class FakeConfig:
    def __init__(self, *, authorized=True, active_globally_enabled=True):
        self.authorized = authorized
        self.active_globally_enabled = active_globally_enabled


class FakeBudget:
    def __init__(self, *, used=1, limit=100, runtime_blocked=False):
        self.used = used
        self.limit = limit
        self.runtime_blocked = runtime_blocked

    def snapshot(self):
        return {"http_requests": {"used": self.used, "limit": self.limit}}

    def check_runtime(self):
        if self.runtime_blocked:
            raise RuntimeError("runtime exhausted")


def make_policy(*, confirmation=True, validation_context=None):
    return TargetPolicy.from_dict(
        {
            "name": "example.test",
            "roots": ["example.test"],
            "include": [r"(^|\.)example\.test$"],
            "active": {
                "confirmation": (
                    "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING" if confirmation else ""
                ),
                "validation_context": dict(validation_context or {}),
            },
        }
    )


def make_ctx(
    root: Path,
    *,
    authorized=True,
    global_active=True,
    cli_allow=True,
    confirmation=True,
    validation_context=None,
    budget=None,
):
    run_dir = root / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        run_id="RUN-1",
        run_dir=run_dir,
        policy=make_policy(
            confirmation=confirmation,
            validation_context=validation_context,
        ),
        config=FakeConfig(
            authorized=authorized,
            active_globally_enabled=global_active,
        ),
        allow_active=cli_allow,
        budget=budget or FakeBudget(),
        db=None,
    )


def req(*keys):
    return [
        {"key": key, "label": key, "why": f"need {key}"}
        for key in keys
    ]


def plan(
    *,
    hypothesis_id="H-1",
    family="broken_object_authorization",
    gap_type="controlled_validation_needed",
    validation_level="controlled",
    endpoint="https://api.example.test/orders/1",
    asset="api.example.test",
    case_requirements=(),
    source_groups=("endpoint", "behavior"),
    live=True,
):
    return {
        "hypothesis_id": hypothesis_id,
        "family": family,
        "planning_phase": "promotion",
        "gap_type": gap_type,
        "validation_level": validation_level,
        "recommended_action": "prepare_controlled_validation",
        "endpoint": endpoint,
        "asset": asset,
        "case_requirements": list(case_requirements),
        "source_groups": list(source_groups),
        "independent_sources": len(source_groups),
        "live_target_interaction_required": live,
        "authorization_required": live,
    }


def planner(*plans):
    return {
        "version": "1.0.0",
        "analysis_id": "A-1",
        "plans": list(plans),
    }


def decision(result, hypothesis_id="H-1"):
    return next(
        row for row in result["decisions"]
        if row["hypothesis_id"] == hypothesis_id
    )


class ValidationEligibilityTests(unittest.TestCase):
    def test_non_live_plan_is_ineligible_for_runner(self):
        item = plan(
            gap_type="passive_collection_gap",
            validation_level="controlled",
            live=False,
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(Path(td)),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        row = decision(result)
        self.assertEqual(row["status"], "ineligible")
        self.assertFalse(row["eligible_for_runner_consideration"])

    def test_manual_only_contract_stays_manual_only(self):
        item = plan(validation_level="manual_only")
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(Path(td)),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        row = decision(result)
        self.assertEqual(row["status"], "manual_only")
        self.assertIn(
            "canonical_validation_level_manual_only",
            row["blocking_reasons"],
        )

    def test_outside_scope_wins_before_authorization(self):
        item = plan(endpoint="https://outside.example.org/orders/1")
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(Path(td), authorized=False),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        row = decision(result)
        self.assertEqual(row["status"], "outside_scope")
        self.assertFalse(row["scope"]["effective_in_scope"])

    def test_missing_surface_fails_closed_as_context_missing(self):
        item = plan(endpoint="", asset="")
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(Path(td)),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        row = decision(result)
        self.assertEqual(row["status"], "context_missing")
        self.assertIn("validation_surface_missing", row["blocking_reasons"])

    def test_existing_active_authorization_gates_are_reused(self):
        item = plan(case_requirements=req("endpoint", "evidence"))
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(Path(td), global_active=False),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        row = decision(result)
        self.assertEqual(row["status"], "authorization_missing")
        self.assertIn("ENABLE_ACTIVE_MODULES", row["authorization"]["missing_gates"])
        self.assertFalse(row["authorization"]["active_allowed"])

    def test_controlled_validation_requires_declared_case_context(self):
        item = plan(
            case_requirements=req(
                "authenticated_context",
                "second_identity",
                "ownership_map",
                "comparable_response",
            )
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(
                    Path(td),
                    validation_context={"authenticated_context": "test-account-a"},
                ),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        row = decision(result)
        self.assertEqual(row["status"], "context_missing")
        self.assertEqual(
            row["context"]["missing_keys"],
            ["comparable_response", "ownership_map", "second_identity"],
        )

    def test_eligible_means_runner_consideration_not_execution_permission(self):
        context = {
            "authenticated_context": "test-account-a",
            "second_identity": "test-account-b",
            "ownership_map": "test-owned-object-map",
            "comparable_response": True,
        }
        item = plan(case_requirements=req(*context.keys()))
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(Path(td), validation_context=context),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        row = decision(result)
        self.assertEqual(row["status"], "eligible")
        self.assertTrue(row["eligible_for_runner_consideration"])
        self.assertFalse(row["automatic_execution_allowed"])
        self.assertFalse(row["executor_enabled"])
        self.assertFalse(row["executes_validation"])
        self.assertIsNone(row["execution_payload"])

    def test_http_budget_exhaustion_blocks_eligibility_without_consuming(self):
        item = plan(case_requirements=req("endpoint", "evidence"))
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(Path(td), budget=FakeBudget(used=100, limit=100)),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        row = decision(result)
        self.assertEqual(row["status"], "budget_blocked")
        self.assertIn("http_requests:exhausted", row["budget"]["blocking_reasons"])
        self.assertFalse(row["budget"]["consumes_budget"])

    def test_runtime_budget_failure_blocks_eligibility(self):
        item = plan(case_requirements=req("endpoint", "evidence"))
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(Path(td), budget=FakeBudget(runtime_blocked=True)),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        row = decision(result)
        self.assertEqual(row["status"], "budget_blocked")
        self.assertFalse(row["budget"]["runtime_ok"])

    def test_passive_live_can_be_eligible_with_explicit_expected_behavior(self):
        item = plan(
            family="authentication_session",
            gap_type="behavioral_validation_needed",
            validation_level="passive_live",
            case_requirements=req("endpoint", "evidence", "expected_behavior"),
        )
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(
                    Path(td),
                    validation_context={"expected_behavior": "logout should invalidate"},
                ),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        self.assertEqual(decision(result)["status"], "eligible")

    def test_sensitive_context_values_are_never_serialized(self):
        secret = "SUPER-SECRET-TEST-CONTEXT"
        item = plan(case_requirements=req("authenticated_context"))
        with tempfile.TemporaryDirectory() as td:
            result = snapshot_validation_eligibility(
                make_ctx(
                    Path(td),
                    validation_context={"authenticated_context": secret},
                ),
                evidence_completion_plan=planner(item),
                persist=False,
            )
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret, encoded)
        self.assertIn("authenticated_context", encoded)
        self.assertTrue(decision(result)["context"]["values_redacted"])

    def test_snapshot_persists_and_global_guardrails_are_fail_closed(self):
        item = plan(case_requirements=req("endpoint", "evidence"))
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            result = snapshot_validation_eligibility(
                ctx,
                evidence_completion_plan=planner(item),
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
        self.assertFalse(saved["automatic_execution_allowed"])
        self.assertIsNone(saved["numeric_score"])


if __name__ == "__main__":
    unittest.main()
