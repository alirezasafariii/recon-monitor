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
from validation_runner import snapshot_validation_runner_dry_run


class FakeConfig:
    def __init__(self, *, authorized=True, active_globally_enabled=True):
        self.authorized = authorized
        self.active_globally_enabled = active_globally_enabled


class FakeBudget:
    def __init__(self, *, used=1, limit=100, runtime_blocked=False):
        self.used = used
        self.limit = limit
        self.runtime_blocked = runtime_blocked
        self.consume_calls = 0

    def snapshot(self):
        return {"http_requests": {"used": self.used, "limit": self.limit}}

    def check_runtime(self):
        if self.runtime_blocked:
            raise RuntimeError("runtime exhausted")

    def consume(self, *args, **kwargs):
        self.consume_calls += 1
        raise AssertionError("dry-run runner must never consume budget")


def make_policy(*, confirmation=True, validation_context=None, target="example.test"):
    escaped = target.replace(".", r"\.")
    return TargetPolicy.from_dict(
        {
            "name": target,
            "roots": [target],
            "include": [rf"(^|\.){escaped}$"],
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
    target="example.test",
):
    run_dir = root / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        run_id="RUN-1",
        run_dir=run_dir,
        policy=make_policy(
            confirmation=confirmation,
            validation_context=validation_context,
            target=target,
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
        "recommended_action": (
            "prepare_passive_live_validation"
            if validation_level == "passive_live"
            else "prepare_controlled_validation"
        ),
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


def eligible_snapshot(ctx, planner_snapshot):
    return snapshot_validation_eligibility(
        ctx,
        evidence_completion_plan=planner_snapshot,
        persist=False,
    )


def item(result, hypothesis_id="H-1"):
    return next(
        row for row in result["items"]
        if row["hypothesis_id"] == hypothesis_id
    )


def full_context():
    return {
        "authenticated_context": "test-account-a",
        "second_identity": "test-account-b",
        "ownership_map": "owned-object-map",
        "comparable_response": True,
    }


class ValidationRunnerDryRunTests(unittest.TestCase):
    def test_eligible_item_produces_non_executing_dry_run_contract(self):
        context = full_context()
        p = planner(plan(case_requirements=req(*context.keys())))
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td), validation_context=context)
            gate = eligible_snapshot(ctx, p)
            result = snapshot_validation_runner_dry_run(
                ctx,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        row = item(result)
        self.assertEqual(row["status"], "dry_run_ready")
        self.assertEqual(result["contract_count"], 1)
        contract = result["contracts"][0]
        self.assertEqual(contract["mode"], "dry_run_only")
        self.assertTrue(contract["human_approval_required"])
        self.assertFalse(contract["execution_enabled"])
        self.assertFalse(contract["executes_validation"])
        self.assertEqual(contract["network_requests_planned"], 0)
        self.assertEqual(contract["network_requests_executed"], 0)
        self.assertIsNone(contract["request_recipe"])
        self.assertIsNone(contract["network_request"])
        self.assertIsNone(contract["payload"])
        self.assertIsNone(contract["credentials"])
        self.assertIsNone(contract["transport"])
        self.assertIsNone(contract["budget_reservation"])

    def test_ineligible_item_is_skipped_without_contract(self):
        p = planner(
            plan(
                gap_type="passive_collection_gap",
                validation_level="controlled",
                live=False,
            )
        )
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            gate = eligible_snapshot(ctx, p)
            result = snapshot_validation_runner_dry_run(
                ctx,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        self.assertEqual(item(result)["status"], "skipped_not_eligible")
        self.assertEqual(result["contract_count"], 0)

    def test_authorization_revoked_after_gate_blocks_recheck(self):
        context = full_context()
        p = planner(plan(case_requirements=req(*context.keys())))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            initial = make_ctx(root, validation_context=context)
            gate = eligible_snapshot(initial, p)
            revoked = make_ctx(
                root,
                validation_context=context,
                global_active=False,
            )
            result = snapshot_validation_runner_dry_run(
                revoked,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        row = item(result)
        self.assertEqual(row["status"], "blocked_recheck")
        self.assertEqual(row["current_eligibility_status"], "authorization_missing")
        self.assertEqual(result["contract_count"], 0)

    def test_context_removed_after_gate_blocks_recheck(self):
        context = full_context()
        p = planner(plan(case_requirements=req(*context.keys())))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            initial = make_ctx(root, validation_context=context)
            gate = eligible_snapshot(initial, p)
            missing = make_ctx(root, validation_context={})
            result = snapshot_validation_runner_dry_run(
                missing,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        row = item(result)
        self.assertEqual(row["status"], "blocked_recheck")
        self.assertEqual(row["current_eligibility_status"], "context_missing")

    def test_budget_exhausted_after_gate_blocks_recheck(self):
        p = planner(plan(case_requirements=req("endpoint", "evidence")))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            initial = make_ctx(root, budget=FakeBudget(used=1, limit=2))
            gate = eligible_snapshot(initial, p)
            exhausted_budget = FakeBudget(used=2, limit=2)
            exhausted = make_ctx(root, budget=exhausted_budget)
            result = snapshot_validation_runner_dry_run(
                exhausted,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        row = item(result)
        self.assertEqual(row["status"], "blocked_recheck")
        self.assertEqual(row["current_eligibility_status"], "budget_blocked")
        self.assertEqual(exhausted_budget.consume_calls, 0)

    def test_scope_change_after_gate_blocks_recheck(self):
        p = planner(plan(case_requirements=req("endpoint", "evidence")))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            initial = make_ctx(root)
            gate = eligible_snapshot(initial, p)
            changed_scope = make_ctx(root, target="other.test")
            result = snapshot_validation_runner_dry_run(
                changed_scope,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        row = item(result)
        self.assertEqual(row["status"], "blocked_recheck")
        self.assertEqual(row["current_eligibility_status"], "outside_scope")

    def test_planner_gate_family_mismatch_fails_as_stale(self):
        p = planner(plan(case_requirements=req("endpoint", "evidence")))
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            gate = eligible_snapshot(ctx, p)
            gate["decisions"][0]["family"] = "authentication_session"
            result = snapshot_validation_runner_dry_run(
                ctx,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        row = item(result)
        self.assertEqual(row["status"], "stale_eligibility")
        self.assertEqual(result["contract_count"], 0)

    def test_query_and_fragment_are_redacted_from_contract(self):
        secret = "SUPER-SECRET-QUERY-VALUE"
        p = planner(
            plan(
                endpoint=f"https://api.example.test/orders/1?token={secret}#frag",
                case_requirements=req("endpoint", "evidence"),
            )
        )
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            gate = eligible_snapshot(ctx, p)
            result = snapshot_validation_runner_dry_run(
                ctx,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret, encoded)
        contract = result["contracts"][0]
        self.assertEqual(
            contract["surface"]["display"],
            "https://api.example.test/orders/1",
        )
        self.assertTrue(contract["surface"]["query_and_fragment_redacted"])

    def test_passive_live_ready_contract_is_still_human_review_only(self):
        p = planner(
            plan(
                family="authentication_session",
                gap_type="behavioral_validation_needed",
                validation_level="passive_live",
                case_requirements=req("endpoint", "evidence", "expected_behavior"),
            )
        )
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(
                Path(td),
                validation_context={"expected_behavior": "expected logout semantics"},
            )
            gate = eligible_snapshot(ctx, p)
            result = snapshot_validation_runner_dry_run(
                ctx,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        contract = result["contracts"][0]
        self.assertEqual(contract["operation_class"], "passive_live_observation_review")
        self.assertTrue(contract["human_approval_required"])
        self.assertFalse(contract["automatic_execution_allowed"])

    def test_dry_run_never_consumes_budget(self):
        budget = FakeBudget(used=1, limit=100)
        p = planner(plan(case_requirements=req("endpoint", "evidence")))
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td), budget=budget)
            gate = eligible_snapshot(ctx, p)
            result = snapshot_validation_runner_dry_run(
                ctx,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=False,
            )
        self.assertEqual(item(result)["status"], "dry_run_ready")
        self.assertEqual(budget.consume_calls, 0)
        self.assertFalse(result["budget_reserved"])
        self.assertFalse(result["budget_consumed"])

    def test_snapshot_persists_with_global_fail_closed_guardrails(self):
        p = planner(plan(case_requirements=req("endpoint", "evidence")))
        with tempfile.TemporaryDirectory() as td:
            ctx = make_ctx(Path(td))
            gate = eligible_snapshot(ctx, p)
            result = snapshot_validation_runner_dry_run(
                ctx,
                evidence_completion_plan=p,
                validation_eligibility=gate,
                persist=True,
            )
            output = Path(result["output"])
            self.assertTrue(output.exists())
            saved = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(saved["mode"], "dry_run_only")
        self.assertFalse(saved["execution_enabled"])
        self.assertFalse(saved["automatic_execution_allowed"])
        self.assertFalse(saved["executes_validation"])
        self.assertEqual(saved["network_requests_executed"], 0)
        self.assertFalse(saved["loads_credentials"])
        self.assertFalse(saved["switches_identity"])
        self.assertFalse(saved["mutates_target"])
        self.assertFalse(saved["affects_admission"])
        self.assertFalse(saved["affects_candidate_promotion"])
        self.assertIsNone(saved["numeric_score"])

    def test_runner_source_has_no_live_transport_import_or_call_surface(self):
        source = (ROOT / "app" / "validation_runner.py").read_text(encoding="utf-8")
        forbidden = (
            "import urllib",
            "import socket",
            "import requests",
            "import httpx",
            "import subprocess",
            "perform_pinned_request",
            "_perform_request(",
            ".consume(",
        )
        for token in forbidden:
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
