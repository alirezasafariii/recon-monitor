from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, AppPaths, Config, Database, PolicySet, ReconError, json_dumps, utc_now
from validation_eligibility import snapshot_validation_eligibility
from validation_executor import execute_validation_runner_contract
from validation_runner import snapshot_validation_runner_dry_run


RUN_ID = "RUN-EXECUTOR-1"
TARGET = "example.test"
ENDPOINT_WITH_SECRET = "https://api.example.test/profile?token=SUPER-SECRET#frag"


class FakeArtifactBudget:
    def __init__(self, used=0, limit=20):
        self.used = used
        self.limit = limit

    def snapshot(self):
        return {"http_requests": {"used": self.used, "limit": self.limit}}

    def check_runtime(self):
        return None


def requirements(*keys):
    return [
        {"key": key, "label": key, "why": f"need {key}"}
        for key in keys
    ]


def passive_plan(
    *,
    hypothesis_id="H-PASSIVE-1",
    family="information_disclosure",
    endpoint=ENDPOINT_WITH_SECRET,
    validation_level="passive_live",
    case_requirements=None,
):
    return {
        "hypothesis_id": hypothesis_id,
        "family": family,
        "planning_phase": "promotion",
        "gap_type": "behavioral_validation_needed",
        "validation_level": validation_level,
        "recommended_action": "prepare_passive_live_validation",
        "endpoint": endpoint,
        "asset": "api.example.test",
        "case_requirements": list(
            case_requirements
            if case_requirements is not None
            else requirements("endpoint", "evidence", "expected_behavior")
        ),
        "source_groups": ["stored:surface", "analysis:semantic"],
        "independent_sources": 2,
        "live_target_interaction_required": True,
        "authorization_required": True,
    }


def controlled_plan():
    return {
        "hypothesis_id": "H-CONTROLLED-1",
        "family": "broken_object_authorization",
        "planning_phase": "promotion",
        "gap_type": "controlled_validation_needed",
        "validation_level": "controlled",
        "recommended_action": "prepare_controlled_validation",
        "endpoint": "https://api.example.test/orders/1",
        "asset": "api.example.test",
        "case_requirements": requirements(
            "authenticated_context",
            "second_identity",
            "ownership_map",
            "comparable_response",
        ),
        "source_groups": ["endpoint", "behavior"],
        "independent_sources": 2,
        "live_target_interaction_required": True,
        "authorization_required": True,
    }


class ExecutorFixture:
    def __init__(self, root: Path):
        self.root = root
        self.paths = AppPaths.from_root(root)
        self.paths.ensure()
        self.run_dir = root / "output" / TARGET / RUN_ID
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.write_config()
        self.write_policy()
        self.config = Config(self.paths)
        self.db = Database(self.paths.db)
        now = utc_now()
        self.db.execute(
            "INSERT INTO runs(id,version,status,started_at,target_count) VALUES(?,?,?,?,?)",
            (RUN_ID, APP_VERSION, "success", now, 1),
        )
        self.db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,started_at,finished_at,run_dir,baseline) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (RUN_ID, TARGET, "test-policy", "success", now, now, str(self.run_dir), 0),
        )
        self.db.execute(
            "INSERT INTO run_budgets(run_id,target,metric,used,limit_value,updated_at) "
            "VALUES(?,?,?,?,?,?)",
            (RUN_ID, TARGET, "http_requests", 0, 20, now),
        )

    def close(self):
        self.db.close()

    def write_config(self, *, authorized=True, global_active=True):
        self.paths.config.write_text(
            "I_HAVE_AUTHORIZATION=" + ("yes" if authorized else "no") + "\n"
            "ENABLE_ACTIVE_MODULES=" + ("yes" if global_active else "no") + "\n",
            encoding="utf-8",
        )

    def write_policy(self, *, include_expected=True, controlled_context=False):
        validation_context = {}
        if include_expected:
            validation_context["expected_behavior"] = "test-only expected response semantics"
        if controlled_context:
            validation_context.update(
                {
                    "authenticated_context": "test-account-a",
                    "second_identity": "test-account-b",
                    "ownership_map": "test-owned-object-map",
                    "comparable_response": True,
                }
            )
        payload = {
            "targets": [
                {
                    "name": TARGET,
                    "roots": [TARGET],
                    "include": [r"(^|\.)example\.test$"],
                    "active": {
                        "confirmation": "I_AM_AUTHORIZED_FOR_ACTIVE_TESTING",
                        "validation_context": validation_context,
                    },
                }
            ]
        }
        self.paths.policy.parent.mkdir(parents=True, exist_ok=True)
        self.paths.policy.write_text(json_dumps(payload, pretty=True) + "\n", encoding="utf-8")

    def policy(self):
        return PolicySet.load(self.paths).select(TARGET)[0]

    def artifact_ctx(self):
        return SimpleNamespace(
            run_id=RUN_ID,
            run_dir=self.run_dir,
            policy=self.policy(),
            config=self.config,
            allow_active=True,
            budget=FakeArtifactBudget(),
            db=self.db,
        )

    def make_artifacts(self, plan):
        planner = {
            "version": "1.0.0",
            "rule_version": "test",
            "run_id": RUN_ID,
            "analysis_id": "A-EXECUTOR-1",
            "target": TARGET,
            "plans": [dict(plan)],
        }
        (self.run_dir / "evidence-completion-plan.json").write_text(
            json_dumps(planner, pretty=True) + "\n",
            encoding="utf-8",
        )
        ctx = self.artifact_ctx()
        gate = snapshot_validation_eligibility(
            ctx,
            evidence_completion_plan=planner,
            persist=True,
        )
        dry = snapshot_validation_runner_dry_run(
            ctx,
            evidence_completion_plan=planner,
            validation_eligibility=gate,
            persist=True,
        )
        if not dry.get("contracts"):
            raise AssertionError(f"fixture did not create a dry-run contract: {dry}")
        return planner, gate, dry, str(dry["contracts"][0]["contract_id"])

    def execute(self, contract_id, *, confirmation=None, allow_live=True):
        if confirmation is None:
            confirmation = f"I_CONFIRM_PASSIVE_VALIDATION_FOR_{contract_id}"
        return execute_validation_runner_contract(
            self.paths,
            self.config,
            self.db,
            scan_run_id=RUN_ID,
            target=TARGET,
            contract_id=contract_id,
            confirmation=confirmation,
            allow_live=allow_live,
            actor="test",
        )

    def budget_used(self):
        row = self.db.one(
            "SELECT used FROM run_budgets WHERE run_id=? AND target=? AND metric='http_requests'",
            (RUN_ID, TARGET),
        )
        return int(row["used"]) if row else -1


class PassiveLiveValidationExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fx = ExecutorFixture(Path(self.temp.name))

    def tearDown(self):
        self.fx.close()
        self.temp.cleanup()

    @staticmethod
    def observation(item, *, status=200, redirect_outside=False, error=""):
        return {
            "method": str(item.get("method") or "GET"),
            "url": str(item.get("url") or ""),
            "status_code": status,
            "headers": {"content-type": "application/json"},
            "content_type": "application/json",
            "response_bytes": 17,
            "body_sha256": "deadbeef",
            "response_shape": {"profile": "string"},
            "shape_hash": "shapehash",
            "sensitive_key_names": [],
            "sensitive_pattern_categories": [],
            "raw_body_stored": False,
            "redirect_outside_scope": redirect_outside,
            "error": error,
            "observed_at": utc_now(),
        }

    def test_passive_live_contract_executes_bounded_safe_recipe(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        seen = []

        def fake_request(item, policy):
            seen.append(dict(item))
            return self.observation(item), "ok"

        with patch("validation_executor.safe_validation._perform_request", side_effect=fake_request), patch(
            "validation_executor.time.sleep", return_value=None
        ):
            result = self.fx.execute(contract_id)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["validation_level"], "passive_live")
        self.assertEqual(result["network_requests_executed"], 2)
        self.assertEqual(len(seen), 2)
        self.assertEqual({row["method"] for row in seen}, {"HEAD", "GET"})
        self.assertTrue(all(row["url"] == "https://api.example.test/profile" for row in seen))
        self.assertTrue(all("?" not in row["url"] and "#" not in row["url"] for row in seen))
        self.assertEqual(self.fx.budget_used(), 2)
        self.assertEqual(result["http_budget_units_consumed"], 2)
        self.assertTrue(result["budget_consumed"])
        self.assertFalse(result["raw_bodies_stored"])
        self.assertFalse(result["typed_evidence_emitted"])
        self.assertFalse(result["affects_admission"])
        self.assertFalse(result["affects_candidate_promotion"])
        self.assertFalse(result["loads_credentials"])
        self.assertFalse(result["switches_identity"])
        self.assertFalse(result["mutates_target"])
        self.assertFalse(result["follows_redirects"])
        output = Path(result["output"])
        self.assertTrue(output.exists())
        persisted = output.read_text(encoding="utf-8")
        self.assertNotIn("SUPER-SECRET", persisted)

    def test_allow_live_is_required_before_transport_or_budget(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        with patch("validation_executor.safe_validation._perform_request") as request:
            with self.assertRaisesRegex(ReconError, "--allow-live"):
                self.fx.execute(contract_id, allow_live=False)
        request.assert_not_called()
        self.assertEqual(self.fx.budget_used(), 0)

    def test_contract_specific_confirmation_is_required(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        with patch("validation_executor.safe_validation._perform_request") as request:
            with self.assertRaisesRegex(ReconError, "confirmation"):
                self.fx.execute(contract_id, confirmation="I_CONFIRM_SOMETHING_ELSE")
        request.assert_not_called()
        self.assertEqual(self.fx.budget_used(), 0)

    def test_controlled_contract_remains_non_executable(self):
        self.fx.write_policy(controlled_context=True)
        _, _, _, contract_id = self.fx.make_artifacts(controlled_plan())
        with patch("validation_executor.safe_validation._perform_request") as request:
            with self.assertRaisesRegex(ReconError, "passive_live contracts only"):
                self.fx.execute(contract_id)
        request.assert_not_called()
        self.assertEqual(self.fx.budget_used(), 0)

    def test_fresh_authorization_change_blocks_execution(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        self.fx.config.values["ENABLE_ACTIVE_MODULES"] = "no"
        with patch("validation_executor.safe_validation._perform_request") as request:
            with self.assertRaisesRegex(ReconError, "Fresh Validation Eligibility"):
                self.fx.execute(contract_id)
        request.assert_not_called()
        self.assertEqual(self.fx.budget_used(), 0)

    def test_fresh_context_change_blocks_execution(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        self.fx.write_policy(include_expected=False)
        with patch("validation_executor.safe_validation._perform_request") as request:
            with self.assertRaisesRegex(ReconError, "Fresh Validation Eligibility"):
                self.fx.execute(contract_id)
        request.assert_not_called()
        self.assertEqual(self.fx.budget_used(), 0)

    def test_exhausted_http_budget_blocks_before_transport(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        self.fx.db.execute(
            "UPDATE run_budgets SET used=limit_value WHERE run_id=? AND target=? AND metric='http_requests'",
            (RUN_ID, TARGET),
        )
        with patch("validation_executor.safe_validation._perform_request") as request:
            with self.assertRaisesRegex(ReconError, "Fresh Validation Eligibility"):
                self.fx.execute(contract_id)
        request.assert_not_called()
        self.assertEqual(self.fx.budget_used(), 20)

    def test_redirect_outside_scope_stops_after_first_request(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        calls = []

        def redirected(item, policy):
            calls.append(dict(item))
            return self.observation(item, status=302, redirect_outside=True), "ok"

        with patch("validation_executor.safe_validation._perform_request", side_effect=redirected), patch(
            "validation_executor.time.sleep", return_value=None
        ):
            result = self.fx.execute(contract_id)
        self.assertEqual(result["status"], "stopped_for_safety")
        self.assertEqual(result["stopped_reason"], "redirect_outside_scope")
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["network_requests_executed"], 1)
        self.assertEqual(result["http_budget_units_consumed"], 1)
        self.assertEqual(self.fx.budget_used(), 1)

    def test_safe_transport_stop_ends_execution(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())

        def stopped(item, policy):
            return self.observation(item, status=429, error="http_error"), "stopped_for_safety"

        with patch("validation_executor.safe_validation._perform_request", side_effect=stopped):
            result = self.fx.execute(contract_id)
        self.assertEqual(result["status"], "stopped_for_safety")
        self.assertEqual(result["network_requests_executed"], 1)
        self.assertEqual(self.fx.budget_used(), 1)

    def test_transport_exception_records_accurate_budget_consumption(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        with patch(
            "validation_executor.safe_validation._perform_request",
            side_effect=RuntimeError("synthetic transport failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic transport failure"):
                self.fx.execute(contract_id)
        self.assertEqual(self.fx.budget_used(), 1)
        output = self.fx.run_dir / "validation-runner-executions.jsonl"
        payload = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(payload["status"], "failed")
        self.assertTrue(payload["budget_consumed"])
        self.assertEqual(payload["http_budget_units_consumed"], 1)
        self.assertEqual(payload["network_requests_executed"], 0)

    def test_budget_failure_before_consume_is_not_reported_as_consumed(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        original = self.fx.db.budget_consume

        def fail_budget(*args, **kwargs):
            raise RuntimeError("synthetic budget failure")

        self.fx.db.budget_consume = fail_budget
        try:
            with patch("validation_executor.safe_validation._perform_request") as request:
                with self.assertRaisesRegex(RuntimeError, "synthetic budget failure"):
                    self.fx.execute(contract_id)
            request.assert_not_called()
        finally:
            self.fx.db.budget_consume = original
        output = self.fx.run_dir / "validation-runner-executions.jsonl"
        payload = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])
        self.assertFalse(payload["budget_consumed"])
        self.assertEqual(payload["http_budget_units_consumed"], 0)
        self.assertEqual(payload["network_requests_executed"], 0)

    def test_cors_recipe_uses_only_allowlisted_safe_headers_and_methods(self):
        cors = passive_plan(family="cors_misconfiguration", hypothesis_id="H-CORS-1")
        _, _, _, contract_id = self.fx.make_artifacts(cors)
        seen = []

        def fake(item, policy):
            seen.append(dict(item))
            return self.observation(item), "ok"

        with patch("validation_executor.safe_validation._perform_request", side_effect=fake), patch(
            "validation_executor.time.sleep", return_value=None
        ):
            self.fx.execute(contract_id)
        self.assertEqual({row["method"] for row in seen}, {"OPTIONS", "GET"})
        for row in seen:
            self.assertNotIn("Authorization", row.get("headers", {}))
            self.assertNotIn("Cookie", row.get("headers", {}))
            for key in row.get("headers", {}):
                self.assertIn(key.lower(), {"origin", "access-control-request-method", "accept"})

    def test_executor_source_cannot_mutate_admission_or_candidates(self):
        source = (ROOT / "app" / "validation_executor.py").read_text(encoding="utf-8")
        forbidden = (
            "record_hypothesis(",
            "UPDATE bug_candidates",
            "INSERT INTO bug_candidates",
            "UPDATE analysis_hypotheses",
            "INSERT INTO analysis_hypotheses",
            "mark_promoted(",
        )
        for token in forbidden:
            self.assertNotIn(token, source)

    def test_cli_parser_exposes_explicit_runner_execute_contract(self):
        import recon_monitor

        parser = recon_monitor.build_parser()
        args = parser.parse_args(
            [
                "validation",
                "runner-execute",
                "--run-id",
                RUN_ID,
                "--target",
                TARGET,
                "--contract-id",
                "VDR-TEST",
                "--confirmation",
                "I_CONFIRM_PASSIVE_VALIDATION_FOR_VDR-TEST",
                "--allow-live",
            ]
        )
        self.assertEqual(args.command, "validation")
        self.assertEqual(args.action, "runner-execute")
        self.assertEqual(args.run_id, RUN_ID)
        self.assertEqual(args.target, TARGET)
        self.assertEqual(args.contract_id, "VDR-TEST")
        self.assertTrue(args.allow_live)


if __name__ == "__main__":
    unittest.main()
