from __future__ import annotations

"""Explicit, bounded passive-live execution for Validation Runner contracts.

This is the first live executor in the hypothesis-completion pipeline. It is
intentionally narrower than the existing Safe Validation case workflow:

- only contracts produced by Validation Runner dry-run are accepted;
- only canonical ``passive_live`` families are executable;
- execution requires the existing global/target/CLI authorization gates plus a
  contract-specific confirmation phrase;
- request recipes are inherited from Safe Validation and limited to
  GET/HEAD/OPTIONS without credentials, bodies, redirects, retries or query
  replay;
- the pinned Safe Transport boundary is reused for public-address validation and
  DNS-rebinding protection;
- observations are redacted metadata only; raw response bodies are never stored;
- live observations do not directly satisfy Admission or promote Candidates in
  this release. A separate typed-evidence adapter is required for that step.
"""

import json
import time
import urllib.parse
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from core import (
    AppPaths,
    Config,
    Database,
    PolicySet,
    ReconError,
    json_dumps,
    normalize_url,
    utc_now,
)
from family_reasoning import FAMILY_REASONING, FAMILY_REASONING_RULE_VERSION
import safe_validation
from validation_eligibility import snapshot_validation_eligibility
from validation_runner import snapshot_validation_runner_dry_run


VALIDATION_EXECUTOR_VERSION = "1.0.0"
VALIDATION_EXECUTOR_RULE_VERSION = "2026.08.16.1"
MAX_EXECUTOR_REQUESTS = 2
MAX_EXECUTOR_RUNTIME_SECONDS = 15
MIN_EXECUTOR_DELAY_SECONDS = 1.0
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
ALLOWED_RECIPE_HEADERS = {"origin", "access-control-request-method", "accept"}
PERSISTED_RESPONSE_HEADERS = {
    "content-type",
    "cache-control",
    "vary",
    "age",
    "etag",
    "location",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "allow",
    "server",
}


class _ExecutionBudget:
    """DB-backed request budget plus a short executor-session runtime budget."""

    def __init__(self, db: Database, run_id: str, target: str) -> None:
        self.db = db
        self.run_id = run_id
        self.target = target
        self.started = time.monotonic()

    def check_runtime(self) -> None:
        elapsed = time.monotonic() - self.started
        if elapsed > MAX_EXECUTOR_RUNTIME_SECONDS:
            raise ReconError(
                f"Validation executor runtime budget exhausted: {elapsed:.1f}s/"
                f"{MAX_EXECUTOR_RUNTIME_SECONDS}s"
            )

    def snapshot(self) -> dict[str, dict[str, int]]:
        rows = self.db.all(
            "SELECT metric,used,limit_value FROM run_budgets "
            "WHERE run_id=? AND target=? ORDER BY metric",
            (self.run_id, self.target),
        )
        return {
            str(row["metric"]): {
                "used": int(row["used"]),
                "limit": int(row["limit_value"]),
            }
            for row in rows
        }

    def consume(self, metric: str, amount: int = 1) -> tuple[int, int]:
        self.check_runtime()
        snapshot = self.snapshot().get(metric)
        if not snapshot or int(snapshot.get("limit") or 0) <= 0:
            raise ReconError(f"Validation executor budget unavailable: {metric}")
        used, limit_value, allowed = self.db.budget_consume(
            self.run_id,
            self.target,
            metric,
            amount,
        )
        if not allowed:
            raise ReconError(
                f"Validation executor budget exhausted: {metric} {used}/{limit_value}"
            )
        return int(used), int(limit_value)


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ReconError(f"Refusing symlinked Validation Runner artifact: {path}")
    if not path.exists() or not path.is_file():
        raise ReconError(f"Validation Runner artifact not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReconError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReconError(f"Validation Runner artifact must contain a JSON object: {path}")
    return value


def _resolve_target_and_run_dir(
    paths: AppPaths,
    db: Database,
    run_id: str,
    target: str,
) -> tuple[str, Path]:
    run_id = str(run_id or "").strip()
    target = str(target or "").strip()
    if not run_id:
        raise ReconError("validation runner-execute requires --run-id RUN_ID")

    if target:
        row = db.one(
            "SELECT target,run_dir FROM run_targets WHERE run_id=? AND target=?",
            (run_id, target),
        )
        if not row:
            raise ReconError(f"Run target not found: {run_id} / {target}")
        selected_target = str(row["target"])
        raw_dir = str(row["run_dir"] or "")
    else:
        rows = db.all(
            "SELECT target,run_dir FROM run_targets WHERE run_id=? ORDER BY target",
            (run_id,),
        )
        if not rows:
            raise ReconError(f"Run not found: {run_id}")
        if len(rows) != 1:
            raise ReconError(
                "validation runner-execute requires --target when the run has multiple targets"
            )
        selected_target = str(rows[0]["target"])
        raw_dir = str(rows[0]["run_dir"] or "")

    if not raw_dir:
        raise ReconError(f"Run directory is unavailable for {run_id} / {selected_target}")
    run_dir = Path(raw_dir).expanduser()
    if not run_dir.is_absolute():
        run_dir = (paths.root / run_dir).resolve()
    run_dir = run_dir.resolve()
    output_root = paths.output.resolve()
    try:
        run_dir.relative_to(output_root)
    except ValueError as exc:
        raise ReconError(
            f"Run directory is outside the current Recon Monitor output root: {run_dir}"
        ) from exc
    if not run_dir.exists() or not run_dir.is_dir():
        raise ReconError(f"Run directory does not exist: {run_dir}")
    return selected_target, run_dir


def _policy_for_target(paths: AppPaths, target: str):
    policies = PolicySet.load(paths)
    selected = policies.select(target)
    if len(selected) != 1:
        raise ReconError(f"Expected exactly one target policy for {target}")
    return selected[0]


def _unique_by_hypothesis(items: Any, hypothesis_id: str, label: str) -> dict[str, Any]:
    if not isinstance(items, list):
        raise ReconError(f"{label} does not contain an item list")
    matches = [
        dict(item)
        for item in items
        if isinstance(item, Mapping)
        and str(item.get("hypothesis_id") or "").strip() == hypothesis_id
    ]
    if len(matches) != 1:
        raise ReconError(
            f"{label} must contain exactly one item for hypothesis {hypothesis_id}; "
            f"found {len(matches)}"
        )
    return matches[0]


def _contract_by_id(snapshot: Mapping[str, Any], contract_id: str) -> dict[str, Any]:
    contracts = snapshot.get("contracts", [])
    if not isinstance(contracts, list):
        raise ReconError("Validation Runner dry-run artifact has invalid contracts")
    matches = [
        dict(item)
        for item in contracts
        if isinstance(item, Mapping)
        and str(item.get("contract_id") or "").strip() == contract_id
    ]
    if len(matches) != 1:
        raise ReconError(
            f"Dry-run contract must exist exactly once: {contract_id} (found {len(matches)})"
        )
    return matches[0]


def _artifact_identity(
    artifact: Mapping[str, Any],
    *,
    run_id: str,
    target: str,
    analysis_id: str | None = None,
    label: str,
) -> str:
    artifact_run = str(artifact.get("run_id") or "").strip()
    artifact_target = str(artifact.get("target") or "").strip()
    artifact_analysis = str(artifact.get("analysis_id") or "").strip()
    if artifact_run != run_id:
        raise ReconError(f"{label} run mismatch: expected {run_id}, got {artifact_run or '<empty>'}")
    if artifact_target and artifact_target != target:
        raise ReconError(
            f"{label} target mismatch: expected {target}, got {artifact_target}"
        )
    if analysis_id is not None and artifact_analysis != analysis_id:
        raise ReconError(
            f"{label} analysis mismatch: expected {analysis_id}, got {artifact_analysis or '<empty>'}"
        )
    return artifact_analysis


def _safe_contract_url(contract: Mapping[str, Any], policy: Any) -> str:
    surface = dict(contract.get("surface") or {})
    if str(surface.get("kind") or "") != "endpoint":
        raise ReconError("Passive-live executor requires an endpoint dry-run surface")
    raw = str(surface.get("display") or "").strip()
    normalized = normalize_url(raw, drop_tracking=False)
    if not normalized:
        raise ReconError("Dry-run contract endpoint is not a valid HTTP(S) URL")
    parsed = urllib.parse.urlsplit(normalized)
    if parsed.query or parsed.fragment:
        raise ReconError("Passive-live executor refuses query strings and fragments")
    if not policy.url_in_scope(normalized):
        raise ReconError("Dry-run contract endpoint is outside the current target policy")
    return normalized


def _validate_recipe(requests: list[dict[str, Any]], expected_url: str) -> list[dict[str, Any]]:
    bounded = [dict(item) for item in requests[:MAX_EXECUTOR_REQUESTS]]
    if not bounded:
        raise ReconError("No bounded passive-live request recipe is available")
    for item in bounded:
        method = str(item.get("method") or "").upper()
        url = str(item.get("url") or "")
        if method not in ALLOWED_METHODS:
            raise ReconError(f"Passive-live executor blocked unsafe method: {method or '<empty>'}")
        if url != expected_url:
            raise ReconError("Passive-live executor blocked a recipe URL mismatch")
        if item.get("data") is not None or item.get("body") is not None:
            raise ReconError("Passive-live executor does not send request bodies")
        headers = dict(item.get("headers") or {})
        forbidden = [
            str(key)
            for key in headers
            if str(key).strip().lower() not in ALLOWED_RECIPE_HEADERS
        ]
        if forbidden:
            raise ReconError(
                "Passive-live executor blocked non-observation request headers: "
                + ", ".join(sorted(forbidden))
            )
    return bounded


def _strip_query_fragment(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return ""
    if parsed.scheme or parsed.netloc:
        if parsed.scheme.lower() not in {"http", "https"}:
            return ""
        return urllib.parse.urlunsplit(
            (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", "")
        )
    return urllib.parse.urlunsplit(("", "", parsed.path or "", "", ""))


def _bounded_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return default


def _sanitize_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Project transport output onto a fixed redacted persistence schema."""

    source = dict(observation or {})
    persisted_headers: dict[str, str] = {}
    raw_headers = source.get("headers")
    if isinstance(raw_headers, Mapping):
        for key, value in raw_headers.items():
            normalized = str(key or "").strip().lower()
            if normalized not in PERSISTED_RESPONSE_HEADERS:
                continue
            rendered = str(value or "")[:1000]
            if normalized == "location":
                rendered = _strip_query_fragment(rendered)
            persisted_headers[normalized] = rendered

    method = str(source.get("method") or "").upper()
    if method not in ALLOWED_METHODS:
        method = ""
    shape = source.get("response_shape", {})
    if not isinstance(shape, (dict, list, str, int, float, bool)) and shape is not None:
        shape = {}

    return {
        "method": method,
        "url": _strip_query_fragment(source.get("url")),
        "status_code": _bounded_int(source.get("status_code")),
        "headers": persisted_headers,
        "content_type": str(source.get("content_type") or "")[:500],
        "response_bytes": _bounded_int(source.get("response_bytes")),
        "body_sha256": str(source.get("body_sha256") or "")[:128],
        "response_shape": shape,
        "shape_hash": str(source.get("shape_hash") or "")[:128],
        "sensitive_key_names": [
            str(value)[:240]
            for value in list(source.get("sensitive_key_names") or [])[:100]
        ],
        "sensitive_pattern_categories": [
            str(value)[:120]
            for value in list(source.get("sensitive_pattern_categories") or [])[:50]
        ],
        "redirect_outside_scope": bool(source.get("redirect_outside_scope")),
        "raw_body_stored": False,
        "error": str(source.get("error") or "")[:500],
        "observed_at": str(source.get("observed_at") or utc_now()),
    }


def _append_execution(run_dir: Path, result: Mapping[str, Any]) -> Path:
    output = run_dir / "validation-runner-executions.jsonl"
    if output.is_symlink():
        raise ReconError(f"Refusing symlinked Validation Runner execution log: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as handle:
        handle.write(json_dumps(dict(result)) + "\n")
    return output


def execute_validation_runner_contract(
    paths: AppPaths,
    config: Config,
    db: Database,
    *,
    scan_run_id: str,
    target: str = "",
    contract_id: str,
    confirmation: str,
    allow_live: bool = False,
    actor: str = "analyst",
) -> dict[str, Any]:
    """Execute one explicitly approved, passive-live dry-run contract.

    This function intentionally produces observation artifacts only. It does not
    call ``record_hypothesis`` or mutate Admission/Candidate state.
    """

    contract_id = str(contract_id or "").strip()
    if not contract_id:
        raise ReconError("validation runner-execute requires --contract-id")
    if not allow_live:
        raise ReconError("Passive-live Validation Runner execution requires --allow-live")

    expected_confirmation = f"I_CONFIRM_PASSIVE_VALIDATION_FOR_{contract_id}"
    if str(confirmation or "").strip() != expected_confirmation:
        raise ReconError(
            "Contract-specific confirmation did not match. Expected: "
            + expected_confirmation
        )

    run_id = str(scan_run_id or "").strip()
    selected_target, run_dir = _resolve_target_and_run_dir(paths, db, run_id, target)
    policy = _policy_for_target(paths, selected_target)

    planner = _load_json(run_dir / "evidence-completion-plan.json")
    input_gate = _load_json(run_dir / "validation-eligibility.json")
    dry_run = _load_json(run_dir / "validation-runner-dry-run.json")

    analysis_id = _artifact_identity(
        planner,
        run_id=run_id,
        target=selected_target,
        label="Evidence Completion Planner",
    )
    if not analysis_id:
        raise ReconError("Evidence Completion Planner artifact has no analysis_id")
    _artifact_identity(
        input_gate,
        run_id=run_id,
        target=selected_target,
        analysis_id=analysis_id,
        label="Validation Eligibility",
    )
    _artifact_identity(
        dry_run,
        run_id=run_id,
        target=selected_target,
        analysis_id=analysis_id,
        label="Validation Runner dry-run",
    )

    contract = _contract_by_id(dry_run, contract_id)
    if str(contract.get("mode") or "") != "dry_run_only":
        raise ReconError("Contract is not a Validation Runner dry-run contract")
    if bool(contract.get("executes_validation")) or bool(contract.get("execution_enabled")):
        raise ReconError("Dry-run contract contains an unexpected execution-enabled state")

    hypothesis_id = str(contract.get("hypothesis_id") or "").strip()
    if not hypothesis_id:
        raise ReconError("Dry-run contract has no hypothesis_id")
    plan = _unique_by_hypothesis(planner.get("plans", []), hypothesis_id, "Planner")
    input_decision = _unique_by_hypothesis(
        input_gate.get("decisions", []), hypothesis_id, "Validation Eligibility"
    )

    if str(input_decision.get("status") or "") != "eligible":
        raise ReconError(
            "Stored Validation Eligibility decision is no longer an executable starting point"
        )

    family = str(plan.get("family") or "").strip()
    level = str(plan.get("validation_level") or "").strip()
    if str(contract.get("family") or "").strip() != family:
        raise ReconError("Planner and dry-run contract family mismatch")
    if str(contract.get("validation_level") or "").strip() != level:
        raise ReconError("Planner and dry-run contract validation-level mismatch")
    if level != "passive_live":
        raise ReconError(
            "This executor release runs passive_live contracts only; controlled/manual work remains blocked"
        )
    canonical = FAMILY_REASONING.get(family)
    if not canonical or str(canonical.get("validation_level") or "") != "passive_live":
        raise ReconError(
            f"Current Family Reasoning does not permit passive-live execution for {family or '<unknown>'}"
        )

    budget = _ExecutionBudget(db, run_id, selected_target)
    ctx = SimpleNamespace(
        run_id=run_id,
        run_dir=run_dir,
        policy=policy,
        config=config,
        allow_active=True,
        budget=budget,
        db=db,
    )
    fresh_gate = snapshot_validation_eligibility(
        ctx,
        evidence_completion_plan=planner,
        persist=False,
    )
    fresh_decision = _unique_by_hypothesis(
        fresh_gate.get("decisions", []), hypothesis_id, "Fresh Validation Eligibility"
    )
    if str(fresh_decision.get("status") or "") != "eligible":
        reasons = [str(value) for value in fresh_decision.get("blocking_reasons", [])]
        raise ReconError(
            "Fresh Validation Eligibility re-check blocked execution: "
            + (", ".join(reasons) if reasons else str(fresh_decision.get("status") or "ineligible"))
        )
    if str(fresh_decision.get("family") or "") != family:
        raise ReconError("Fresh Validation Eligibility family mismatch")
    if str(fresh_decision.get("validation_level") or "") != "passive_live":
        raise ReconError("Fresh Validation Eligibility no longer permits passive-live validation")

    fresh_dry_run = snapshot_validation_runner_dry_run(
        ctx,
        evidence_completion_plan=planner,
        validation_eligibility=fresh_gate,
        persist=False,
    )
    fresh_contract = _contract_by_id(fresh_dry_run, contract_id)
    for key in ("hypothesis_id", "family", "validation_level", "planning_phase"):
        if str(contract.get(key) or "") != str(fresh_contract.get(key) or ""):
            raise ReconError(f"Fresh Validation Runner dry-run contract mismatch: {key}")
    stored_surface = dict(contract.get("surface") or {})
    fresh_surface = dict(fresh_contract.get("surface") or {})
    if (
        str(stored_surface.get("kind") or "") != str(fresh_surface.get("kind") or "")
        or str(stored_surface.get("display") or "") != str(fresh_surface.get("display") or "")
    ):
        raise ReconError("Fresh Validation Runner dry-run contract surface mismatch")
    contract = fresh_contract

    endpoint = _safe_contract_url(contract, policy)
    allowed, safety_reason = safe_validation._url_safety(endpoint, policy)
    if not allowed:
        raise ReconError(f"Safe Validation URL policy blocked execution: {safety_reason}")

    recipe = safe_validation._request_recipe(family, endpoint)
    requests = _validate_recipe(list(recipe or []), endpoint)

    execution_id = "VEX-" + uuid.uuid4().hex[:16].upper()
    observations: list[dict[str, Any]] = []
    stopped_reason = ""
    started_at = utc_now()
    failed_5xx = 0
    http_budget_units_consumed = 0

    try:
        for index, request in enumerate(requests):
            budget.check_runtime()
            budget.consume("http_requests", 1)
            http_budget_units_consumed += 1
            observation, state = safe_validation._perform_request(request, policy)
            row = _sanitize_observation(observation or {})
            row["sequence"] = index + 1
            row["request_purpose"] = str(request.get("purpose") or "")[:500]
            observations.append(row)

            status_code = int(row.get("status_code") or 0)
            if 500 <= status_code <= 599:
                failed_5xx += 1
            if state == "stopped_for_safety":
                stopped_reason = str(row.get("error") or "safe_transport_stopped")
                break
            if state == "error":
                stopped_reason = str(row.get("error") or "transport_error")
                break
            if bool(row.get("redirect_outside_scope")):
                stopped_reason = "redirect_outside_scope"
                break
            if failed_5xx >= 2:
                stopped_reason = "repeated_server_errors"
                break
            if index < len(requests) - 1:
                time.sleep(MIN_EXECUTOR_DELAY_SECONDS)
    except Exception as exc:
        stopped_reason = f"executor_error:{type(exc).__name__}"
        result = {
            "version": VALIDATION_EXECUTOR_VERSION,
            "rule_version": VALIDATION_EXECUTOR_RULE_VERSION,
            "family_reasoning_rule_version": FAMILY_REASONING_RULE_VERSION,
            "execution_id": execution_id,
            "contract_id": contract_id,
            "run_id": run_id,
            "analysis_id": analysis_id,
            "target": selected_target,
            "hypothesis_id": hypothesis_id,
            "family": family,
            "validation_level": level,
            "status": "failed",
            "stopped_reason": stopped_reason,
            "error": str(exc)[:1000],
            "observations": observations,
            "network_requests_executed": len(observations),
            "http_budget_units_consumed": http_budget_units_consumed,
            "budget_consumed": http_budget_units_consumed > 0,
            "raw_bodies_stored": False,
            "typed_evidence_emitted": False,
            "affects_admission": False,
            "affects_candidate_promotion": False,
            "requires_evidence_adapter": True,
            "automatic_execution": False,
            "actor": actor,
            "started_at": started_at,
            "finished_at": utc_now(),
        }
        output = _append_execution(run_dir, result)
        result["output"] = str(output)
        db.audit(
            "validation_runner_execution_failed",
            actor=actor,
            target=selected_target,
            entity_type="analysis_hypothesis",
            entity_value=hypothesis_id,
            details={
                "execution_id": execution_id,
                "contract_id": contract_id,
                "family": family,
                "requests": len(observations),
                "reason": stopped_reason,
            },
        )
        raise

    status = "stopped_for_safety" if stopped_reason else "completed"
    result = {
        "version": VALIDATION_EXECUTOR_VERSION,
        "rule_version": VALIDATION_EXECUTOR_RULE_VERSION,
        "family_reasoning_rule_version": FAMILY_REASONING_RULE_VERSION,
        "execution_id": execution_id,
        "contract_id": contract_id,
        "run_id": run_id,
        "analysis_id": analysis_id,
        "target": selected_target,
        "hypothesis_id": hypothesis_id,
        "family": family,
        "validation_level": level,
        "status": status,
        "stopped_reason": stopped_reason,
        "observations": observations,
        "network_requests_planned": len(requests),
        "network_requests_executed": len(observations),
        "http_budget_units_consumed": http_budget_units_consumed,
        "budget_consumed": http_budget_units_consumed > 0,
        "raw_bodies_stored": False,
        "loads_credentials": False,
        "switches_identity": False,
        "mutates_target": False,
        "follows_redirects": False,
        "retries": 0,
        "typed_evidence_emitted": False,
        "observation_only": True,
        "affects_admission": False,
        "affects_candidate_promotion": False,
        "requires_evidence_adapter": True,
        "automatic_execution": False,
        "contract_confirmation_verified": True,
        "fresh_eligibility_verified": True,
        "actor": actor,
        "started_at": started_at,
        "finished_at": utc_now(),
        "safety_semantics": (
            "This execution collected bounded passive-live response metadata only. "
            "It did not reuse credentials, send a body, follow redirects, retry, mutate "
            "the target, satisfy Admission, or promote a Candidate."
        ),
    }
    output = _append_execution(run_dir, result)
    result["output"] = str(output)
    db.audit(
        "validation_runner_passive_live_executed",
        actor=actor,
        target=selected_target,
        entity_type="analysis_hypothesis",
        entity_value=hypothesis_id,
        details={
            "execution_id": execution_id,
            "contract_id": contract_id,
            "family": family,
            "status": status,
            "requests": len(observations),
            "raw_bodies_stored": False,
            "typed_evidence_emitted": False,
        },
    )
    return result
