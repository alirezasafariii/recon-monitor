from __future__ import annotations

"""Design safe, family-aware near-miss controls for Real-World Corpus V1.

This module turns the 100 near-miss *planning* placeholders into explicit
non-triggering control contracts. It does not execute vulnerable software,
contact targets, generate exploit payloads, assign final labels, or score
Analysis.

A near miss must preserve a meaningful vulnerability-family surface while
leaving at least one promotion group unsatisfied and observing none of the
family's positive override/confirmation signals. If an enforcing blocking
control is observed, the case belongs in ``secure_negative`` instead. If a
positive override/confirmation signal is observed, it is no longer a near miss.
"""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from family_reasoning import FAMILY_ORDER, FAMILY_REASONING
from real_world_corpus_v1_targeted import canonical_family_cwes

CONTROL_DESIGN_VERSION = "1.0.0"
CONTROL_DESIGN_RULE_VERSION = "2026.08.14.8"
EXPECTED_CASE_COUNT = 400
EXPECTED_NEAR_MISS_COUNT = 100


def _text(value: Any) -> str:
    return str(value or "").strip()


def _policy_groups(policy: Mapping[str, Any], key: str) -> list[list[str]]:
    groups = policy.get(key, ())
    result: list[list[str]] = []
    for group in groups or ():
        if isinstance(group, (set, frozenset, list, tuple)):
            result.append(sorted(str(item) for item in group if str(item).strip()))
    return result


def _flat(groups: Iterable[Iterable[str]]) -> list[str]:
    return sorted({str(item) for group in groups for item in group if str(item).strip()})


def _reverse_cwe_map() -> dict[str, list[str]]:
    reverse: dict[str, set[str]] = defaultdict(set)
    for family, cwes in canonical_family_cwes().items():
        for cwe in cwes:
            reverse[str(cwe).upper()].add(str(family))
    return {cwe: sorted(families) for cwe, families in reverse.items()}


def _source_family_candidates(source: Mapping[str, Any]) -> tuple[str | None, str, list[str]]:
    target = _text(source.get("family_target"))
    taxonomy = source.get("source_taxonomy_match") if isinstance(source.get("source_taxonomy_match"), Mapping) else {}
    if target in FAMILY_REASONING and taxonomy.get("status") == "exact_target_cwe_match":
        return target, "exact_target_cwe", [target]

    reverse = _reverse_cwe_map()
    candidates: set[str] = set()
    for cwe in source.get("advisory_cwes", []) or []:
        candidates.update(reverse.get(_text(cwe).upper(), []))
    candidates &= set(str(item) for item in FAMILY_ORDER)
    ordered = sorted(candidates)
    if len(ordered) == 1:
        return ordered[0], "unique_canonical_cwe_proposal", ordered
    if ordered:
        return None, "multi_family_cwe_proposal", ordered
    return None, "generic_source_control", []


def _policy_contract(family: str) -> dict[str, Any]:
    policy = FAMILY_REASONING.get(family, {})
    promotion = _policy_groups(policy, "promotion_required")
    confirmation = _policy_groups(policy, "confirmation_required")
    override = sorted(str(item) for item in policy.get("override_signals", ()) if str(item).strip())
    blocking = sorted(str(item) for item in policy.get("blocking_contradictions", ()) if str(item).strip())
    return {
        "family": family,
        "family_label": _text(policy.get("label")),
        "promotion_required_groups": promotion,
        "positive_override_signals_forbidden": override,
        "confirmation_signals_forbidden": _flat(confirmation),
        "blocking_signals_reclassify_to_secure_negative": blocking,
        "validation_level": _text(policy.get("validation_level")) or "offline",
    }


def design_near_miss(case: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    selected_family, basis, candidates = _source_family_candidates(source)
    candidate_contracts = [_policy_contract(family) for family in candidates if family in FAMILY_REASONING]
    selected_contract = _policy_contract(selected_family) if selected_family else None

    forbidden_positive = sorted({
        signal
        for contract in candidate_contracts
        for signal in (
            contract["positive_override_signals_forbidden"]
            + contract["confirmation_signals_forbidden"]
        )
    })
    blocking = sorted({
        signal
        for contract in candidate_contracts
        for signal in contract["blocking_signals_reclassify_to_secure_negative"]
    })

    return {
        "design_version": CONTROL_DESIGN_VERSION,
        "rule_version": CONTROL_DESIGN_RULE_VERSION,
        "design_id": f"control:{_text(case.get('case_id'))}",
        "control_kind": "source_adjacent_nontriggering_near_miss",
        "family_basis": basis,
        "control_family": selected_family,
        "candidate_families": candidates,
        "family_label_is_final": False,
        "selected_family_contract": selected_contract,
        "candidate_policy_count": len(candidate_contracts),
        "forbidden_positive_signals": forbidden_positive,
        "blocking_signals_reclassify_to_secure_negative": blocking,
        "required_observation_contract": {
            "same_source_root_and_project": True,
            "same_version_or_revision_lineage": True,
            "preserve_meaningful_surface_context": True,
            "leave_at_least_one_promotion_group_unsatisfied": True,
            "positive_override_or_confirmation_signal_must_not_be_observed": True,
            "blocking_control_is_not_required_for_near_miss": True,
            "use_inert_benign_marker_only_if_marker_is_needed": True,
            "record_exact_source_revision_or_version": True,
            "record_raw_observation_hash": True,
            "independent_variant_capture_required": True,
        },
        "reclassification_rules": {
            "if_positive_override_or_confirmation_signal_observed": "positive_candidate_requires_review",
            "if_blocking_security_control_observed": "secure_negative_candidate_requires_review",
            "if_family_surface_not_preserved": "sparse_noisy_or_invalid_near_miss",
            "if_final_family_differs_from_control_family": "redesign_or_rereview_control_before_label",
        },
        "safety": {
            "public_source_or_isolated_controlled_replay_only": True,
            "vulnerability_target_network_access": False,
            "credential_use": False,
            "state_mutation_on_external_target": False,
            "exploit_payload_generation": False,
            "human_label_created": False,
            "analysis_scoring_executed": False,
        },
        "review_requirements": {
            "source_family_adjudication_required_before_final_label": True,
            "human_review_required": True,
            "all_seven_evidence_quality_dimensions_required": True,
        },
        "design_status": "ready_for_controlled_source_observation",
    }


def build_ready_plan(
    cases: Iterable[Mapping[str, Any]],
    sources: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    source_map = {_text(row.get("source_root")).upper(): dict(row) for row in sources}
    output: list[dict[str, Any]] = []
    basis_counts: Counter[str] = Counter()
    near_miss_count = 0

    for raw in cases:
        row = dict(raw)
        if _text(row.get("variant")) == "near_miss":
            near_miss_count += 1
            source = source_map.get(_text(row.get("source_root")).upper())
            if not source:
                raise ValueError(f"missing_source_for_near_miss:{row.get('source_root')}")
            design = design_near_miss(row, source)
            row["control_design"] = design
            row["capture_design_status"] = "ready_to_collect"
            basis_counts[design["family_basis"]] += 1
        output.append(row)

    ready_count = sum(1 for row in output if _text(row.get("capture_design_status")) == "ready_to_collect")
    errors: list[str] = []
    if len(output) != EXPECTED_CASE_COUNT:
        errors.append(f"case_count:{len(output)}!=400")
    if near_miss_count != EXPECTED_NEAR_MISS_COUNT:
        errors.append(f"near_miss_count:{near_miss_count}!=100")
    if ready_count != EXPECTED_CASE_COUNT:
        errors.append(f"ready_count:{ready_count}!=400")
    near_rows = [row for row in output if _text(row.get("variant")) == "near_miss"]
    if any(not isinstance(row.get("control_design"), Mapping) for row in near_rows):
        errors.append("near_miss_control_design_missing")
    if any(row.get("review", {}).get("label") is not None for row in output):
        errors.append("ready_plan_must_not_create_labels")
    if any(bool(row.get("review", {}).get("human_verified")) for row in output):
        errors.append("ready_plan_must_not_create_human_verification")
    if any(bool(row.get("scoring_executed")) for row in output):
        errors.append("ready_plan_must_not_score")
    if any(bool(row.get("target_contact_performed")) for row in output):
        errors.append("ready_plan_must_not_contact_targets")

    canonical = json.dumps(output, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "version": CONTROL_DESIGN_VERSION,
        "rule_version": CONTROL_DESIGN_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_collection_ready_plan",
        "status": "collection_design_ready" if not errors else "collection_design_invalid",
        "plan_sha256": hashlib.sha256(canonical).hexdigest(),
        "case_count": len(output),
        "near_miss_control_count": near_miss_count,
        "ready_to_collect_count": ready_count,
        "family_basis_counts": dict(sorted(basis_counts.items())),
        "errors": errors,
        "passed": not errors,
        "family_assignment_is_final": False,
        "human_labels_created": False,
        "scoring_executed": False,
        "target_contact_performed": False,
        "cases": output,
        "next_transition": "capture_public_source_and_isolated_controlled_observations_then_human_review",
    }


def _load(path: Path, key: str) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"missing_list:{key}:{path}")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Design Corpus V1 near-miss controls")
    parser.add_argument("--plan", default="benchmarks/real_world/v1/capture_plan.json")
    parser.add_argument("--sources", default="benchmarks/real_world/v1/source_feasibility_final.json")
    parser.add_argument("--output", default="benchmarks/real_world/v1/capture_plan_ready.json")
    parser.add_argument("--report", default="benchmarks/real_world/v1/control_design_report.json")
    args = parser.parse_args(argv)

    result = build_ready_plan(
        _load(Path(args.plan), "cases"),
        _load(Path(args.sources), "sources"),
    )
    _write(Path(args.output), result)
    report = {key: value for key, value in result.items() if key != "cases"}
    _write(Path(args.report), report)
    print(json.dumps({
        "ok": result["passed"],
        "cases": result["case_count"],
        "near_miss_controls": result["near_miss_control_count"],
        "ready_to_collect": result["ready_to_collect_count"],
        "family_basis_counts": result["family_basis_counts"],
    }, sort_keys=True))
    if not result["passed"]:
        raise SystemExit("control_design_gate_failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
