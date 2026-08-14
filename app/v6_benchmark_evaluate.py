from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from analysis_ranking import rank_families
from family_detectors.registry import DETECTOR_SPECS
from hypothesis_admission import assess_admission
from raw_recon_benchmark import _prepare_family_packets, run_raw_benchmark
from raw_recon_corpus import ROOT
from v6_benchmark_validate import validate_v6_corpus
from v6_freeze_verify import verify_freeze

VERSION = "1.1.0"
RULE_VERSION = "2026.08.14.6.31.2"
DEFAULT_CORPUS = ROOT / "benchmarks/raw/analysis_raw_v6.jsonl"
DEFAULT_SHORTLIST = ROOT / "benchmarks/raw/sources/v6_shortlist.json"
DEFAULT_PROTOCOL = ROOT / "benchmarks/raw/sources/v6_protocol.json"
DEFAULT_FREEZE = ROOT / "benchmarks/raw/sources/v6_corpus_freeze.json"
DEFAULT_EVALUATOR_FREEZE = ROOT / "benchmarks/raw/sources/v6_evaluator_freeze.json"


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_cases(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _gate_spec(protocol: Mapping[str, Any], section: str) -> dict[str, tuple[str, float]]:
    raw = protocol.get(section) if isinstance(protocol.get(section), Mapping) else {}
    gates: dict[str, tuple[str, float]] = {}
    for key, value in raw.items():
        metric = str(key)
        if metric.endswith("_min"):
            gates[metric[:-4]] = ("min", float(value))
        elif metric.endswith("_max"):
            gates[metric[:-4]] = ("max", float(value))
        else:
            raise RuntimeError(f"unsupported v6 gate name: {metric}")
    return gates


def _apply_gates(metrics: Mapping[str, Any], gates: Mapping[str, tuple[str, float]]) -> dict[str, Any]:
    failures: list[dict[str, Any]] = []
    for metric, (direction, threshold) in gates.items():
        if metric not in metrics:
            failures.append({"metric": metric, "reason": "missing_metric", "direction": direction, "threshold": threshold})
            continue
        value = float(metrics[metric])
        failed = value < threshold if direction == "min" else value > threshold
        if failed:
            failures.append({"metric": metric, "value": value, "direction": direction, "threshold": threshold})
    return {"passed": not failures, "failures": failures}


def _single_to_legacy(case: Mapping[str, Any]) -> dict[str, Any]:
    family = str(case.get("family") or "")
    expected = case.get("expected") if isinstance(case.get("expected"), Mapping) else {}
    expected_families = {str(value) for value in expected.get("admitted_families") or [] if str(value)}
    condition_map = expected.get("condition_signals") if isinstance(expected.get("condition_signals"), Mapping) else {}
    return {
        "id": case.get("id"),
        "source_root": case.get("source_root"),
        "source_project": case.get("source_project"),
        "source_date": case.get("source_date"),
        "family": family,
        "case_kind": case.get("case_kind"),
        "rank_required": case.get("rank_required"),
        "provenance": case.get("provenance"),
        "raw": case.get("raw"),
        "expected": {
            "family": family,
            "admitted": family in expected_families,
            "condition_signals": list(condition_map.get(family) or []),
        },
    }


def _evaluate_multi_case(case: Mapping[str, Any], *, top_n: int) -> dict[str, Any]:
    observations = [dict(value) for value in case.get("raw_observations") or [] if isinstance(value, Mapping)]
    combined: dict[str, dict[str, list[dict[str, Any]]]] = {}
    aggregate_support: list[dict[str, Any]] = []
    aggregate_contradict: list[dict[str, Any]] = []
    observation_emissions: list[list[str]] = []

    for observation in observations:
        packets, support, contradict = _prepare_family_packets(observation)
        observation_emissions.append(sorted(packets))
        aggregate_support.extend(dict(item) for item in support)
        aggregate_contradict.extend(dict(item) for item in contradict)
        for family, packet in packets.items():
            bucket = combined.setdefault(family, {"support": [], "contradict": []})
            bucket["support"].extend(dict(item) for item in packet.get("support") or [])
            bucket["contradict"].extend(dict(item) for item in packet.get("contradict") or [])

    admitted: list[str] = []
    family_states: dict[str, str] = {}
    predicted_conditions: dict[str, list[str]] = {}
    for family, packet in combined.items():
        assessment = assess_admission(family, packet["support"], packet["contradict"])
        family_states[family] = str(assessment.get("state") or "")
        if bool(assessment.get("admitted")):
            admitted.append(family)
        support_types = {str(item.get("type") or "") for item in packet["support"]}
        condition_types = sorted(support_types & set(DETECTOR_SPECS[family].condition_signals))
        if condition_types:
            predicted_conditions[family] = condition_types
    admitted.sort()

    rankings = rank_families(aggregate_support, aggregate_contradict)
    top = [str(item["family"]) for item in rankings[:top_n]]

    expected = case.get("expected") if isinstance(case.get("expected"), Mapping) else {}
    expected_families = sorted({str(value) for value in expected.get("admitted_families") or [] if str(value)})
    expected_conditions_raw = expected.get("condition_signals") if isinstance(expected.get("condition_signals"), Mapping) else {}
    expected_conditions = {
        str(family): sorted({str(value) for value in values or [] if str(value)})
        for family, values in expected_conditions_raw.items()
    }

    condition_slots = 0
    condition_hits = 0
    condition_misses: dict[str, list[str]] = {}
    for family, values in expected_conditions.items():
        predicted = set(predicted_conditions.get(family, []))
        condition_slots += len(values)
        missing = sorted(set(values) - predicted)
        condition_hits += len(values) - len(missing)
        if missing:
            condition_misses[family] = missing

    unexpected = sorted(set(admitted) - set(expected_families))
    missing_admissions = sorted(set(expected_families) - set(admitted))
    top_hits = sorted(set(expected_families) & set(top))
    return {
        "id": str(case.get("id") or ""),
        "case_kind": str(case.get("case_kind") or ""),
        "expected_families": expected_families,
        "admitted_families": admitted,
        "missing_admissions": missing_admissions,
        "unexpected_promotions": unexpected,
        "exact_admission_set": admitted == expected_families,
        "expected_condition_slots": condition_slots,
        "expected_condition_hits": condition_hits,
        "condition_misses": condition_misses,
        "predicted_conditions": predicted_conditions,
        "family_states": family_states,
        "observation_emissions": observation_emissions,
        "top": top,
        "expected_top_slots": len(expected_families),
        "expected_top_hits": len(top_hits),
        "expected_top_families": top_hits,
    }


def _evaluate_pair(cases: Iterable[Mapping[str, Any]], gates: Mapping[str, tuple[str, float]]) -> dict[str, Any]:
    evaluated = [_evaluate_multi_case(case, top_n=3) for case in cases]
    condition_slots = sum(int(row["expected_condition_slots"]) for row in evaluated)
    condition_hits = sum(int(row["expected_condition_hits"]) for row in evaluated)
    top_slots = sum(int(row["expected_top_slots"]) for row in evaluated)
    top_hits = sum(int(row["expected_top_hits"]) for row in evaluated)
    dual_positive = [row for row in evaluated if row["case_kind"] == "dual_positive"]
    dual_secure = [row for row in evaluated if row["case_kind"] == "dual_secure"]
    metrics = {
        "exact_admission_set_accuracy": round(_ratio(sum(1 for row in evaluated if row["exact_admission_set"]), len(evaluated)), 6),
        "expected_condition_recall": round(_ratio(condition_hits, condition_slots), 6),
        "unexpected_promotion_rate": round(_ratio(sum(1 for row in evaluated if row["unexpected_promotions"]), len(evaluated)), 6),
        "dual_positive_both_admitted_rate": round(_ratio(sum(1 for row in dual_positive if not row["missing_admissions"]), len(dual_positive)), 6),
        "dual_secure_rejection_rate": round(_ratio(sum(1 for row in dual_secure if not row["admitted_families"]), len(dual_secure)), 6),
        "expected_family_top3_coverage": round(_ratio(top_hits, top_slots), 6),
    }
    return {
        "case_count": len(evaluated),
        "metrics": metrics,
        "quality_gate": _apply_gates(metrics, gates),
        "errors": [row for row in evaluated if not row["exact_admission_set"] or row["condition_misses"]],
        "cases": evaluated,
    }


def _evaluate_triad(cases: Iterable[Mapping[str, Any]], gates: Mapping[str, tuple[str, float]]) -> dict[str, Any]:
    evaluated = [_evaluate_multi_case(case, top_n=5) for case in cases]
    condition_slots = sum(int(row["expected_condition_slots"]) for row in evaluated)
    condition_hits = sum(int(row["expected_condition_hits"]) for row in evaluated)
    triple_positive = [row for row in evaluated if row["case_kind"] == "triple_positive"]
    triple_secure = [row for row in evaluated if row["case_kind"] == "triple_secure"]

    top3_slots = 0
    top3_hits = 0
    top5_slots = 0
    top5_hits = 0
    for row in evaluated:
        expected = set(row["expected_families"])
        if not expected:
            continue
        top3_slots += len(expected)
        top5_slots += len(expected)
        top3_hits += len(expected & set(row["top"][:3]))
        top5_hits += len(expected & set(row["top"][:5]))

    metrics = {
        "exact_admission_set_accuracy": round(_ratio(sum(1 for row in evaluated if row["exact_admission_set"]), len(evaluated)), 6),
        "expected_condition_recall": round(_ratio(condition_hits, condition_slots), 6),
        "unexpected_promotion_rate": round(_ratio(sum(1 for row in evaluated if row["unexpected_promotions"]), len(evaluated)), 6),
        "triple_positive_all_admitted_rate": round(_ratio(sum(1 for row in triple_positive if not row["missing_admissions"]), len(triple_positive)), 6),
        "triple_secure_rejection_rate": round(_ratio(sum(1 for row in triple_secure if not row["admitted_families"]), len(triple_secure)), 6),
        "expected_family_top3_coverage": round(_ratio(top3_hits, top3_slots), 6),
        "expected_family_top5_coverage": round(_ratio(top5_hits, top5_slots), 6),
    }
    return {
        "case_count": len(evaluated),
        "metrics": metrics,
        "quality_gate": _apply_gates(metrics, gates),
        "errors": [row for row in evaluated if not row["exact_admission_set"] or row["condition_misses"]],
        "cases": evaluated,
    }


def _verify_evaluator_freeze(
    path: Path = DEFAULT_EVALUATOR_FREEZE,
    *,
    corpus_freeze_path: Path = DEFAULT_FREEZE,
) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError("v6 evaluator freeze artifact is missing")
    frozen = json.loads(path.read_text(encoding="utf-8"))
    if frozen.get("first_blind_evaluator_frozen") is not True:
        raise RuntimeError("v6 evaluator is not frozen")
    if frozen.get("scoring_executed") is not False or frozen.get("first_blind_consumed") is not False:
        raise RuntimeError("v6 evaluator freeze must be unscored and unconsumed")

    expected_eval = str(frozen.get("evaluator_sha256") or "")
    expected_protocol = str(frozen.get("protocol_sha256") or "")
    expected_corpus_freeze = str(frozen.get("corpus_freeze_sha256") or "")
    if not expected_eval or expected_eval != _sha256(Path(__file__)):
        raise RuntimeError("v6 evaluator code changed after evaluator freeze")
    if not expected_protocol or expected_protocol != _sha256(DEFAULT_PROTOCOL):
        raise RuntimeError("v6 protocol changed after evaluator freeze")
    if not expected_corpus_freeze or expected_corpus_freeze != _sha256(corpus_freeze_path):
        raise RuntimeError("v6 corpus freeze changed after evaluator freeze")
    return frozen


def run_v6_benchmark(
    *,
    corpus_path: Path = DEFAULT_CORPUS,
    shortlist_path: Path = DEFAULT_SHORTLIST,
    protocol_path: Path = DEFAULT_PROTOCOL,
    freeze_path: Path = DEFAULT_FREEZE,
) -> dict[str, Any]:
    freeze_path = Path(freeze_path)
    freeze_check = verify_freeze(freeze_path, require_freeze=True, require_evaluator_frozen=True)
    if not freeze_check["passed"]:
        raise RuntimeError("v6 corpus/evaluator freeze verification failed: " + "; ".join(freeze_check["errors"]))
    evaluator_freeze = _verify_evaluator_freeze(corpus_freeze_path=freeze_path)

    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    shortlist = json.loads(shortlist_path.read_text(encoding="utf-8"))
    cases = _load_cases(corpus_path)
    validation = validate_v6_corpus(cases, shortlist, require_literal_single_capture=True)
    if not validation["passed"]:
        raise RuntimeError("v6 corpus validation failed: " + "; ".join(validation["errors"]))

    singles = [case for case in cases if case.get("case_mode") == "single_family_fresh_v6"]
    pairs = [case for case in cases if case.get("case_mode") == "2_family_interference_v6"]
    triads = [case for case in cases if case.get("case_mode") == "3_family_interference_v6"]
    if (len(singles), len(pairs), len(triads)) != (144, 72, 60):
        raise RuntimeError("v6 evaluator cardinality mismatch")

    single_validation = {
        "passed": True,
        "errors": [],
        "source_root_count": 36,
        "prior_source_root_overlap_count": 0,
        "label_leakage_count": 0,
    }
    single_report = run_raw_benchmark([_single_to_legacy(case) for case in singles], validation=single_validation)
    single_metrics = dict(single_report.get("metrics") or {})
    single_gates = _gate_spec(protocol, "single_quality_gates")
    single_gate = _apply_gates(single_metrics, single_gates)
    single_report["quality_gate"] = single_gate

    pair_gates = _gate_spec(protocol, "pair_quality_gates")
    triad_gates = _gate_spec(protocol, "triad_quality_gates")
    pair_report = _evaluate_pair(pairs, pair_gates)
    triad_report = _evaluate_triad(triads, triad_gates)
    passed = bool(single_gate["passed"] and pair_report["quality_gate"]["passed"] and triad_report["quality_gate"]["passed"])

    return {
        "v6_benchmark_version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_single_consumption",
        "case_count": len(cases),
        "single_case_count": len(singles),
        "pair_case_count": len(pairs),
        "triad_case_count": len(triads),
        "corpus_validation": validation,
        "freeze_validation": freeze_check,
        "evaluator_freeze": {
            "first_blind_evaluator_frozen": evaluator_freeze.get("first_blind_evaluator_frozen"),
            "evaluator_sha256": evaluator_freeze.get("evaluator_sha256"),
            "protocol_sha256": evaluator_freeze.get("protocol_sha256"),
            "corpus_freeze_sha256": evaluator_freeze.get("corpus_freeze_sha256"),
        },
        "single_family": single_report,
        "pair_family": pair_report,
        "triad_family": triad_report,
        "quality_gate": {
            "passed": passed,
            "single_passed": bool(single_gate["passed"]),
            "pair_passed": bool(pair_report["quality_gate"]["passed"]),
            "triad_passed": bool(triad_report["quality_gate"]["passed"]),
            "single_failures": list(single_gate["failures"]),
            "pair_failures": list(pair_report["quality_gate"]["failures"]),
            "triad_failures": list(triad_report["quality_gate"]["failures"]),
        },
        "scoring_executed": True,
        "first_blind_consumed": True,
    }


__all__ = ["VERSION", "RULE_VERSION", "run_v6_benchmark"]
