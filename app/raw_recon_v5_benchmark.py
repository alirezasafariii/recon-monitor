from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from analysis_ranking import rank_families
from family_detectors.registry import DETECTOR_SPECS
from hypothesis_admission import assess_admission
from raw_recon_benchmark import RAW_QUALITY_GATES, _prepare_family_packets, run_raw_benchmark
from raw_recon_corpus import ROOT
from raw_recon_v5_corpus import validate_v5_corpus

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.29"
DEFAULT_CORPUS = ROOT / "benchmarks/raw/analysis_raw_v5.jsonl"
DEFAULT_SHORTLIST = ROOT / "benchmarks/raw/sources/v5_shortlist.json"
DEFAULT_FREEZE = ROOT / "benchmarks/raw/sources/v5_freeze_manifest.json"

MULTI_QUALITY_GATES: dict[str, tuple[str, float]] = {
    "multi_exact_admission_set_accuracy": ("min", 0.90),
    "multi_expected_condition_recall": ("min", 0.85),
    "multi_unexpected_promotion_rate": ("max", 0.05),
    "multi_dual_positive_both_admitted_rate": ("min", 0.80),
    "multi_dual_secure_rejection_rate": ("min", 0.95),
    "multi_expected_family_top3_coverage": ("min", 0.90),
}


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _load_cases(path: Path = DEFAULT_CORPUS) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _single_to_legacy(case: Mapping[str, Any]) -> dict[str, Any]:
    family = str(case.get("family") or "")
    expected = case.get("expected") if isinstance(case.get("expected"), Mapping) else {}
    expected_families = {
        str(value) for value in expected.get("admitted_families") or [] if str(value)
    }
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


def _multi_case(case: Mapping[str, Any]) -> dict[str, Any]:
    observations = [
        dict(value)
        for value in case.get("raw_observations") or []
        if isinstance(value, Mapping)
    ]
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
    top1 = str(rankings[0]["family"]) if rankings else ""
    top3 = [str(item["family"]) for item in rankings[:3]]

    expected = case.get("expected") if isinstance(case.get("expected"), Mapping) else {}
    expected_families = sorted(
        {str(value) for value in expected.get("admitted_families") or [] if str(value)}
    )
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
    top3_expected_hits = sorted(set(expected_families) & set(top3))
    exact = admitted == expected_families

    return {
        "id": str(case.get("id") or ""),
        "case_kind": str(case.get("case_kind") or ""),
        "paired_families": list(case.get("paired_families") or []),
        "expected_families": expected_families,
        "admitted_families": admitted,
        "missing_admissions": missing_admissions,
        "unexpected_promotions": unexpected,
        "exact_admission_set": exact,
        "expected_condition_slots": condition_slots,
        "expected_condition_hits": condition_hits,
        "condition_misses": condition_misses,
        "predicted_conditions": predicted_conditions,
        "family_states": family_states,
        "observation_emissions": observation_emissions,
        "top1": top1,
        "top3": top3,
        "expected_top3_slots": len(expected_families),
        "expected_top3_hits": len(top3_expected_hits),
        "expected_top3_families": top3_expected_hits,
        "dual_positive_both_admitted": str(case.get("case_kind") or "") == "dual_positive" and not missing_admissions,
        "dual_secure_rejected": str(case.get("case_kind") or "") == "dual_secure" and not admitted,
    }


def _evaluate_multi(cases: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    evaluated = [_multi_case(case) for case in cases]
    exact = _ratio(sum(1 for row in evaluated if row["exact_admission_set"]), len(evaluated))
    condition_slots = sum(int(row["expected_condition_slots"]) for row in evaluated)
    condition_hits = sum(int(row["expected_condition_hits"]) for row in evaluated)
    unexpected = _ratio(sum(1 for row in evaluated if row["unexpected_promotions"]), len(evaluated))
    dual_positive = [row for row in evaluated if row["case_kind"] == "dual_positive"]
    dual_secure = [row for row in evaluated if row["case_kind"] == "dual_secure"]
    top3_slots = sum(int(row["expected_top3_slots"]) for row in evaluated)
    top3_hits = sum(int(row["expected_top3_hits"]) for row in evaluated)

    metrics = {
        "multi_exact_admission_set_accuracy": round(exact, 6),
        "multi_expected_condition_recall": round(_ratio(condition_hits, condition_slots), 6),
        "multi_unexpected_promotion_rate": round(unexpected, 6),
        "multi_dual_positive_both_admitted_rate": round(
            _ratio(sum(1 for row in dual_positive if row["dual_positive_both_admitted"]), len(dual_positive)), 6
        ),
        "multi_dual_secure_rejection_rate": round(
            _ratio(sum(1 for row in dual_secure if row["dual_secure_rejected"]), len(dual_secure)), 6
        ),
        "multi_expected_family_top3_coverage": round(_ratio(top3_hits, top3_slots), 6),
    }
    failures: list[dict[str, Any]] = []
    for metric, (direction, threshold) in MULTI_QUALITY_GATES.items():
        value = float(metrics[metric])
        failed = value < threshold if direction == "min" else value > threshold
        if failed:
            failures.append({
                "metric": metric,
                "value": value,
                "direction": direction,
                "threshold": threshold,
            })
    return {
        "case_count": len(evaluated),
        "metrics": metrics,
        "quality_gate": {"passed": not failures, "failures": failures},
        "errors": [
            row for row in evaluated
            if not row["exact_admission_set"] or row["condition_misses"] or row["expected_top3_hits"] < row["expected_top3_slots"]
        ],
        "cases": evaluated,
    }


def _canonical_frozen_gates() -> dict[str, Any]:
    return {
        "single_existing_raw_gates": "unchanged RAW_QUALITY_GATES",
        "multi_exact_admission_set_accuracy_min": 0.90,
        "multi_expected_condition_recall_min": 0.85,
        "multi_unexpected_promotion_rate_max": 0.05,
        "multi_dual_positive_both_admitted_min": 0.80,
        "multi_dual_secure_rejection_min": 0.95,
        "multi_expected_family_top3_coverage_min": 0.90,
    }


def run_v5_benchmark(
    *,
    corpus_path: Path = DEFAULT_CORPUS,
    shortlist_path: Path = DEFAULT_SHORTLIST,
    freeze_path: Path = DEFAULT_FREEZE,
) -> dict[str, Any]:
    cases = _load_cases(corpus_path)
    shortlist = json.loads(shortlist_path.read_text(encoding="utf-8"))
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    if str(freeze.get("evaluation_status") or "") != "sealed_unscored":
        raise RuntimeError("v5 first blind requires sealed_unscored freeze state")
    if freeze.get("pre_registered_gates") != _canonical_frozen_gates():
        raise RuntimeError("v5 frozen gates differ from pre-registered evaluator gates")

    validation = validate_v5_corpus(cases, shortlist=shortlist)
    if not validation["passed"]:
        raise RuntimeError("v5 corpus validation failed: " + "; ".join(validation["errors"]))

    singles = [case for case in cases if case.get("case_mode") == "single_family_fresh"]
    multi = [case for case in cases if case.get("case_mode") == "multi_family_hard_case"]
    single_validation = {
        "passed": True,
        "errors": [],
        "source_root_count": validation["single_source_root_count"],
        "prior_source_root_overlap_count": validation["prior_source_root_overlap_count"],
        "label_leakage_count": validation["label_leakage_count"],
    }
    single_report = run_raw_benchmark(
        [_single_to_legacy(case) for case in singles],
        validation=single_validation,
    )
    multi_report = _evaluate_multi(multi)
    passed = bool(single_report["quality_gate"]["passed"] and multi_report["quality_gate"]["passed"])
    return {
        "v5_benchmark_version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v5_single_consumption",
        "case_count": len(cases),
        "single_case_count": len(singles),
        "multi_case_count": len(multi),
        "corpus_validation": validation,
        "single_family": single_report,
        "multi_family": multi_report,
        "quality_gate": {
            "passed": passed,
            "single_passed": bool(single_report["quality_gate"]["passed"]),
            "multi_passed": bool(multi_report["quality_gate"]["passed"]),
            "single_failures": list(single_report["quality_gate"]["failures"]),
            "multi_failures": list(multi_report["quality_gate"]["failures"]),
        },
        "single_quality_gates": {
            metric: {"direction": direction, "threshold": threshold}
            for metric, (direction, threshold) in RAW_QUALITY_GATES.items()
        },
        "multi_quality_gates": {
            metric: {"direction": direction, "threshold": threshold}
            for metric, (direction, threshold) in MULTI_QUALITY_GATES.items()
        },
    }


__all__ = [
    "VERSION",
    "RULE_VERSION",
    "MULTI_QUALITY_GATES",
    "run_v5_benchmark",
]
