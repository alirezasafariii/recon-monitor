from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from analysis_standards import FAMILY_STANDARDS, validate_family_standards
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission

BENCHMARK_ENGINE_VERSION = "2.0.0"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "golden" / "analysis_golden_v1.jsonl"
HARD_CORPUS = ROOT / "benchmarks" / "golden" / "analysis_golden_v2.jsonl"
DEFAULT_RUN_CORPUS = HARD_CORPUS

DEFAULT_QUALITY_GATES: dict[str, float] = {
    "precision": 0.95,
    "recall": 0.90,
    "top1_accuracy": 0.90,
    "top3_accuracy": 0.98,
    "abstention_accuracy": 0.95,
    "false_promotion_rate": 0.05,
    "macro_family_recall": 0.85,
    "brier_score": 0.12,
    "ece": 0.12,
    "standards_coverage": 1.0,
}
HARD_QUALITY_GATES: dict[str, float] = {
    "hard_top1_accuracy": 0.90,
    "hard_top3_accuracy": 0.98,
    "hard_abstention_accuracy": 0.95,
    "confounder_leak_rate": 0.05,
}


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def load_golden_cases(path: str | Path = DEFAULT_CORPUS) -> list[dict[str, Any]]:
    source = Path(path)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        row = json.loads(text)
        case_id = str(row.get("id") or "").strip()
        if not case_id:
            raise ValueError(f"Golden case on line {line_no} has no id")
        if case_id in seen:
            raise ValueError(f"Duplicate golden case id: {case_id}")
        seen.add(case_id)
        family = str(row.get("family") or "")
        if family not in FAMILY_ADMISSION_POLICIES:
            raise ValueError(f"Golden case {case_id} references unknown family: {family}")
        kind = str(row.get("case_kind") or "")
        if kind not in {"positive", "near_miss", "secure_negative"}:
            raise ValueError(f"Golden case {case_id} has unsupported case_kind: {kind}")
        expected = row.get("expected") if isinstance(row.get("expected"), Mapping) else {}
        if str(expected.get("family") or "") != family:
            raise ValueError(f"Golden case {case_id} expected family must equal case family")
        confounders = row.get("confounders")
        if confounders is not None:
            if not isinstance(confounders, list) or any(str(value) not in FAMILY_ADMISSION_POLICIES for value in confounders):
                raise ValueError(f"Golden case {case_id} has invalid confounders")
            if family in {str(value) for value in confounders}:
                raise ValueError(f"Golden case {case_id} lists expected family as a confounder")
        rows.append(row)
    if not rows:
        raise ValueError(f"Golden corpus is empty: {source}")
    return rows


def family_compatibility(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in (contradict or [])]
    assessment = assess_admission(family, support_items, contradict_items)
    policy = FAMILY_ADMISSION_POLICIES[family]
    required_count = max(1, len(policy.get("required", [])))
    satisfied_count = len(assessment.get("required_satisfied") or [])
    coverage = satisfied_count / required_count
    required_sources = max(1, int(policy.get("min_independent_sources", 1)))
    source_ratio = min(1.0, int(assessment.get("independent_sources") or 0) / required_sources)
    blocking = len(assessment.get("blocking_contradictions") or [])

    # Compatibility is a ranking signal, not a vulnerability probability.
    score = 0.68 * coverage + 0.14 * source_ratio
    if assessment.get("admitted"):
        score += 0.18
    if blocking:
        score -= min(0.30, 0.16 + 0.05 * blocking)
    score = _clamp(score)
    return {
        "family": family,
        "score": round(score, 6),
        "coverage": round(coverage, 6),
        "source_ratio": round(source_ratio, 6),
        "assessment": assessment,
    }


def _admission_confidence(assessment: Mapping[str, Any]) -> float:
    """Confidence that the vulnerability condition is established, not family similarity."""
    if assessment.get("admitted"):
        return 0.96
    state = str(assessment.get("state") or "")
    if state == "shadow_contradicted":
        return 0.04
    satisfied = len(assessment.get("required_satisfied") or [])
    missing = len(assessment.get("required_missing") or [])
    coverage = satisfied / max(1, satisfied + missing)
    if state == "shadow_partial":
        return round(min(0.28, 0.06 + 0.24 * coverage), 6)
    return 0.04


def evaluate_case(case: Mapping[str, Any]) -> dict[str, Any]:
    support = case.get("support") if isinstance(case.get("support"), list) else []
    contradict = case.get("contradict") if isinstance(case.get("contradict"), list) else []
    rankings = [family_compatibility(family, support, contradict) for family in FAMILY_ADMISSION_POLICIES]
    rankings.sort(
        key=lambda item: (
            float(item["score"]),
            bool(item["assessment"].get("admitted")),
            str(item["family"]),
        ),
        reverse=True,
    )
    expected = case.get("expected") if isinstance(case.get("expected"), Mapping) else {}
    expected_family = str(expected.get("family") or case.get("family") or "")
    expected_admitted = bool(expected.get("admitted"))
    target = next(item for item in rankings if item["family"] == expected_family)
    admitted_families = [item["family"] for item in rankings if item["assessment"].get("admitted")]
    top = [item["family"] for item in rankings[:3]]
    acceptable_top = {str(value) for value in case.get("acceptable_top_families", []) if str(value)}
    if not acceptable_top:
        acceptable_top = {expected_family}
    confounders = [str(value) for value in case.get("confounders", []) if str(value)]
    predicted_positive = bool(admitted_families)
    correct_admission = bool(target["assessment"].get("admitted")) == expected_admitted
    no_wrong_promotion = not any(family != expected_family for family in admitted_families)
    if not expected_admitted:
        no_wrong_promotion = not admitted_families
    top1_family = rankings[0]["family"] if rankings else ""
    confounder_leaks = [family for family in admitted_families if family in set(confounders)]
    return {
        "id": str(case.get("id") or ""),
        "family": expected_family,
        "case_kind": str(case.get("case_kind") or ""),
        "difficulty": str(case.get("difficulty") or "seed"),
        "rank_required": bool(case.get("rank_required", True)),
        "confounders": confounders,
        "confounder_leaks": confounder_leaks,
        "expected_admitted": expected_admitted,
        "predicted_positive": predicted_positive,
        "admitted_families": admitted_families,
        "expected_family_score": float(target["score"]),
        "expected_family_confidence": _admission_confidence(target["assessment"]),
        "expected_family_state": str(target["assessment"].get("state") or ""),
        "expected_family_standards": target["assessment"].get("standards") or {},
        "top1": top1_family,
        "top3": top,
        "top1_correct": top1_family in acceptable_top,
        "top3_correct": bool(acceptable_top & set(top)),
        "correct_admission": correct_admission,
        "no_wrong_promotion": no_wrong_promotion,
        "pass": correct_admission and no_wrong_promotion and not confounder_leaks,
    }


def _safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _calibration_metrics(rows: list[dict[str, Any]], bins: int = 5) -> tuple[float, float]:
    labeled = [row for row in rows if row["case_kind"] in {"positive", "near_miss", "secure_negative"}]
    if not labeled:
        return 0.0, 0.0
    brier = sum(
        (row["expected_family_confidence"] - (1.0 if row["expected_admitted"] else 0.0)) ** 2
        for row in labeled
    ) / len(labeled)
    ece = 0.0
    for index in range(bins):
        low = index / bins
        high = (index + 1) / bins
        bucket = [
            row for row in labeled
            if low <= row["expected_family_confidence"] < high
            or (index == bins - 1 and row["expected_family_confidence"] == 1.0)
        ]
        if not bucket:
            continue
        confidence = sum(row["expected_family_confidence"] for row in bucket) / len(bucket)
        accuracy = sum(1.0 if row["expected_admitted"] else 0.0 for row in bucket) / len(bucket)
        ece += (len(bucket) / len(labeled)) * abs(confidence - accuracy)
    return round(brier, 6), round(ece, 6)


def run_benchmark(cases: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    evaluated = [evaluate_case(case) for case in cases]
    positives = [row for row in evaluated if row["expected_admitted"]]
    negatives = [row for row in evaluated if not row["expected_admitted"]]

    tp = sum(1 for row in positives if row["family"] in row["admitted_families"])
    prediction_pairs = sum(len(row["admitted_families"]) for row in evaluated)
    fp = prediction_pairs - tp
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, len(positives))
    labeled_rank = [row for row in evaluated if row["family"] and row["rank_required"]]
    top1 = _safe_ratio(sum(1 for row in labeled_rank if row["top1_correct"]), len(labeled_rank))
    top3 = _safe_ratio(sum(1 for row in labeled_rank if row["top3_correct"]), len(labeled_rank))
    abstention = _safe_ratio(sum(1 for row in negatives if not row["admitted_families"]), len(negatives))
    false_promotion_rate = _safe_ratio(sum(1 for row in negatives if row["admitted_families"]), len(negatives))

    family_positive: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in positives:
        family_positive[row["family"]].append(row)
    family_recalls = {
        family: _safe_ratio(sum(1 for row in rows if family in row["admitted_families"]), len(rows))
        for family, rows in sorted(family_positive.items())
    }
    macro_family_recall = sum(family_recalls.values()) / len(family_recalls) if family_recalls else 0.0
    brier, ece = _calibration_metrics(evaluated)

    hard = [row for row in evaluated if row["difficulty"] == "hard"]
    hard_rank = [row for row in hard if row["rank_required"]]
    hard_negatives = [row for row in hard if not row["expected_admitted"]]
    hard_top1 = _safe_ratio(sum(1 for row in hard_rank if row["top1_correct"]), len(hard_rank))
    hard_top3 = _safe_ratio(sum(1 for row in hard_rank if row["top3_correct"]), len(hard_rank))
    hard_abstention = _safe_ratio(
        sum(1 for row in hard_negatives if not row["admitted_families"]),
        len(hard_negatives),
    )
    confounder_slots = sum(len(row["confounders"]) for row in hard)
    confounder_leaks = sum(len(row["confounder_leaks"]) for row in hard)
    confounder_leak_rate = _safe_ratio(confounder_leaks, confounder_slots)

    standards_errors = validate_family_standards(FAMILY_ADMISSION_POLICIES)
    standards_coverage = 1.0 if not standards_errors and set(FAMILY_STANDARDS) == set(FAMILY_ADMISSION_POLICIES) else 0.0

    by_kind: dict[str, dict[str, Any]] = {}
    for kind in ("positive", "near_miss", "secure_negative"):
        subset = [row for row in evaluated if row["case_kind"] == kind]
        passed = sum(1 for row in subset if row["pass"])
        by_kind[kind] = {
            "count": len(subset),
            "pass": passed,
            "pass_rate": round(_safe_ratio(passed, len(subset)), 6),
        }

    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in hard_rank:
        confusion[row["family"]][row["top1"]] += 1

    metrics = {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "top1_accuracy": round(top1, 6),
        "top3_accuracy": round(top3, 6),
        "abstention_accuracy": round(abstention, 6),
        "false_promotion_rate": round(false_promotion_rate, 6),
        "macro_family_recall": round(macro_family_recall, 6),
        "brier_score": brier,
        "ece": ece,
        "standards_coverage": round(standards_coverage, 6),
        "hard_top1_accuracy": round(hard_top1, 6),
        "hard_top3_accuracy": round(hard_top3, 6),
        "hard_abstention_accuracy": round(hard_abstention, 6),
        "confounder_leak_rate": round(confounder_leak_rate, 6),
    }
    return {
        "benchmark_engine_version": BENCHMARK_ENGINE_VERSION,
        "case_count": len(evaluated),
        "positive_count": len(positives),
        "negative_count": len(negatives),
        "family_count": len(family_positive),
        "hard_case_count": len(hard),
        "hard_negative_count": len(hard_negatives),
        "confounder_slots": confounder_slots,
        "confounder_leaks": confounder_leaks,
        "metrics": metrics,
        "family_recall": family_recalls,
        "hard_confusion_matrix": {family: dict(values) for family, values in sorted(confusion.items())},
        "standards_errors": standards_errors,
        "by_kind": by_kind,
        "failures": [row for row in evaluated if not row["pass"]],
        "cases": evaluated,
    }


def quality_gate(report: Mapping[str, Any], thresholds: Mapping[str, float] | None = None) -> dict[str, Any]:
    gates = dict(DEFAULT_QUALITY_GATES)
    if int(report.get("hard_case_count") or 0) > 0:
        gates.update(HARD_QUALITY_GATES)
    if thresholds:
        gates.update({str(key): float(value) for key, value in thresholds.items()})
    metrics = report.get("metrics") if isinstance(report.get("metrics"), Mapping) else {}
    failures: list[dict[str, Any]] = []
    lower_is_better = {"false_promotion_rate", "brier_score", "ece", "confounder_leak_rate"}
    for metric, threshold in gates.items():
        value = float(metrics.get(metric, math.inf if metric in lower_is_better else -math.inf))
        ok = value <= threshold if metric in lower_is_better else value >= threshold
        if not ok:
            failures.append({
                "metric": metric,
                "value": value,
                "threshold": threshold,
                "direction": "max" if metric in lower_is_better else "min",
            })
    return {"passed": not failures, "thresholds": gates, "failures": failures}


def benchmark_file(path: str | Path = DEFAULT_CORPUS) -> dict[str, Any]:
    report = run_benchmark(load_golden_cases(path))
    report["quality_gate"] = quality_gate(report)
    report["corpus"] = str(Path(path))
    return report


def _summary(report: Mapping[str, Any]) -> str:
    metrics = report["metrics"]
    gate = report["quality_gate"]
    hard = ""
    if int(report.get("hard_case_count") or 0):
        hard = (
            f" hardTop1={metrics['hard_top1_accuracy']:.3f}"
            f" hardTop3={metrics['hard_top3_accuracy']:.3f}"
            f" hardAbst={metrics['hard_abstention_accuracy']:.3f}"
            f" confLeak={metrics['confounder_leak_rate']:.3f}"
        )
    return (
        f"Golden benchmark {report['benchmark_engine_version']}: {report['case_count']} cases / "
        f"{report['family_count']} positive families | precision={metrics['precision']:.3f} "
        f"recall={metrics['recall']:.3f} top1={metrics['top1_accuracy']:.3f} "
        f"top3={metrics['top3_accuracy']:.3f} abstention={metrics['abstention_accuracy']:.3f} "
        f"FPR={metrics['false_promotion_rate']:.3f} Brier={metrics['brier_score']:.3f} "
        f"ECE={metrics['ece']:.3f} standards={metrics['standards_coverage']:.3f}{hard} "
        f"| gate={'PASS' if gate['passed'] else 'FAIL'}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Recon Monitor Analysis Golden Dataset benchmark")
    parser.add_argument("--corpus", default=str(DEFAULT_RUN_CORPUS))
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when the benchmark quality gate fails")
    args = parser.parse_args(argv)
    report = benchmark_file(args.corpus)
    print(json.dumps(report, indent=2, sort_keys=True) if args.as_json else _summary(report))
    return 2 if args.strict and not report["quality_gate"]["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
