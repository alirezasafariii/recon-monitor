from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from analysis_ranking import rank_families
from family_detectors import evaluate_family_detector, execute_detector_intelligence
from family_detectors.registry import DETECTOR_SPECS
from hypothesis_admission import assess_admission
from raw_recon_corpus import load_raw_cases, validate_raw_corpus

RAW_RECON_BENCHMARK_VERSION = "1.0.0"
RAW_RECON_BENCHMARK_RULE_VERSION = "2026.08.11.6.11"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "raw" / "analysis_raw_v1.jsonl"
DEFAULT_MANIFEST = ROOT / "benchmarks" / "raw" / "splits" / "v1.json"

# Pre-registered before blind source collection. These gates are intentionally
# lower than the structured-evidence Golden benchmark because this benchmark
# begins from raw/minimally-normalized artifacts rather than typed evidence.
RAW_QUALITY_GATES: dict[str, tuple[str, float]] = {
    "condition_extraction_precision": ("min", 0.90),
    "condition_extraction_recall": ("min", 0.75),
    "routing_top1_accuracy": ("min", 0.80),
    "routing_top3_accuracy": ("min", 0.95),
    "admission_precision": ("min", 0.93),
    "admission_recall": ("min", 0.75),
    "abstention_accuracy": ("min", 0.90),
    "false_promotion_rate": ("max", 0.07),
    "wrong_family_promotion_rate": ("max", 0.05),
    "end_to_end_accuracy": ("min", 0.80),
    "prior_source_root_overlap_rate": ("max", 0.0),
    "raw_label_leakage_rate": ("max", 0.0),
}


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    header = f"blob {len(data)}\0".encode("utf-8")
    return hashlib.sha1(header + data).hexdigest()


def verify_freeze(manifest_path: str | Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    protected = manifest.get("protected_files") if isinstance(manifest.get("protected_files"), Mapping) else {}
    for relative, expected in protected.items():
        target = ROOT / str(relative)
        if not target.exists():
            errors.append(f"protected file missing: {relative}")
            continue
        actual = _git_blob_sha(target)
        if actual != str(expected):
            errors.append(f"protected file changed after freeze: {relative} expected={expected} actual={actual}")
    gates = manifest.get("acceptance_gates") if isinstance(manifest.get("acceptance_gates"), Mapping) else {}
    canonical_gates = {
        metric: {"direction": direction, "threshold": threshold}
        for metric, (direction, threshold) in RAW_QUALITY_GATES.items()
    }
    if gates != canonical_gates:
        errors.append("acceptance gates differ from benchmark engine pre-registration")
    return {
        "passed": not errors,
        "errors": errors,
        "manifest": manifest,
        "protected_file_count": len(protected),
    }


def _prepare_family_packets(raw: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    execution = execute_detector_intelligence(
        target=str(raw.get("target") or ""),
        endpoint=str(raw.get("endpoint") or ""),
        method=str(raw.get("method") or "UNKNOWN"),
        endpoint_schema=raw.get("endpoint_schema") if isinstance(raw.get("endpoint_schema"), Mapping) else {},
        details=raw.get("details") if isinstance(raw.get("details"), Mapping) else {},
        category=str(raw.get("category") or ""),
        business_context=str(raw.get("business_context") or "general"),
    )
    prepared: dict[str, dict[str, Any]] = {}
    aggregate_support: list[dict[str, Any]] = []
    aggregate_contradict: list[dict[str, Any]] = []
    for family, packet in execution.items():
        scoped = evaluate_family_detector(
            family,
            packet.get("support") or [],
            packet.get("contradict") or [],
            channel="raw_benchmark",
        )
        support = [dict(item) for item in scoped.get("support") or []]
        contradict = [dict(item) for item in scoped.get("contradict") or []]
        assessment = assess_admission(family, support, contradict)
        prepared[family] = {
            "support": support,
            "contradict": contradict,
            "assessment": assessment,
            "raw_rule_ids": list(packet.get("rule_ids") or []),
        }
        aggregate_support.extend(support)
        aggregate_contradict.extend(contradict)
    return prepared, aggregate_support, aggregate_contradict


def evaluate_raw_case(case: Mapping[str, Any]) -> dict[str, Any]:
    family = str(case.get("family") or "")
    kind = str(case.get("case_kind") or "")
    expected = case.get("expected") if isinstance(case.get("expected"), Mapping) else {}
    raw = case.get("raw") if isinstance(case.get("raw"), Mapping) else {}
    packets, support, contradict = _prepare_family_packets(raw)
    rankings = rank_families(support, contradict)
    admitted_families = [
        item_family for item_family, packet in packets.items()
        if bool((packet.get("assessment") or {}).get("admitted"))
    ]
    admitted_families.sort()
    target_packet = packets.get(family, {"support": [], "contradict": [], "assessment": assess_admission(family, [], [])})
    target_support_types = {str(item.get("type") or "") for item in target_packet.get("support") or []}
    target_condition_types = target_support_types & set(DETECTOR_SPECS[family].condition_signals)
    predicted_condition_families = sorted(
        candidate_family
        for candidate_family, packet in packets.items()
        if {str(item.get("type") or "") for item in packet.get("support") or []}
        & set(DETECTOR_SPECS[candidate_family].condition_signals)
    )
    expected_condition_families = [family] if kind == "positive" else []
    expected_condition_signals = {str(value) for value in expected.get("condition_signals") or [] if str(value)}
    signal_hits = sorted(target_condition_types & expected_condition_signals)
    signal_misses = sorted(expected_condition_signals - target_condition_types)

    top1 = str(rankings[0]["family"]) if rankings else ""
    top3 = [str(item["family"]) for item in rankings[:3]]
    rank_required = bool(case.get("rank_required", kind != "sparse_noisy"))
    expected_admitted = bool(expected.get("admitted"))
    target_admitted = family in admitted_families
    wrong_promotions = [value for value in admitted_families if value != family]
    if expected_admitted:
        e2e_pass = target_admitted and not wrong_promotions
    else:
        e2e_pass = not admitted_families

    return {
        "id": str(case.get("id") or ""),
        "source_root": str(case.get("source_root") or ""),
        "source_project": str(case.get("source_project") or ""),
        "family": family,
        "case_kind": kind,
        "rank_required": rank_required,
        "expected_admitted": expected_admitted,
        "target_admitted": target_admitted,
        "admitted_families": admitted_families,
        "wrong_promotions": wrong_promotions,
        "emitted_families": sorted(packets),
        "predicted_condition_families": predicted_condition_families,
        "expected_condition_families": expected_condition_families,
        "target_condition_signals": sorted(target_condition_types),
        "expected_condition_signals": sorted(expected_condition_signals),
        "condition_signal_hits": signal_hits,
        "condition_signal_misses": signal_misses,
        "target_state": str((target_packet.get("assessment") or {}).get("state") or ""),
        "top1": top1,
        "top3": top3,
        "top1_correct": top1 == family,
        "top3_correct": family in top3,
        "end_to_end_pass": e2e_pass,
    }


def run_raw_benchmark(cases: Iterable[Mapping[str, Any]], *, validation: Mapping[str, Any] | None = None) -> dict[str, Any]:
    evaluated = [evaluate_raw_case(case) for case in cases]
    positives = [row for row in evaluated if row["expected_admitted"]]
    negatives = [row for row in evaluated if not row["expected_admitted"]]
    rank_rows = [row for row in evaluated if row["rank_required"]]

    expected_condition_slots = sum(len(row["expected_condition_families"]) for row in evaluated)
    predicted_condition_slots = sum(len(row["predicted_condition_families"]) for row in evaluated)
    condition_tp = sum(
        len(set(row["expected_condition_families"]) & set(row["predicted_condition_families"]))
        for row in evaluated
    )
    condition_precision = _ratio(condition_tp, predicted_condition_slots)
    condition_recall = _ratio(condition_tp, expected_condition_slots)

    admission_tp = sum(1 for row in positives if row["target_admitted"])
    admitted_slots = sum(len(row["admitted_families"]) for row in evaluated)
    admission_fp = admitted_slots - admission_tp
    admission_precision = _ratio(admission_tp, admission_tp + admission_fp)
    admission_recall = _ratio(admission_tp, len(positives))
    abstention = _ratio(sum(1 for row in negatives if not row["admitted_families"]), len(negatives))
    fpr = _ratio(sum(1 for row in negatives if row["admitted_families"]), len(negatives))
    wrong_family = _ratio(sum(1 for row in evaluated if row["wrong_promotions"]), len(evaluated))
    top1 = _ratio(sum(1 for row in rank_rows if row["top1_correct"]), len(rank_rows))
    top3 = _ratio(sum(1 for row in rank_rows if row["top3_correct"]), len(rank_rows))
    end_to_end = _ratio(sum(1 for row in evaluated if row["end_to_end_pass"]), len(evaluated))

    validation = dict(validation or {})
    root_count = max(1, int(validation.get("source_root_count") or 0))
    overlap_rate = _ratio(int(validation.get("prior_source_root_overlap_count") or 0), root_count)
    label_leakage_count = sum(
        1 for error in validation.get("errors") or [] if "engine-native labels leaked" in str(error)
    )
    label_leakage_rate = _ratio(label_leakage_count, len(evaluated))

    metrics = {
        "condition_extraction_precision": round(condition_precision, 6),
        "condition_extraction_recall": round(condition_recall, 6),
        "routing_top1_accuracy": round(top1, 6),
        "routing_top3_accuracy": round(top3, 6),
        "admission_precision": round(admission_precision, 6),
        "admission_recall": round(admission_recall, 6),
        "abstention_accuracy": round(abstention, 6),
        "false_promotion_rate": round(fpr, 6),
        "wrong_family_promotion_rate": round(wrong_family, 6),
        "end_to_end_accuracy": round(end_to_end, 6),
        "prior_source_root_overlap_rate": round(overlap_rate, 6),
        "raw_label_leakage_rate": round(label_leakage_rate, 6),
    }

    gate_failures: list[dict[str, Any]] = []
    for metric, (direction, threshold) in RAW_QUALITY_GATES.items():
        value = float(metrics.get(metric, 0.0))
        failed = value < threshold if direction == "min" else value > threshold
        if failed:
            gate_failures.append({"metric": metric, "value": value, "direction": direction, "threshold": threshold})

    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rank_rows:
        confusion[row["family"]][row["top1"]] += 1
    by_kind: dict[str, Any] = {}
    for kind in ("positive", "near_miss", "secure_negative", "sparse_noisy"):
        subset = [row for row in evaluated if row["case_kind"] == kind]
        by_kind[kind] = {
            "count": len(subset),
            "end_to_end_pass": sum(1 for row in subset if row["end_to_end_pass"]),
            "end_to_end_pass_rate": round(_ratio(sum(1 for row in subset if row["end_to_end_pass"]), len(subset)), 6),
        }
    family_positive = Counter(row["family"] for row in positives)
    family_recall = {
        family: round(_ratio(sum(1 for row in positives if row["family"] == family and row["target_admitted"]), count), 6)
        for family, count in sorted(family_positive.items())
    }

    return {
        "raw_recon_benchmark_version": RAW_RECON_BENCHMARK_VERSION,
        "rule_version": RAW_RECON_BENCHMARK_RULE_VERSION,
        "case_count": len(evaluated),
        "positive_count": len(positives),
        "negative_count": len(negatives),
        "rank_required_count": len(rank_rows),
        "metrics": metrics,
        "quality_gate": {"passed": not gate_failures and bool(validation.get("passed", True)), "failures": gate_failures},
        "corpus_validation": validation,
        "family_positive_recall": family_recall,
        "confusion_matrix": {family: dict(values) for family, values in sorted(confusion.items())},
        "by_kind": by_kind,
        "ranking_errors": [row for row in rank_rows if not row["top1_correct"]],
        "admission_errors": [row for row in evaluated if not row["end_to_end_pass"]],
        "cases": evaluated,
    }


def benchmark_raw_file(
    corpus_path: str | Path = DEFAULT_CORPUS,
    manifest_path: str | Path = DEFAULT_MANIFEST,
    *,
    allow_consumed: bool = False,
) -> dict[str, Any]:
    freeze = verify_freeze(manifest_path)
    if not freeze["passed"]:
        raise RuntimeError("Analysis 6.11 freeze verification failed: " + "; ".join(freeze["errors"]))
    manifest = freeze["manifest"]
    status = str(manifest.get("evaluation_status") or "")
    if status not in {"sealed_unscored", "evaluated_once_consumed"}:
        raise RuntimeError(f"Raw holdout is not sealed for evaluation: status={status!r}")
    if status == "evaluated_once_consumed" and not allow_consumed:
        raise RuntimeError("Raw holdout has already been consumed; rerun only as an explicitly labeled regression with allow_consumed=True")
    cases = load_raw_cases(corpus_path)
    validation = validate_raw_corpus(cases)
    if not validation["passed"]:
        raise RuntimeError("Raw corpus validation failed: " + "; ".join(validation["errors"]))
    report = run_raw_benchmark(cases, validation=validation)
    report["freeze_validation"] = {key: value for key, value in freeze.items() if key != "manifest"}
    report["evaluation_status_at_start"] = status
    report["corpus"] = str(Path(corpus_path))
    report["manifest"] = str(Path(manifest_path))
    return report


def _summary(report: Mapping[str, Any]) -> str:
    metrics = report["metrics"]
    return (
        f"Raw recon benchmark {report['raw_recon_benchmark_version']}: {report['case_count']} cases | "
        f"extractP={metrics['condition_extraction_precision']:.3f} extractR={metrics['condition_extraction_recall']:.3f} "
        f"top1={metrics['routing_top1_accuracy']:.3f} top3={metrics['routing_top3_accuracy']:.3f} "
        f"admitP={metrics['admission_precision']:.3f} admitR={metrics['admission_recall']:.3f} "
        f"abst={metrics['abstention_accuracy']:.3f} FPR={metrics['false_promotion_rate']:.3f} "
        f"wrongFamily={metrics['wrong_family_promotion_rate']:.3f} e2e={metrics['end_to_end_accuracy']:.3f} "
        f"| gate={'PASS' if report['quality_gate']['passed'] else 'FAIL'}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Analysis 6.11 blind raw recon benchmark")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--allow-consumed", action="store_true", help="Regression-only rerun of an already-consumed holdout")
    args = parser.parse_args(argv)
    report = benchmark_raw_file(args.corpus, args.manifest, allow_consumed=args.allow_consumed)
    print(json.dumps(report, indent=2, sort_keys=True) if args.as_json else _summary(report))
    return 2 if args.strict and not report["quality_gate"]["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
