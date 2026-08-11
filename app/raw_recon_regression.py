from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_benchmark import run_raw_benchmark
from raw_recon_corpus import load_raw_cases, validate_raw_corpus
from raw_recon_observability import analyze_variant_observability

REGRESSION_ENGINE_VERSION = "1.0.0"
REGRESSION_RULE_VERSION = "2026.08.11.6.12"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "raw" / "analysis_raw_v1.jsonl"
DEFAULT_HISTORICAL_REPORT = ROOT / "benchmarks" / "raw" / "reports" / "analysis_raw_v1_postfreeze_report.json"

SAFETY_METRICS = (
    "condition_extraction_precision",
    "admission_precision",
    "abstention_accuracy",
)
MAX_METRICS = (
    "false_promotion_rate",
    "wrong_family_promotion_rate",
)
IMPROVEMENT_METRICS = (
    "condition_extraction_recall",
    "admission_recall",
    "routing_top1_accuracy",
    "routing_top3_accuracy",
    "end_to_end_accuracy",
)


def run_consumed_v1_regression(
    corpus_path: str | Path = DEFAULT_CORPUS,
    historical_report_path: str | Path = DEFAULT_HISTORICAL_REPORT,
) -> dict[str, Any]:
    cases = load_raw_cases(corpus_path)
    validation = validate_raw_corpus(cases)
    if not validation["passed"]:
        raise RuntimeError("Consumed raw corpus validation failed: " + "; ".join(validation["errors"]))
    current = run_raw_benchmark(cases, validation=validation)
    historical = json.loads(Path(historical_report_path).read_text(encoding="utf-8"))
    historical_metrics = historical.get("metrics") if isinstance(historical.get("metrics"), Mapping) else {}
    current_metrics = current["metrics"]

    failures: list[dict[str, Any]] = []
    for metric in SAFETY_METRICS:
        old = float(historical_metrics.get(metric, 0.0))
        new = float(current_metrics.get(metric, 0.0))
        if new < old:
            failures.append({"metric": metric, "historical": old, "current": new, "rule": "must_not_decrease"})
    for metric in MAX_METRICS:
        old = float(historical_metrics.get(metric, 0.0))
        new = float(current_metrics.get(metric, 0.0))
        if new > old:
            failures.append({"metric": metric, "historical": old, "current": new, "rule": "must_not_increase"})

    deltas = {
        metric: round(float(current_metrics.get(metric, 0.0)) - float(historical_metrics.get(metric, 0.0)), 6)
        for metric in sorted(set(SAFETY_METRICS + MAX_METRICS + IMPROVEMENT_METRICS))
    }
    observability = analyze_variant_observability(cases)
    return {
        "regression_engine_version": REGRESSION_ENGINE_VERSION,
        "rule_version": REGRESSION_RULE_VERSION,
        "evaluation_status": "consumed_diagnostic_regression",
        "fresh_or_blind_claim_allowed": False,
        "historical_report": str(Path(historical_report_path)),
        "historical_metrics": dict(historical_metrics),
        "current_metrics": dict(current_metrics),
        "metric_deltas": deltas,
        "safety_regression": {"passed": not failures, "failures": failures},
        "observability": observability,
        "current_report": current,
        "note": "Analysis raw v1 was consumed by the single Analysis 6.11 fresh evaluation. This run is development regression only and must never be described as fresh or blind.",
    }


def _summary(report: Mapping[str, Any]) -> str:
    current = report["current_metrics"]
    delta = report["metric_deltas"]
    obs = report["observability"]
    return (
        "Consumed raw v1 regression: "
        f"extractP={current['condition_extraction_precision']:.3f} "
        f"extractR={current['condition_extraction_recall']:.3f} ({delta['condition_extraction_recall']:+.3f}) "
        f"top1={current['routing_top1_accuracy']:.3f} ({delta['routing_top1_accuracy']:+.3f}) "
        f"top3={current['routing_top3_accuracy']:.3f} ({delta['routing_top3_accuracy']:+.3f}) "
        f"admitP={current['admission_precision']:.3f} "
        f"admitR={current['admission_recall']:.3f} ({delta['admission_recall']:+.3f}) "
        f"abst={current['abstention_accuracy']:.3f} FPR={current['false_promotion_rate']:.3f} "
        f"collisions={obs['collision_root_count']}/{obs['source_root_count']} "
        f"| safety={'PASS' if report['safety_regression']['passed'] else 'FAIL'}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Analysis 6.12 regression on consumed Analysis 6.11 raw v1")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--historical-report", default=str(DEFAULT_HISTORICAL_REPORT))
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--strict-safety", action="store_true")
    args = parser.parse_args(argv)
    report = run_consumed_v1_regression(args.corpus, args.historical_report)
    print(json.dumps(report, indent=2, sort_keys=True) if args.as_json else _summary(report))
    return 2 if args.strict_safety and not report["safety_regression"]["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
