from __future__ import annotations

import json
from pathlib import Path

from raw_recon_benchmark import run_raw_benchmark
from raw_recon_corpus import load_raw_cases
from raw_recon_v2_corpus import validate_v2_corpus


corpus = Path("benchmarks/raw/analysis_raw_v2.jsonl")
cases = load_raw_cases(corpus)
validation = validate_v2_corpus(cases)
if not validation["passed"]:
    raise SystemExit("v2 validation failed: " + "; ".join(validation["errors"]))
report = run_raw_benchmark(cases, validation=validation)
metrics = report["metrics"]
envelope = {
    "evaluation_status": "consumed_diagnostic_regression_only",
    "fresh_or_blind_claim_allowed": False,
    "source_evaluation_run": "31471744115",
    "engine_version": "6.14.0",
    "metrics": metrics,
    "quality_gate": report["quality_gate"],
    "case_results": report["cases"],
    "note": "Analysis raw v2 was consumed by the single Analysis 6.13 fresh evaluation. This run is development regression only and must never be described as fresh or blind.",
}
output = Path("benchmarks/raw/results/analysis_raw_v2_6_14_regression.json")
output.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(metrics, indent=2, sort_keys=True))

assert metrics["condition_extraction_precision"] >= 0.90, metrics
assert metrics["condition_extraction_recall"] >= 0.875, metrics
assert metrics["admission_precision"] >= 0.93, metrics
assert metrics["admission_recall"] >= 0.875, metrics
assert metrics["abstention_accuracy"] >= 0.972222, metrics
assert metrics["false_promotion_rate"] <= 0.027778, metrics
assert metrics["wrong_family_promotion_rate"] == 0.0, metrics
