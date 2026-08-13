from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_benchmark import run_raw_benchmark
from raw_recon_corpus import load_raw_cases
from raw_recon_v4_blind import _augment_metrics, verify_v4_freeze
from raw_recon_v4_corpus import validate_v4_corpus

ROOT = Path(__file__).resolve().parents[1]
REGRESSION_VERSION = "1.0.0"
REGRESSION_RULE_VERSION = "2026.08.13.6.27"
DEFAULT_CORPUS = ROOT / "benchmarks" / "raw" / "analysis_raw_v4.jsonl"
DEFAULT_SHORTLIST = ROOT / "benchmarks" / "raw" / "sources" / "v4_shortlist.json"
DEFAULT_FREEZE = ROOT / "benchmarks" / "raw" / "sources" / "v4_freeze.json"
DEFAULT_RECEIPT = ROOT / "benchmarks" / "raw" / "sources" / "v4_first_blind_receipt.json"
DEFAULT_FIRST_REPORT = ROOT / "benchmarks" / "raw" / "sources" / "v4_first_blind_report.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "results" / "analysis_raw_v4_6_27_regression.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return data


def run_regression(
    *,
    corpus_path: Path = DEFAULT_CORPUS,
    shortlist_path: Path = DEFAULT_SHORTLIST,
    freeze_path: Path = DEFAULT_FREEZE,
    receipt_path: Path = DEFAULT_RECEIPT,
    first_report_path: Path = DEFAULT_FIRST_REPORT,
) -> dict[str, Any]:
    receipt = _load(receipt_path)
    if receipt.get("status") != "first_blind_consumed":
        raise RuntimeError("v4 regression requires an immutable consumed first-blind receipt")
    if receipt.get("evaluation_kind") != "first_blind_single_consumption":
        raise RuntimeError("v4 receipt is not the original single-consumption first blind")
    if _sha256(first_report_path) != str(receipt.get("report_sha256") or ""):
        raise RuntimeError("immutable first-blind report hash differs from consumption receipt")

    freeze = verify_v4_freeze(
        corpus_path=corpus_path,
        shortlist_path=shortlist_path,
        freeze_path=freeze_path,
    )
    if not freeze["passed"]:
        raise RuntimeError("frozen v4 inputs changed after first blind: " + "; ".join(freeze["errors"]))
    if freeze["corpus_sha256"] != str(receipt.get("corpus_sha256") or ""):
        raise RuntimeError("v4 corpus hash differs from the consumed first-blind receipt")
    if freeze["shortlist_sha256"] != str(receipt.get("shortlist_sha256") or ""):
        raise RuntimeError("v4 shortlist hash differs from the consumed first-blind receipt")

    shortlist = _load(shortlist_path)
    cases = load_raw_cases(corpus_path)
    validation = validate_v4_corpus(cases, shortlist=shortlist)
    if not validation["passed"]:
        raise RuntimeError("v4 regression corpus validation failed: " + "; ".join(validation["errors"]))

    report = run_raw_benchmark(cases, validation=validation)
    _augment_metrics(report)
    report.update({
        "regression_version": REGRESSION_VERSION,
        "regression_rule_version": REGRESSION_RULE_VERSION,
        "evaluation_kind": "post_first_blind_regression",
        "first_blind_consumed": True,
        "first_blind_report_sha256": receipt["report_sha256"],
        "frozen_inputs": {
            "corpus_sha256": freeze["corpus_sha256"],
            "shortlist_sha256": freeze["shortlist_sha256"],
            "freeze_sha256": _sha256(freeze_path),
        },
        "mutation_policy": {
            "frozen_v4_inputs": "immutable",
            "benchmark_repairs": "forbidden",
            "engine_repairs": "allowed",
            "regression_is_not_first_blind": True,
        },
    })
    return report


def _summary(report: Mapping[str, Any]) -> str:
    m = report["metrics"]
    return (
        f"Analysis 6.27 post-blind v4 regression: {report['case_count']} cases | "
        f"condP={m['condition_extraction_precision']:.3f} condR={m['condition_extraction_recall']:.3f} "
        f"top1={m['routing_top1_accuracy']:.3f} top3={m['routing_top3_accuracy']:.3f} "
        f"admitP={m['admission_precision']:.3f} admitR={m['admission_recall']:.3f} "
        f"near={m['near_miss_abstention_accuracy']:.3f} secure={m['secure_negative_rejection_accuracy']:.3f} "
        f"sparse={m['sparse_noisy_abstention_accuracy']:.3f} FPR={m['false_promotion_rate']:.3f} "
        f"wrong={m['wrong_family_promotion_rate']:.3f} e2e={m['end_to_end_accuracy']:.3f} | "
        f"gate={'PASS' if report['quality_gate']['passed'] else 'FAIL'}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Analysis 6.27 regression against the already-consumed immutable v4 holdout")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = run_regression()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else _summary(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
