from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from raw_recon_benchmark import RAW_QUALITY_GATES, run_raw_benchmark
from raw_recon_corpus import load_raw_cases
from raw_recon_v4_corpus import validate_v4_corpus

RAW_RECON_V4_BLIND_VERSION = "1.0.0"
RAW_RECON_V4_BLIND_RULE_VERSION = "2026.08.13.6.26"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "raw" / "analysis_raw_v4.jsonl"
DEFAULT_SHORTLIST = ROOT / "benchmarks" / "raw" / "sources" / "v4_shortlist.json"
DEFAULT_FREEZE = ROOT / "benchmarks" / "raw" / "sources" / "v4_freeze.json"
DEFAULT_REPORT = ROOT / "benchmarks" / "raw" / "sources" / "v4_first_blind_report.json"

# Pre-registered before the first v4 score. Existing raw benchmark quality gates
# are inherited unchanged. v4 adds explicit negative-control gates so near-miss,
# secure-negative and sparse/noisy behavior cannot hide inside one aggregate.
V4_BLIND_QUALITY_GATES: dict[str, tuple[str, float]] = {
    **RAW_QUALITY_GATES,
    "near_miss_abstention_accuracy": ("min", 0.90),
    "secure_negative_rejection_accuracy": ("min", 0.95),
    "sparse_noisy_abstention_accuracy": ("min", 0.90),
    "positive_end_to_end_accuracy": ("min", 0.75),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ratio(num: int | float, den: int | float) -> float:
    return float(num) / float(den) if den else 0.0


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return raw


def verify_v4_freeze(
    *,
    corpus_path: Path = DEFAULT_CORPUS,
    shortlist_path: Path = DEFAULT_SHORTLIST,
    freeze_path: Path = DEFAULT_FREEZE,
) -> dict[str, Any]:
    freeze = _load_json(freeze_path)
    errors: list[str] = []
    if freeze.get("status") != "frozen_pre_first_blind":
        errors.append(f"v4 freeze status is not pre-first-blind: {freeze.get('status')!r}")
    if freeze.get("first_blind_scoring_executed") is not False:
        errors.append("v4 freeze does not attest an unscored corpus")
    if int(freeze.get("case_count") or 0) != 144:
        errors.append(f"v4 freeze case count mismatch: {freeze.get('case_count')!r}")
    if int(freeze.get("source_root_count") or 0) != 36:
        errors.append(f"v4 freeze root count mismatch: {freeze.get('source_root_count')!r}")
    if int(freeze.get("source_project_count") or 0) != 36:
        errors.append(f"v4 freeze project count mismatch: {freeze.get('source_project_count')!r}")
    if int(freeze.get("positive_family_count") or 0) != 36:
        errors.append(f"v4 freeze family count mismatch: {freeze.get('positive_family_count')!r}")

    actual_corpus = _sha256(corpus_path)
    actual_shortlist = _sha256(shortlist_path)
    expected_corpus = str(freeze.get("corpus_sha256") or "")
    expected_shortlist = str(freeze.get("shortlist_sha256") or "")
    if actual_corpus != expected_corpus:
        errors.append(f"frozen corpus hash mismatch expected={expected_corpus} actual={actual_corpus}")
    if actual_shortlist != expected_shortlist:
        errors.append(f"frozen shortlist hash mismatch expected={expected_shortlist} actual={actual_shortlist}")

    for key in (
        "prior_source_root_overlap_count",
        "prior_source_project_overlap_count",
        "prior_url_overlap_count",
        "grounding_writeup_overlap_count",
        "label_leakage_count",
        "positive_control_raw_collision_count",
    ):
        if int(freeze.get(key) or 0) != 0:
            errors.append(f"frozen v4 independence/observability invariant failed: {key}={freeze.get(key)!r}")
    if float(freeze.get("positive_observable_delta_rate") or 0.0) != 1.0:
        errors.append("frozen v4 observable delta rate is not 1.0")

    return {
        "passed": not errors,
        "errors": errors,
        "freeze_version": freeze.get("freeze_version"),
        "freeze_rule_version": freeze.get("freeze_rule_version"),
        "materialization_commit": freeze.get("materialization_commit"),
        "corpus_sha256": actual_corpus,
        "shortlist_sha256": actual_shortlist,
    }


def _augment_metrics(report: dict[str, Any]) -> None:
    cases = list(report.get("cases") or [])
    by_kind: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    by_family: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in cases:
        if not isinstance(row, Mapping):
            continue
        by_kind[str(row.get("case_kind") or "")].append(row)
        by_family[str(row.get("family") or "")].append(row)

    def abstention(kind: str) -> float:
        rows = by_kind.get(kind, [])
        return _ratio(sum(1 for row in rows if not (row.get("admitted_families") or [])), len(rows))

    positive_rows = by_kind.get("positive", [])
    extra = {
        "near_miss_abstention_accuracy": round(abstention("near_miss"), 6),
        "secure_negative_rejection_accuracy": round(abstention("secure_negative"), 6),
        "sparse_noisy_abstention_accuracy": round(abstention("sparse_noisy"), 6),
        "positive_end_to_end_accuracy": round(
            _ratio(sum(1 for row in positive_rows if bool(row.get("end_to_end_pass"))), len(positive_rows)),
            6,
        ),
    }
    report["metrics"].update(extra)

    failures: list[dict[str, Any]] = []
    for metric, (direction, threshold) in V4_BLIND_QUALITY_GATES.items():
        value = float(report["metrics"].get(metric, 0.0))
        failed = value < threshold if direction == "min" else value > threshold
        if failed:
            failures.append({
                "metric": metric,
                "value": value,
                "direction": direction,
                "threshold": threshold,
            })
    report["quality_gate"] = {"passed": not failures, "failures": failures}

    family_results: dict[str, Any] = {}
    for family, rows in sorted(by_family.items()):
        positive = [row for row in rows if row.get("case_kind") == "positive"]
        near = [row for row in rows if row.get("case_kind") == "near_miss"]
        secure = [row for row in rows if row.get("case_kind") == "secure_negative"]
        sparse = [row for row in rows if row.get("case_kind") == "sparse_noisy"]
        family_results[family] = {
            "positive_admitted": bool(positive and positive[0].get("target_admitted")),
            "positive_top1_correct": bool(positive and positive[0].get("top1_correct")),
            "positive_top3_correct": bool(positive and positive[0].get("top3_correct")),
            "positive_condition_signals": list(positive[0].get("target_condition_signals") or []) if positive else [],
            "positive_expected_condition_signals": list(positive[0].get("expected_condition_signals") or []) if positive else [],
            "positive_condition_misses": list(positive[0].get("condition_signal_misses") or []) if positive else [],
            "near_miss_abstained": bool(near and not (near[0].get("admitted_families") or [])),
            "secure_negative_abstained": bool(secure and not (secure[0].get("admitted_families") or [])),
            "sparse_noisy_abstained": bool(sparse and not (sparse[0].get("admitted_families") or [])),
            "wrong_promotions": sorted({
                value
                for row in rows
                for value in (row.get("wrong_promotions") or [])
            }),
            "case_end_to_end_pass_count": sum(1 for row in rows if row.get("end_to_end_pass")),
            "case_count": len(rows),
        }
    report["family_results"] = family_results
    report["family_count"] = len(family_results)


def benchmark_v4_first_blind(
    *,
    corpus_path: Path = DEFAULT_CORPUS,
    shortlist_path: Path = DEFAULT_SHORTLIST,
    freeze_path: Path = DEFAULT_FREEZE,
    output_path: Path = DEFAULT_REPORT,
) -> dict[str, Any]:
    # First blind is single-consumption. Refuse to overwrite a historical result.
    if output_path.exists():
        raise RuntimeError(f"Analysis 6.26 v4 first blind report already exists and is immutable: {output_path}")

    freeze_validation = verify_v4_freeze(
        corpus_path=corpus_path,
        shortlist_path=shortlist_path,
        freeze_path=freeze_path,
    )
    if not freeze_validation["passed"]:
        raise RuntimeError("Analysis 6.26 v4 freeze verification failed: " + "; ".join(freeze_validation["errors"]))

    shortlist = _load_json(shortlist_path)
    cases = load_raw_cases(corpus_path)
    validation = validate_v4_corpus(cases, shortlist=shortlist)
    if not validation["passed"]:
        raise RuntimeError("Analysis 6.26 v4 corpus validation failed: " + "; ".join(validation["errors"]))

    report = run_raw_benchmark(cases, validation=validation)
    _augment_metrics(report)
    report["raw_recon_v4_blind_version"] = RAW_RECON_V4_BLIND_VERSION
    report["raw_recon_v4_blind_rule_version"] = RAW_RECON_V4_BLIND_RULE_VERSION
    report["evaluation_kind"] = "first_blind_single_consumption"
    report["freeze_validation"] = freeze_validation
    report["pre_registered_quality_gates"] = {
        metric: {"direction": direction, "threshold": threshold}
        for metric, (direction, threshold) in V4_BLIND_QUALITY_GATES.items()
    }
    report["frozen_inputs"] = {
        "corpus": str(corpus_path.relative_to(ROOT)),
        "corpus_sha256": _sha256(corpus_path),
        "shortlist": str(shortlist_path.relative_to(ROOT)),
        "shortlist_sha256": _sha256(shortlist_path),
        "freeze": str(freeze_path.relative_to(ROOT)),
        "freeze_sha256": _sha256(freeze_path),
    }
    return report


def _summary(report: Mapping[str, Any]) -> str:
    m = report["metrics"]
    return (
        f"Analysis 6.26 raw v4 FIRST BLIND: {report['case_count']} cases / {report['family_count']} families | "
        f"condP={m['condition_extraction_precision']:.3f} condR={m['condition_extraction_recall']:.3f} "
        f"top1={m['routing_top1_accuracy']:.3f} top3={m['routing_top3_accuracy']:.3f} "
        f"admitP={m['admission_precision']:.3f} admitR={m['admission_recall']:.3f} "
        f"near={m['near_miss_abstention_accuracy']:.3f} secure={m['secure_negative_rejection_accuracy']:.3f} "
        f"sparse={m['sparse_noisy_abstention_accuracy']:.3f} FPR={m['false_promotion_rate']:.3f} "
        f"wrong={m['wrong_family_promotion_rate']:.3f} e2e={m['end_to_end_accuracy']:.3f} | "
        f"gate={'PASS' if report['quality_gate']['passed'] else 'FAIL'}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the single-consumption Analysis 6.26 raw v4 first blind evaluation")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--shortlist", default=str(DEFAULT_SHORTLIST))
    parser.add_argument("--freeze", default=str(DEFAULT_FREEZE))
    parser.add_argument("--output", default=str(DEFAULT_REPORT))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    output = Path(args.output)
    report = benchmark_v4_first_blind(
        corpus_path=Path(args.corpus),
        shortlist_path=Path(args.shortlist),
        freeze_path=Path(args.freeze),
        output_path=output,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_summary(report))
    # Never make the first execution disappear because a quality gate failed.
    # The workflow persists the report first and may fail afterwards.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
