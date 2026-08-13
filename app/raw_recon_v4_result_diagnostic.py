from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "benchmarks" / "raw" / "sources" / "v4_first_blind_report.json"
DEFAULT_RECEIPT = ROOT / "benchmarks" / "raw" / "sources" / "v4_first_blind_receipt.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_first_blind_diagnostic.json"

DIAGNOSTIC_VERSION = "1.0.0"
DIAGNOSTIC_RULE_VERSION = "2026.08.13.6.26"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _classify_positive(row: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    family = str(row.get("family") or "")
    emitted = set(str(v) for v in row.get("emitted_families") or [])
    expected_conditions = set(str(v) for v in row.get("expected_condition_signals") or [])
    observed_conditions = set(str(v) for v in row.get("target_condition_signals") or [])
    admitted = bool(row.get("target_admitted"))
    wrong = list(row.get("wrong_promotions") or [])

    if family not in emitted:
        reasons.append("execution_extraction_gap")
    elif expected_conditions and not (expected_conditions & observed_conditions):
        reasons.append("condition_reconstruction_gap")
    elif not admitted:
        reasons.append("admission_gap")

    if not bool(row.get("top3_correct")):
        reasons.append("routing_top3_gap")
    elif not bool(row.get("top1_correct")):
        reasons.append("routing_top1_gap")
    if wrong:
        reasons.append("cross_family_precision_gap")
    if not reasons and not bool(row.get("end_to_end_pass")):
        reasons.append("unclassified_end_to_end_gap")
    return reasons


def diagnose(report: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any]:
    if receipt.get("status") != "first_blind_consumed":
        raise RuntimeError("Analysis 6.26 first blind is not marked consumed")
    cases = [row for row in report.get("cases") or [] if isinstance(row, Mapping)]
    if len(cases) != 144:
        raise RuntimeError(f"expected 144 stored first-blind cases, got {len(cases)}")
    if int(report.get("family_count") or 0) != 36:
        raise RuntimeError(f"expected 36 first-blind families, got {report.get('family_count')!r}")

    positive_failures: list[dict[str, Any]] = []
    positive_reason_counts: Counter[str] = Counter()
    negative_promotions: list[dict[str, Any]] = []
    promoted_family_counts: Counter[str] = Counter()
    negative_kind_counts: Counter[str] = Counter()
    routing_top1_confusions: Counter[str] = Counter()
    routing_top3_misses: Counter[str] = Counter()
    condition_false_positive_families: Counter[str] = Counter()
    condition_miss_families: Counter[str] = Counter()

    for row in cases:
        family = str(row.get("family") or "")
        kind = str(row.get("case_kind") or "")
        if kind == "positive":
            if not bool(row.get("end_to_end_pass")):
                reasons = _classify_positive(row)
                positive_reason_counts.update(reasons)
                positive_failures.append({
                    "family": family,
                    "id": row.get("id"),
                    "reasons": reasons,
                    "emitted": family in set(row.get("emitted_families") or []),
                    "expected_condition_signals": list(row.get("expected_condition_signals") or []),
                    "target_condition_signals": list(row.get("target_condition_signals") or []),
                    "condition_signal_misses": list(row.get("condition_signal_misses") or []),
                    "target_state": row.get("target_state"),
                    "target_admitted": bool(row.get("target_admitted")),
                    "top1": row.get("top1"),
                    "top3": list(row.get("top3") or []),
                    "wrong_promotions": list(row.get("wrong_promotions") or []),
                })
            if not bool(row.get("top1_correct")):
                routing_top1_confusions[f"{family}->{row.get('top1') or '<none>'}"] += 1
            if not bool(row.get("top3_correct")):
                routing_top3_misses[family] += 1
            if row.get("condition_signal_misses"):
                condition_miss_families[family] += 1
        else:
            admitted = [str(v) for v in row.get("admitted_families") or []]
            if admitted:
                negative_kind_counts[kind] += 1
                promoted_family_counts.update(admitted)
                negative_promotions.append({
                    "expected_family": family,
                    "case_kind": kind,
                    "id": row.get("id"),
                    "admitted_families": admitted,
                    "predicted_condition_families": list(row.get("predicted_condition_families") or []),
                    "top1": row.get("top1"),
                    "top3": list(row.get("top3") or []),
                })
            for predicted in row.get("predicted_condition_families") or []:
                condition_false_positive_families[str(predicted)] += 1

    family_results = report.get("family_results") if isinstance(report.get("family_results"), Mapping) else {}
    failed_positive_families = sorted(
        family for family, value in family_results.items()
        if isinstance(value, Mapping) and not bool(value.get("positive_admitted"))
    )

    return {
        "diagnostic_version": DIAGNOSTIC_VERSION,
        "diagnostic_rule_version": DIAGNOSTIC_RULE_VERSION,
        "source": {
            "report_sha256": receipt.get("report_sha256"),
            "corpus_sha256": receipt.get("corpus_sha256"),
            "shortlist_sha256": receipt.get("shortlist_sha256"),
            "receipt_status": receipt.get("status"),
        },
        "first_blind_quality_gate_passed": bool(report.get("quality_gate", {}).get("passed")),
        "metrics": dict(report.get("metrics") or {}),
        "positive_failure_count": len(positive_failures),
        "failed_positive_family_count": len(failed_positive_families),
        "failed_positive_families": failed_positive_families,
        "positive_failure_reason_counts": dict(sorted(positive_reason_counts.items())),
        "positive_failures": positive_failures,
        "negative_promotion_case_count": len(negative_promotions),
        "negative_promotion_kind_counts": dict(sorted(negative_kind_counts.items())),
        "promoted_family_counts_on_negative_controls": dict(promoted_family_counts.most_common()),
        "negative_promotions": negative_promotions,
        "condition_false_positive_family_counts": dict(condition_false_positive_families.most_common()),
        "condition_miss_family_counts": dict(condition_miss_families.most_common()),
        "positive_top1_confusions": dict(routing_top1_confusions.most_common()),
        "positive_top3_miss_families": dict(routing_top3_misses.most_common()),
        "diagnostic_executes_analysis_engine": False,
        "diagnostic_reruns_holdout": False,
        "frozen_inputs_mutated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose the stored Analysis 6.26 first blind result without rerunning the engine")
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--receipt", default=str(DEFAULT_RECEIPT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    report_path = Path(args.report)
    receipt_path = Path(args.receipt)
    receipt = _load(receipt_path)
    if _sha256(report_path) != str(receipt.get("report_sha256") or ""):
        raise RuntimeError("stored first-blind report hash does not match immutable consumption receipt")
    result = diagnose(_load(report_path), receipt)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "positive_failure_count": result["positive_failure_count"],
        "failed_positive_families": result["failed_positive_families"],
        "positive_failure_reason_counts": result["positive_failure_reason_counts"],
        "negative_promotion_case_count": result["negative_promotion_case_count"],
        "negative_promotion_kind_counts": result["negative_promotion_kind_counts"],
        "promoted_family_counts_on_negative_controls": result["promoted_family_counts_on_negative_controls"],
        "positive_top1_confusions": result["positive_top1_confusions"],
        "positive_top3_miss_families": result["positive_top3_miss_families"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
