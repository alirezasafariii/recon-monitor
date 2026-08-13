from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTIC_VERSION = "1.0.0"
DIAGNOSTIC_RULE_VERSION = "2026.08.13.6.27"
DEFAULT_REPORT = ROOT / "benchmarks" / "raw" / "results" / "analysis_raw_v4_6_27_regression.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "results" / "analysis_raw_v4_6_27_diagnostic.json"


def diagnose(report: Mapping[str, Any]) -> dict[str, Any]:
    cases = [dict(row) for row in report.get("cases") or [] if isinstance(row, Mapping)]
    condition_fp = Counter()
    top1_confusions = Counter()
    top3_misses = Counter()
    rank_errors_by_kind = Counter()
    rank_errors: list[dict[str, Any]] = []
    wrong_promotions = Counter()
    wrong_cases: list[dict[str, Any]] = []

    for row in cases:
        expected_conditions = set(row.get("expected_condition_families") or [])
        predicted_conditions = set(row.get("predicted_condition_families") or [])
        for family in sorted(predicted_conditions - expected_conditions):
            condition_fp[family] += 1

        if row.get("rank_required") and not row.get("top1_correct"):
            key = f"{row.get('family')}->{row.get('top1')}"
            top1_confusions[key] += 1
            rank_errors_by_kind[str(row.get("case_kind") or "")] += 1
            rank_errors.append({
                "id": row.get("id"),
                "case_kind": row.get("case_kind"),
                "family": row.get("family"),
                "top1": row.get("top1"),
                "top3": row.get("top3"),
                "admitted_families": row.get("admitted_families"),
                "predicted_condition_families": row.get("predicted_condition_families"),
                "target_condition_signals": row.get("target_condition_signals"),
            })
        if row.get("rank_required") and not row.get("top3_correct"):
            top3_misses[str(row.get("family") or "")] += 1
        for family in row.get("wrong_promotions") or []:
            wrong_promotions[str(family)] += 1
        if row.get("wrong_promotions"):
            wrong_cases.append({
                "id": row.get("id"),
                "case_kind": row.get("case_kind"),
                "family": row.get("family"),
                "wrong_promotions": row.get("wrong_promotions"),
                "top1": row.get("top1"),
                "top3": row.get("top3"),
                "predicted_condition_families": row.get("predicted_condition_families"),
            })

    family_rank_summary: dict[str, dict[str, int]] = defaultdict(lambda: {"rank_required": 0, "top1_ok": 0, "top3_ok": 0})
    for row in cases:
        if not row.get("rank_required"):
            continue
        family = str(row.get("family") or "")
        family_rank_summary[family]["rank_required"] += 1
        family_rank_summary[family]["top1_ok"] += int(bool(row.get("top1_correct")))
        family_rank_summary[family]["top3_ok"] += int(bool(row.get("top3_correct")))

    return {
        "diagnostic_version": DIAGNOSTIC_VERSION,
        "diagnostic_rule_version": DIAGNOSTIC_RULE_VERSION,
        "source_evaluation_kind": report.get("evaluation_kind"),
        "source_metrics": report.get("metrics"),
        "source_quality_gate": report.get("quality_gate"),
        "condition_false_positive_family_counts": dict(condition_fp.most_common()),
        "top1_confusions": dict(top1_confusions.most_common()),
        "top3_miss_family_counts": dict(top3_misses.most_common()),
        "ranking_error_kind_counts": dict(rank_errors_by_kind.most_common()),
        "ranking_error_count": len(rank_errors),
        "ranking_errors": rank_errors,
        "wrong_promotion_family_counts": dict(wrong_promotions.most_common()),
        "wrong_promotion_cases": wrong_cases,
        "family_rank_summary": dict(sorted(family_rank_summary.items())),
        "diagnostic_executes_analysis_engine": False,
        "diagnostic_reruns_holdout": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose stored Analysis 6.27 post-blind regression without rerunning the engine")
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    result = diagnose(report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "condition_false_positive_family_counts": result["condition_false_positive_family_counts"],
        "top1_confusions": result["top1_confusions"],
        "top3_miss_family_counts": result["top3_miss_family_counts"],
        "ranking_error_kind_counts": result["ranking_error_kind_counts"],
        "wrong_promotion_family_counts": result["wrong_promotion_family_counts"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
