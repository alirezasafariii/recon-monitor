from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "benchmarks" / "raw" / "results" / "analysis_raw_v2_first_evaluation.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "results" / "analysis_raw_v2_diagnostic_summary.json"
RESULT_DIAGNOSTIC_VERSION = "1.0.0"


def summarize(report: Mapping[str, Any]) -> dict[str, Any]:
    rows = [dict(row) for row in report.get("cases") or [] if isinstance(row, Mapping)]
    condition_false_positives: list[dict[str, Any]] = []
    condition_false_negatives: list[dict[str, Any]] = []
    admission_false_positives: list[dict[str, Any]] = []
    admission_false_negatives: list[dict[str, Any]] = []
    routing_top1_errors: list[dict[str, Any]] = []
    routing_top3_errors: list[dict[str, Any]] = []

    def slim(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "id": row.get("id"),
            "source_root": row.get("source_root"),
            "source_project": row.get("source_project"),
            "family": row.get("family"),
            "case_kind": row.get("case_kind"),
            "expected_condition_families": row.get("expected_condition_families"),
            "predicted_condition_families": row.get("predicted_condition_families"),
            "target_condition_signals": row.get("target_condition_signals"),
            "expected_condition_signals": row.get("expected_condition_signals"),
            "admitted_families": row.get("admitted_families"),
            "top1": row.get("top1"),
            "top3": row.get("top3"),
            "target_state": row.get("target_state"),
        }

    for row in rows:
        expected_conditions = set(row.get("expected_condition_families") or [])
        predicted_conditions = set(row.get("predicted_condition_families") or [])
        if predicted_conditions - expected_conditions:
            condition_false_positives.append(slim(row))
        if expected_conditions - predicted_conditions:
            condition_false_negatives.append(slim(row))
        expected_admitted = bool(row.get("expected_admitted"))
        admitted = bool(row.get("admitted_families"))
        if admitted and not expected_admitted:
            admission_false_positives.append(slim(row))
        if expected_admitted and not bool(row.get("target_admitted")):
            admission_false_negatives.append(slim(row))
        if row.get("rank_required") and not row.get("top1_correct"):
            routing_top1_errors.append(slim(row))
        if row.get("rank_required") and not row.get("top3_correct"):
            routing_top3_errors.append(slim(row))

    return {
        "result_diagnostic_version": RESULT_DIAGNOSTIC_VERSION,
        "source_report_is_saved_first_evaluation_only": True,
        "rescoring_executed": False,
        "metrics": report.get("metrics"),
        "quality_gate": report.get("quality_gate"),
        "condition_false_positive_count": len(condition_false_positives),
        "condition_false_negative_count": len(condition_false_negatives),
        "admission_false_positive_count": len(admission_false_positives),
        "admission_false_negative_count": len(admission_false_negatives),
        "routing_top1_error_count": len(routing_top1_errors),
        "routing_top3_error_count": len(routing_top3_errors),
        "condition_false_positives": condition_false_positives,
        "condition_false_negatives": condition_false_negatives,
        "admission_false_positives": admission_false_positives,
        "admission_false_negatives": admission_false_negatives,
        "routing_top1_errors": routing_top1_errors,
        "routing_top3_errors": routing_top3_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize saved Analysis 6.13 v2 result without rescoring")
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    summary = summarize(report)
    Path(args.output).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in (
        "condition_false_positive_count",
        "condition_false_negative_count",
        "admission_false_positive_count",
        "admission_false_negative_count",
        "routing_top1_error_count",
        "routing_top3_error_count",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
