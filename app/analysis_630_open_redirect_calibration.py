from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from family_detectors.execution import execute_detector_intelligence
from family_detectors.registry import DETECTOR_SPECS
from hypothesis_admission import assess_admission
from raw_recon_corpus import ROOT

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.30"
DATASET = ROOT / "benchmarks/calibration/analysis_630_open_redirect.json"
OUTPUT = ROOT / "benchmarks/calibration/results/analysis_630_open_redirect.json"


def evaluate() -> dict[str, Any]:
    dataset = json.loads(DATASET.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = []
    condition_contract = set(DETECTOR_SPECS["open_redirect"].condition_signals)
    for source in dataset["cases"]:
        raw = dict(source["raw"])
        execution = execute_detector_intelligence(
            target=raw["target"],
            endpoint=raw["endpoint"],
            method=raw["method"],
            endpoint_schema=raw.get("endpoint_schema") or {},
            details=raw.get("details") or {},
            category=raw.get("category") or "",
            business_context=raw.get("business_context") or "general",
        )
        packet = execution.get("open_redirect") or {"support": [], "contradict": []}
        assessment = assess_admission("open_redirect", packet.get("support") or [], packet.get("contradict") or [])
        support_types = {str(row.get("type") or "") for row in packet.get("support") or []}
        condition_types = sorted(support_types & condition_contract)
        expected_condition = str(source.get("expected_condition") or "")
        condition_ok = (expected_condition in condition_types) if expected_condition else not condition_types
        admission_ok = bool(assessment["admitted"]) == bool(source["expected_admitted"])
        cases.append({
            "id": source["id"],
            "source_root": source["source_root"],
            "source_project": source["source_project"],
            "expected_admitted": bool(source["expected_admitted"]),
            "actual_admitted": bool(assessment["admitted"]),
            "expected_condition": expected_condition,
            "condition_types": condition_types,
            "blocking_contradictions": list(assessment.get("blocking_contradictions") or []),
            "condition_ok": condition_ok,
            "admission_ok": admission_ok,
            "passed": condition_ok and admission_ok,
        })
    passed = sum(1 for row in cases if row["passed"])
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "dataset_version": dataset["version"],
        "case_count": len(cases),
        "passed_count": passed,
        "failed_count": len(cases) - passed,
        "pass_rate": passed / len(cases) if cases else 0.0,
        "all_passed": passed == len(cases),
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--require-baseline-failure", action="store_true")
    args = parser.parse_args()
    result = evaluate()
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "all_passed": result["all_passed"],
        "passed_count": result["passed_count"],
        "failed_count": result["failed_count"],
        "failed_cases": [row["id"] for row in result["cases"] if not row["passed"]],
    }, indent=2, sort_keys=True))
    if args.require_pass and not result["all_passed"]:
        return 2
    if args.require_baseline_failure:
        failed = {row["id"] for row in result["cases"] if not row["passed"]}
        required = {"cal630-control-location-on-400", "cal630-koa-protocol-relative-302"}
        if not required.issubset(failed):
            raise SystemExit(f"expected pre-fix calibration failures not observed: {sorted(required-failed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
