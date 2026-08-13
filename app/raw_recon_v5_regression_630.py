from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from raw_recon_corpus import ROOT
from raw_recon_v5_benchmark import run_v5_benchmark

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.30"
OUTPUT = ROOT / "benchmarks/raw/results/analysis_raw_v5_6_30_regression.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run() -> dict[str, Any]:
    freeze_path = ROOT / "benchmarks/raw/sources/v5_freeze_manifest.json"
    receipt_path = ROOT / "benchmarks/raw/sources/v5_first_blind_receipt.json"
    first_report_path = ROOT / "benchmarks/raw/results/analysis_raw_v5_first_blind.json"
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "first_blind_consumed"
    assert receipt["evaluation_kind"] == "fresh_blind_v5_single_consumption"
    assert _sha(first_report_path) == receipt["report_sha256"]
    for rel, wanted in freeze["protected_sha256"].items():
        actual = _sha(ROOT / rel)
        assert actual == wanted, (rel, wanted, actual)

    report = run_v5_benchmark()
    report["evaluation_kind"] = "post_first_blind_regression"
    report["regression_version"] = VERSION
    report["regression_rule_version"] = RULE_VERSION
    report["first_blind_receipt_status"] = receipt["status"]
    report["first_blind_report_sha256"] = receipt["report_sha256"]
    report["frozen_corpus_sha256"] = receipt["corpus_sha256"]
    report["frozen_evaluator_sha256"] = receipt["evaluator_sha256"]
    report["first_blind_rerun_claimed"] = False
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    report = run()
    print(json.dumps({
        "evaluation_kind": report["evaluation_kind"],
        "quality_gate": report["quality_gate"],
        "single_metrics": report["single_family"]["metrics"],
        "multi_metrics": report["multi_family"]["metrics"],
    }, indent=2, sort_keys=True))
    return 0 if report["quality_gate"]["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
