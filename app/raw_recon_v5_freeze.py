from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from raw_recon_benchmark import RAW_QUALITY_GATES
from raw_recon_corpus import ROOT
from raw_recon_v5_benchmark import MULTI_QUALITY_GATES
from raw_recon_v5_corpus import validate_v5_corpus

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.29"
CORPUS = ROOT / "benchmarks/raw/analysis_raw_v5.jsonl"
SHORTLIST = ROOT / "benchmarks/raw/sources/v5_shortlist.json"
FREEZE = ROOT / "benchmarks/raw/sources/v5_freeze_manifest.json"
REPORT = ROOT / "benchmarks/raw/sources/v5_prepare_report.json"

PROTECTED_FILES = (
    "benchmarks/raw/analysis_raw_v5.jsonl",
    "benchmarks/raw/sources/v5_candidates.json",
    "benchmarks/raw/sources/v5_business_logic_supplement.json",
    "benchmarks/raw/sources/v5_shortlist.json",
    "app/raw_recon_v5_benchmark.py",
    "app/raw_recon_v5_corpus.py",
    "app/raw_recon_v5_source_discovery.py",
    "app/raw_recon_v5_source_audit.py",
    "app/raw_recon_benchmark.py",
    "app/raw_recon_v4_corpus.py",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _multi_gate_manifest() -> dict[str, float]:
    return {
        "multi_exact_admission_set_accuracy_min": MULTI_QUALITY_GATES["multi_exact_admission_set_accuracy"][1],
        "multi_expected_condition_recall_min": MULTI_QUALITY_GATES["multi_expected_condition_recall"][1],
        "multi_unexpected_promotion_rate_max": MULTI_QUALITY_GATES["multi_unexpected_promotion_rate"][1],
        "multi_dual_positive_both_admitted_min": MULTI_QUALITY_GATES["multi_dual_positive_both_admitted_rate"][1],
        "multi_dual_secure_rejection_min": MULTI_QUALITY_GATES["multi_dual_secure_rejection_rate"][1],
        "multi_expected_family_top3_coverage_min": MULTI_QUALITY_GATES["multi_expected_family_top3_coverage"][1],
    }


def finalize_freeze() -> dict[str, Any]:
    cases = [
        json.loads(line)
        for line in CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    shortlist = json.loads(SHORTLIST.read_text(encoding="utf-8"))
    preliminary = json.loads(FREEZE.read_text(encoding="utf-8"))
    validation = validate_v5_corpus(cases, shortlist=shortlist)
    if not validation["passed"]:
        raise RuntimeError("v5 integrity validation failed before freeze: " + "; ".join(validation["errors"]))
    if validation["label_leakage_count"] != 0:
        raise RuntimeError("v5 freeze refuses raw label leakage")
    if validation["single_positive_control_collision_count"] != 0:
        raise RuntimeError("v5 freeze refuses single positive/control collisions")
    if validation["multi_raw_collision_count"] != 0:
        raise RuntimeError("v5 freeze refuses multi-variant collisions")
    if validation["single_positive_observable_delta_rate"] != 1.0:
        raise RuntimeError("v5 freeze requires 100% single positive observable delta")

    gates = {"single_existing_raw_gates": "unchanged RAW_QUALITY_GATES", **_multi_gate_manifest()}
    if preliminary.get("pre_registered_gates") != gates:
        raise RuntimeError("preliminary v5 gates differ from evaluator gate definitions")
    protected = {}
    for relative in PROTECTED_FILES:
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"v5 protected file missing before freeze: {relative}")
        protected[relative] = _sha(path)

    freeze = dict(preliminary)
    freeze.update({
        "freeze_finalizer_version": VERSION,
        "freeze_finalizer_rule_version": RULE_VERSION,
        "evaluation_status": "sealed_unscored",
        "scoring_executed": False,
        "evaluator_frozen_before_scoring": True,
        "single_quality_gates": {
            metric: {"direction": direction, "threshold": threshold}
            for metric, (direction, threshold) in RAW_QUALITY_GATES.items()
        },
        "pre_registered_gates": gates,
        "corpus_validation": validation,
        "protected_sha256": protected,
    })
    FREEZE.write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = json.loads(REPORT.read_text(encoding="utf-8")) if REPORT.exists() else {}
    report.update({
        "evaluation_status": "sealed_unscored",
        "scoring_executed": False,
        "evaluator_frozen_before_scoring": True,
        "corpus_validation": validation,
        "protected_sha256": protected,
        "corpus_sha256": protected["benchmarks/raw/analysis_raw_v5.jsonl"],
        "shortlist_sha256": protected["benchmarks/raw/sources/v5_shortlist.json"],
        "evaluator_sha256": protected["app/raw_recon_v5_benchmark.py"],
    })
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return freeze


def main() -> int:
    freeze = finalize_freeze()
    print(json.dumps({
        "evaluation_status": freeze["evaluation_status"],
        "case_count": freeze["case_count"],
        "corpus_sha256": freeze["protected_sha256"]["benchmarks/raw/analysis_raw_v5.jsonl"],
        "evaluator_sha256": freeze["protected_sha256"]["app/raw_recon_v5_benchmark.py"],
        "label_leakage_count": freeze["corpus_validation"]["label_leakage_count"],
        "observable_delta_rate": freeze["corpus_validation"]["single_positive_observable_delta_rate"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
