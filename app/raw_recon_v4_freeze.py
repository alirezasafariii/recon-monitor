from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT, load_raw_cases
from raw_recon_v4_corpus import validate_v4_corpus

FREEZE_VERSION = "1.0.0"
FREEZE_RULE_VERSION = "2026.08.12.6.26"
DEFAULT_CORPUS = ROOT / "benchmarks" / "raw" / "analysis_raw_v4.jsonl"
DEFAULT_SHORTLIST = ROOT / "benchmarks" / "raw" / "sources" / "v4_shortlist.json"
DEFAULT_AUDIT = ROOT / "benchmarks" / "raw" / "sources" / "v4_source_family_audit.json"
DEFAULT_MATERIALIZATION = ROOT / "benchmarks" / "raw" / "sources" / "v4_materialization_report.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_freeze.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise RuntimeError(f"expected JSON object: {path}")
    return dict(value)


def build_freeze(
    *,
    corpus_path: Path = DEFAULT_CORPUS,
    shortlist_path: Path = DEFAULT_SHORTLIST,
    audit_path: Path = DEFAULT_AUDIT,
    materialization_path: Path = DEFAULT_MATERIALIZATION,
    materialization_commit: str,
) -> dict[str, Any]:
    shortlist = _load(shortlist_path)
    audit = _load(audit_path)
    materialization = _load(materialization_path)
    cases = load_raw_cases(corpus_path)
    validation = validate_v4_corpus(cases, shortlist=shortlist)

    corpus_sha = _sha256(corpus_path)
    if not validation["passed"]:
        raise RuntimeError("cannot freeze invalid v4 corpus: " + "; ".join(validation["errors"]))
    if materialization.get("scoring_executed") is not False:
        raise RuntimeError("cannot freeze v4 after scoring has executed")
    if str(materialization.get("corpus_sha256") or "") != corpus_sha:
        raise RuntimeError("materialization corpus SHA does not match current v4 corpus")
    if int(materialization.get("case_count") or 0) != 144:
        raise RuntimeError("materialization report is not exact 144-case v4")
    if validation["source_root_count"] != 36 or validation["source_project_count"] != 36:
        raise RuntimeError("v4 freeze requires exactly 36 source roots/projects")
    if validation["positive_family_count"] != 36:
        raise RuntimeError("v4 freeze requires exactly 36 positive families")
    if validation["label_leakage_count"] != 0:
        raise RuntimeError("v4 freeze refuses label leakage")
    if validation["prior_source_root_overlap_count"] or validation["prior_source_project_overlap_count"]:
        raise RuntimeError("v4 freeze refuses prior source overlap")
    if validation["prior_url_overlap_count"] or validation["grounding_writeup_overlap_count"]:
        raise RuntimeError("v4 freeze refuses URL/write-up grounding overlap")
    if validation["positive_control_raw_collision_count"]:
        raise RuntimeError("v4 freeze refuses positive/control collisions")
    if validation["positive_observable_delta_rate"] != 1.0:
        raise RuntimeError("v4 freeze requires observable delta rate 1.0")

    return {
        "freeze_version": FREEZE_VERSION,
        "freeze_rule_version": FREEZE_RULE_VERSION,
        "status": "frozen_pre_first_blind",
        "materialization_commit": materialization_commit,
        "case_count": 144,
        "source_root_count": 36,
        "source_project_count": 36,
        "positive_family_count": 36,
        "variant_count_per_root": 4,
        "corpus_sha256": corpus_sha,
        "shortlist_sha256": _sha256(shortlist_path),
        "source_family_audit_sha256": _sha256(audit_path),
        "materialization_report_sha256": _sha256(materialization_path),
        "materializer_version": materialization.get("materializer_version"),
        "materializer_rule_version": materialization.get("materializer_rule_version"),
        "validator_version": validation.get("validator_version"),
        "validator_rule_version": validation.get("validator_rule_version"),
        "source_audit_version": audit.get("audit_version"),
        "source_audit_rule_version": audit.get("audit_rule_version"),
        "prior_source_root_overlap_count": validation["prior_source_root_overlap_count"],
        "prior_source_project_overlap_count": validation["prior_source_project_overlap_count"],
        "prior_url_overlap_count": validation["prior_url_overlap_count"],
        "grounding_writeup_overlap_count": validation["grounding_writeup_overlap_count"],
        "label_leakage_count": validation["label_leakage_count"],
        "positive_control_raw_collision_count": validation["positive_control_raw_collision_count"],
        "positive_observable_delta_rate": validation["positive_observable_delta_rate"],
        "first_blind_scoring_executed": False,
        "freeze_policy": {
            "corpus_mutation_after_freeze": "forbidden",
            "shortlist_mutation_after_freeze": "forbidden",
            "source_audit_mutation_after_freeze": "forbidden",
            "materialization_report_mutation_after_freeze": "forbidden",
            "benchmark_repairs_after_first_blind": "forbidden",
            "engine_repairs_after_first_blind": "must_not_modify_frozen_v4_inputs",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze Analysis 6.26 raw v4 corpus before first blind scoring")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--shortlist", default=str(DEFAULT_SHORTLIST))
    parser.add_argument("--audit", default=str(DEFAULT_AUDIT))
    parser.add_argument("--materialization", default=str(DEFAULT_MATERIALIZATION))
    parser.add_argument("--materialization-commit", required=True)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    report = build_freeze(
        corpus_path=Path(args.corpus),
        shortlist_path=Path(args.shortlist),
        audit_path=Path(args.audit),
        materialization_path=Path(args.materialization),
        materialization_commit=str(args.materialization_commit),
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
