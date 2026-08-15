from __future__ import annotations

"""Repair targeted metadata when the same advisory already exists in V7 base discovery.

This is a pre-scoring source-selection repair only. It never runs Analysis and never
creates a family label. Targeted metadata remains candidate-only until literal
source adjudication.
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v7_gap_discovery import _discover_family
from raw_recon_v7_source_firewall import engine_exposure_index, research_exposure_index

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.duplicate-target.1"
DEFAULT_INPUT = ROOT / "benchmarks/raw/sources/v7_candidates.json"
DEFAULT_OUTPUT = DEFAULT_INPUT
DEFAULT_REPORT = ROOT / "benchmarks/raw/sources/v7_duplicate_target_repair_report.json"
REPAIR_FAMILIES = ("dom_xss", "sensitive_business_flow_abuse")

TARGETED_FIELDS = (
    "v7_targeted_gap_candidate",
    "v7_targeted_exact_cwe",
    "v7_targeted_context_match",
    "v7_targeted_context_tokens",
    "v7_engine_seen",
    "v7_research_preexposed",
    "v7_target_family_is_candidate_only",
    "v7_target_family_requires_literal_adjudication",
    "selection_uses_detector_scores",
    "selection_uses_admission_results",
    "selection_uses_ranking_results",
    "selection_uses_v6_first_blind_score",
    "selection_uses_v6_first_blind_case_errors",
    "selection_uses_corpus_v1_labels",
    "selection_uses_corpus_v1_evidence",
    "selection_uses_corpus_v1_scores",
    "scoring_executed",
)


def merge_targeted_rows(
    payload: Mapping[str, Any],
    targeted_by_family: Mapping[str, list[Mapping[str, Any]]],
) -> tuple[dict[str, Any], dict[str, int]]:
    if payload.get("scoring_executed") is not False or payload.get("first_blind_consumed") is not False:
        raise RuntimeError("V7 duplicate-target repair requires an unscored, unconsumed candidate pool")
    out = dict(payload)
    raw_pools = payload.get("candidates_by_family")
    if not isinstance(raw_pools, Mapping):
        raise RuntimeError("V7 candidate pool is missing candidates_by_family")

    pools: dict[str, list[dict[str, Any]]] = {
        str(family): [dict(row) for row in rows or [] if isinstance(row, Mapping)]
        for family, rows in raw_pools.items()
    }
    promoted: dict[str, int] = {}

    for family, targeted_rows in targeted_by_family.items():
        rows = pools.setdefault(family, [])
        by_root = {
            str(row.get("source_root") or "").strip().casefold(): i
            for i, row in enumerate(rows)
            if str(row.get("source_root") or "").strip()
        }
        count = 0
        for raw_target in targeted_rows:
            target = dict(raw_target)
            root = str(target.get("source_root") or "").strip().casefold()
            if not root:
                continue
            if root in by_root:
                i = by_root[root]
                existing = dict(rows[i])
                existing_project = str(existing.get("source_project") or "").strip().casefold()
                target_project = str(target.get("source_project") or "").strip().casefold()
                if existing_project and target_project and existing_project != target_project:
                    raise RuntimeError(f"V7 duplicate root project mismatch for {family}: {root}")
                existing["matched_cwes"] = sorted(
                    set(str(v) for v in existing.get("matched_cwes") or [])
                    | set(str(v) for v in target.get("matched_cwes") or [])
                )
                for field in TARGETED_FIELDS:
                    if field in target:
                        existing[field] = target[field]
                rows[i] = existing
                count += 1
            else:
                rows.append(target)
                by_root[root] = len(rows) - 1
                count += 1
        promoted[family] = count

    out["candidates_by_family"] = pools
    out["family_candidate_counts"] = {family: len(rows) for family, rows in pools.items()}
    out["families_without_candidates"] = sorted(family for family, rows in pools.items() if not rows)
    out["duplicate_target_repair_version"] = VERSION
    out["duplicate_target_repair_rule_version"] = RULE_VERSION
    out["duplicate_target_repair_families"] = sorted(targeted_by_family)
    out["duplicate_target_repair_scoring_executed"] = False
    return out, promoted


def repair(payload: Mapping[str, Any], *, max_pages: int = 12, target: int = 20) -> tuple[dict[str, Any], dict[str, Any]]:
    hard = engine_exposure_index()
    research = research_exposure_index()
    cache: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    counters = defaultdict(int)
    targeted: dict[str, list[dict[str, Any]]] = {}
    for family in REPAIR_FAMILIES:
        targeted[family] = _discover_family(
            family,
            hard_index=hard,
            research_index=research,
            max_pages=max_pages,
            target=target,
            cache=cache,
            counters=counters,
        )
    merged, promoted = merge_targeted_rows(payload, targeted)
    for family in REPAIR_FAMILIES:
        if not targeted[family]:
            raise RuntimeError(f"V7 duplicate-target repair found no engine-unseen targeted candidates for {family}")
        if promoted.get(family, 0) < 1:
            raise RuntimeError(f"V7 duplicate-target repair promoted no candidates for {family}")
    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_duplicate_target_metadata_repair",
        "families": list(REPAIR_FAMILIES),
        "targeted_candidate_counts": {family: len(targeted[family]) for family in REPAIR_FAMILIES},
        "promoted_or_appended_counts": promoted,
        "api_request_count": int(counters["api_requests"]),
        "scoring_executed": False,
        "first_blind_consumed": False,
    }
    return merged, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--max-pages", type=int, default=12)
    parser.add_argument("--target", type=int, default=20)
    args = parser.parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    merged, report = repair(payload, max_pages=max(1, args.max_pages), target=max(1, args.target))
    Path(args.output).write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
