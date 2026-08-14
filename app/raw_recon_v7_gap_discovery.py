from __future__ import annotations

"""Targeted, pre-scoring source discovery for V7 semantic gap families.

This module is deliberately a source-candidate finder, not a labeler. It queries
GitHub advisory metadata by the existing external CWE taxonomy and requires
family-specific context words in the advisory text. A match only means "worth
literal source adjudication". It never counts as target evidence and never runs
Analysis/detectors/admission/ranking.
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from analysis_standards import FAMILY_STANDARDS
from raw_recon_corpus import ROOT
import raw_recon_v4_source_discovery as v4
import raw_recon_v5_source_discovery as v5
from raw_recon_v7_source_firewall import (
    HARD_SCOPE,
    RESEARCH_SCOPE,
    check_candidate,
    engine_exposure_index,
    research_exposure_index,
)

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.33.v7.gap.1"
DEFAULT_BASE = ROOT / "benchmarks/raw/sources/v7_candidates_fast.json"
DEFAULT_OUT = ROOT / "benchmarks/raw/sources/v7_candidates.json"
DEFAULT_REPORT = ROOT / "benchmarks/raw/sources/v7_gap_discovery_report.json"

GAP_FAMILIES = (
    "dom_xss",
    "graphql_authorization",
    "graphql_data_exposure",
    "improper_inventory_management",
    "sensitive_business_flow_abuse",
    "source_map_exposure",
    "unsafe_api_consumption",
    "websocket_authorization",
)

# Every inner tuple is an OR group; every outer item must match at least one token.
# These are discovery context hints only. Literal capture later decides the family.
CONTEXT_GROUPS: dict[str, tuple[tuple[str, ...], ...]] = {
    "dom_xss": (
        ("dom", "document object model", "innerhtml", "outerhtml", "document.write", "client-side", "javascript"),
        ("xss", "cross-site scripting", "cross site scripting"),
    ),
    "graphql_authorization": (
        ("graphql", "resolver", "mutation", "subscription"),
        ("authorization", "authorisation", "access control", "permission", "unauthorized", "privilege"),
    ),
    "graphql_data_exposure": (
        ("graphql", "resolver", "query", "introspection"),
        ("exposure", "sensitive", "private", "unauthorized data", "field", "information disclosure"),
    ),
    "improper_inventory_management": (
        ("api", "endpoint", "route", "version"),
        ("deprecated", "legacy", "old version", "undocumented", "inventory", "shadow api", "obsolete"),
    ),
    "sensitive_business_flow_abuse": (
        ("workflow", "business", "transaction", "order", "payment", "purchase", "coupon", "redeem", "invite", "credit"),
        ("bypass", "repeat", "replay", "limit", "state", "sequence", "abuse", "multiple", "duplicate"),
    ),
    "source_map_exposure": (
        ("source map", "sourcemap", "sourcemappingurl", ".map file", ".map"),
        ("source", "javascript", "bundle", "client"),
    ),
    "unsafe_api_consumption": (
        ("api", "upstream", "third-party", "third party", "external service", "webhook", "remote service"),
        ("untrusted", "validation", "trust", "response", "redirect", "url", "insecure", "unsanitized"),
    ),
    "websocket_authorization": (
        ("websocket", "web socket", "wss://", "ws://", "subscription", "socket"),
        ("authorization", "authorisation", "access control", "permission", "authentication", "channel", "unauthorized"),
    ),
}


def _family_cwes(family: str) -> tuple[str, ...]:
    rows = FAMILY_STANDARDS.get(family, {}).get("cwe", [])
    result = tuple(
        str(item.get("id") or "").strip()
        for item in rows
        if isinstance(item, Mapping) and str(item.get("id") or "").strip().startswith("CWE-")
    )
    if not result:
        raise RuntimeError(f"v7 gap discovery has no CWE bucket for {family}")
    return result


def _context_text(row: Mapping[str, Any]) -> str:
    values = [
        str(row.get("summary") or ""),
        str(row.get("description") or ""),
        str(row.get("canonical_advisory_url") or ""),
        str(row.get("source_code_location") or ""),
        " ".join(str(v) for v in row.get("references") or []),
    ]
    return " ".join(values).casefold()


def _context_match(family: str, row: Mapping[str, Any]) -> tuple[bool, list[str]]:
    text = _context_text(row)
    matched: list[str] = []
    for group in CONTEXT_GROUPS[family]:
        hits = [token for token in group if token.casefold() in text]
        if not hits:
            return False, []
        matched.append(hits[0])
    return True, matched


def _discover_family(
    family: str,
    *,
    hard_index: Mapping[str, set[str]],
    research_index: Mapping[str, set[str]],
    max_pages: int,
    target: int,
    cache: dict[tuple[str, str, int], list[dict[str, Any]]],
    counters: dict[str, int],
) -> list[dict[str, Any]]:
    grounding = v4._grounding_writeup_urls()
    by_root: dict[str, dict[str, Any]] = {}
    for cwe in _family_cwes(family):
        for advisory_type in v5.ADVISORY_TYPES:
            rows = v5._fetch_query_rows(
                cwe,
                advisory_type,
                max_pages=max_pages,
                cache=cache,
                counters=counters,
            )
            for raw in rows:
                candidate = v5._eligible_candidate(
                    raw,
                    advisory_type=advisory_type,
                    family=family,
                    cwe=cwe,
                    excluded=hard_index,
                    grounding_urls=grounding,
                )
                if candidate is None:
                    continue
                allowed = check_candidate(candidate, index=hard_index, research_index=research_index)
                if not allowed["allowed"] or allowed["engine_seen"]:
                    continue
                matched, tokens = _context_match(family, candidate)
                if not matched:
                    continue
                candidate = dict(candidate)
                candidate.update({
                    "v7_targeted_gap_candidate": True,
                    "v7_targeted_exact_cwe": cwe in set(candidate.get("matched_cwes") or []),
                    "v7_targeted_context_match": True,
                    "v7_targeted_context_tokens": tokens,
                    "v7_engine_seen": False,
                    "v7_research_preexposed": bool(allowed["research_preexposed"]),
                    "v7_target_family_is_candidate_only": True,
                    "v7_target_family_requires_literal_adjudication": True,
                    "selection_uses_detector_scores": False,
                    "selection_uses_admission_results": False,
                    "selection_uses_ranking_results": False,
                    "selection_uses_v6_first_blind_score": False,
                    "selection_uses_v6_first_blind_case_errors": False,
                    "selection_uses_corpus_v1_labels": False,
                    "selection_uses_corpus_v1_evidence": False,
                    "selection_uses_corpus_v1_scores": False,
                    "scoring_executed": False,
                })
                root = str(candidate.get("source_root") or "").strip()
                if root not in by_root:
                    by_root[root] = candidate
                else:
                    old = by_root[root]
                    old["matched_cwes"] = sorted(set(old.get("matched_cwes") or []) | set(candidate.get("matched_cwes") or []))
                if len(by_root) >= target:
                    break
            if len(by_root) >= target:
                break
        if len(by_root) >= target:
            break
    result = list(by_root.values())
    result.sort(
        key=lambda row: (
            int(not bool(row.get("v7_research_preexposed"))),
            str(row.get("published_at") or ""),
            str(row.get("source_root") or ""),
        ),
        reverse=True,
    )
    return result


def discover_and_merge(base: Mapping[str, Any], *, max_pages: int = 12, target: int = 80) -> dict[str, Any]:
    if base.get("scoring_executed") is not False:
        raise RuntimeError("v7 base candidate pool must be unscored")
    hard_index = engine_exposure_index()
    research_index = research_exposure_index()
    cache: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    counters = defaultdict(int)
    targeted: dict[str, list[dict[str, Any]]] = {}
    for family in GAP_FAMILIES:
        targeted[family] = _discover_family(
            family,
            hard_index=hard_index,
            research_index=research_index,
            max_pages=max_pages,
            target=target,
            cache=cache,
            counters=counters,
        )

    merged = dict(base)
    raw_pools = base.get("candidates_by_family") if isinstance(base.get("candidates_by_family"), Mapping) else {}
    pools: dict[str, list[dict[str, Any]]] = {}
    for family in sorted(raw_pools):
        rows = [dict(row) for row in raw_pools.get(family) or [] if isinstance(row, Mapping)]
        seen = {str(row.get("source_root") or "").strip().casefold() for row in rows}
        for candidate in targeted.get(str(family), []):
            key = str(candidate.get("source_root") or "").strip().casefold()
            if key and key not in seen:
                seen.add(key)
                rows.append(candidate)
        pools[str(family)] = rows
    counts = {family: len(rows) for family, rows in pools.items()}
    merged.update({
        "version": "1.3.0",
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_with_targeted_gap_candidates",
        "candidates_by_family": pools,
        "family_candidate_counts": counts,
        "families_without_candidates": sorted(f for f, rows in pools.items() if not rows),
        "targeted_gap_families": list(GAP_FAMILIES),
        "targeted_gap_candidate_counts": {family: len(targeted[family]) for family in GAP_FAMILIES},
        "targeted_gap_api_request_count": int(counters["api_requests"]),
        "hard_engine_exposure_scope": HARD_SCOPE,
        "research_preexposure_scope": RESEARCH_SCOPE,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_ranking_results": False,
        "candidate_selection_uses_v6_first_blind_score": False,
        "candidate_selection_uses_v6_first_blind_case_errors": False,
        "candidate_selection_uses_corpus_v1_labels": False,
        "candidate_selection_uses_corpus_v1_evidence": False,
        "candidate_selection_uses_corpus_v1_scores": False,
        "active_target_validation_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    })
    return {"merged": merged, "targeted": targeted, "counters": dict(counters)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=str(DEFAULT_BASE))
    parser.add_argument("--output", default=str(DEFAULT_OUT))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--max-pages", type=int, default=12)
    parser.add_argument("--target", type=int, default=80)
    args = parser.parse_args()
    base = json.loads(Path(args.base).read_text(encoding="utf-8"))
    result = discover_and_merge(base, max_pages=max(1, args.max_pages), target=max(1, args.target))
    merged = result["merged"]
    Path(args.output).write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_targeted_gap_discovery_report",
        "targeted_gap_families": list(GAP_FAMILIES),
        "targeted_gap_candidate_counts": merged["targeted_gap_candidate_counts"],
        "families_without_candidates_after_merge": merged["families_without_candidates"],
        "api_request_count": merged["targeted_gap_api_request_count"],
        "hard_engine_exposure_scope": HARD_SCOPE,
        "research_preexposure_scope": RESEARCH_SCOPE,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }
    Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
