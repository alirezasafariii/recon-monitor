from __future__ import annotations

"""Repair a V7 global-project conflict without re-running broad discovery.

The repair is pre-scoring and family-candidate-only. It discovers additional
broken-function-authorization advisory sources via the existing CWE taxonomy,
requires explicit privileged-function/access-control context, rejects every hard
engine-exposed or Corpus V1 source, and never treats the candidate family as
final until literal source adjudication.
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
    check_candidate,
    engine_exposure_index,
    research_exposure_index,
)

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.33.v7.uniqueness.1"
FAMILY = "broken_function_authorization"
DEFAULT_CANDIDATES = ROOT / "benchmarks/raw/sources/v7_candidates.json"
DEFAULT_REPORT = ROOT / "benchmarks/raw/sources/v7_uniqueness_repair_report.json"

PRIVILEGED = (
    "admin", "administrator", "privileged", "role", "permission", "function",
    "endpoint", "route", "operation", "management", "moderator", "staff",
)
AUTHZ = (
    "authorization", "authorisation", "access control", "unauthorized",
    "privilege escalation", "missing authorization", "permission check",
    "role check", "access restriction",
)


def _cwes() -> tuple[str, ...]:
    rows = FAMILY_STANDARDS[FAMILY]["cwe"]
    result = tuple(str(row.get("id") or "").strip() for row in rows if isinstance(row, Mapping))
    if not result:
        raise RuntimeError("BFLA CWE taxonomy missing")
    return result


def _haystack(row: Mapping[str, Any]) -> str:
    return " ".join((
        str(row.get("summary") or ""),
        str(row.get("description") or ""),
        str(row.get("canonical_advisory_url") or ""),
        str(row.get("source_code_location") or ""),
        " ".join(str(v) for v in row.get("references") or []),
    )).casefold()


def _context(row: Mapping[str, Any]) -> tuple[bool, list[str]]:
    text = _haystack(row)
    p = next((token for token in PRIVILEGED if token in text), "")
    a = next((token for token in AUTHZ if token in text), "")
    return bool(p and a), [p, a] if p and a else []


def repair(payload: Mapping[str, Any], *, max_pages: int = 20, target: int = 20) -> tuple[dict[str, Any], dict[str, Any]]:
    if payload.get("scoring_executed") is not False or payload.get("first_blind_consumed") is not False:
        raise RuntimeError("V7 candidate registry is not pre-scoring")
    pools = payload.get("candidates_by_family")
    if not isinstance(pools, Mapping) or FAMILY not in pools:
        raise RuntimeError("BFLA candidate pool missing")

    hard = engine_exposure_index()
    research = research_exposure_index()
    grounding = v4._grounding_writeup_urls()
    cache: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    counters = defaultdict(int)
    discovered: dict[str, dict[str, Any]] = {}

    for cwe in _cwes():
        for advisory_type in v5.ADVISORY_TYPES:
            for raw in v5._fetch_query_rows(cwe, advisory_type, max_pages=max_pages, cache=cache, counters=counters):
                candidate = v5._eligible_candidate(
                    raw,
                    advisory_type=advisory_type,
                    family=FAMILY,
                    cwe=cwe,
                    excluded=hard,
                    grounding_urls=grounding,
                )
                if candidate is None:
                    continue
                check = check_candidate(candidate, index=hard, research_index=research)
                if not check["allowed"] or check["engine_seen"]:
                    continue
                ok, tokens = _context(candidate)
                if not ok:
                    continue
                project = str(candidate.get("source_project") or "").strip().casefold()
                root = str(candidate.get("source_root") or "").strip().casefold()
                if not project or not root or project == "getgrav/grav":
                    continue
                row = dict(candidate)
                row.update({
                    "v7_uniqueness_repair_candidate": True,
                    "v7_targeted_gap_candidate": True,
                    "v7_targeted_exact_cwe": cwe in set(row.get("matched_cwes") or []),
                    "v7_targeted_context_match": True,
                    "v7_targeted_context_tokens": tokens,
                    "v7_engine_seen": False,
                    "v7_research_preexposed": bool(check["research_preexposed"]),
                    "v7_target_family_is_candidate_only": True,
                    "v7_target_family_requires_literal_adjudication": True,
                    "v7_target_family_is_final": False,
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
                discovered[root] = row
                if len(discovered) >= target:
                    break
            if len(discovered) >= target:
                break
        if len(discovered) >= target:
            break

    if not discovered:
        raise RuntimeError("no engine-unseen alternative BFLA source discovered")

    result = dict(payload)
    merged_pools = {str(k): [dict(x) for x in (v or []) if isinstance(x, Mapping)] for k, v in pools.items()}
    current = merged_pools[FAMILY]
    existing_roots = {str(row.get("source_root") or "").strip().casefold() for row in current}
    added = []
    for root, row in sorted(discovered.items()):
        if root in existing_roots:
            continue
        existing_roots.add(root)
        current.append(row)
        added.append({
            "source_root": row.get("source_root"),
            "source_project": row.get("source_project"),
            "matched_cwes": row.get("matched_cwes"),
            "context_tokens": row.get("v7_targeted_context_tokens"),
            "research_preexposed": row.get("v7_research_preexposed"),
        })
    if not added:
        raise RuntimeError("BFLA repair found no new root after deduplication")

    result.update({
        "candidates_by_family": merged_pools,
        "family_candidate_counts": {family: len(rows) for family, rows in merged_pools.items()},
        "v7_uniqueness_repair_applied": True,
        "v7_uniqueness_repair_family": FAMILY,
        "v7_uniqueness_repair_added_count": len(added),
        "v7_uniqueness_repair_rule_version": RULE_VERSION,
        "scoring_executed": False,
        "first_blind_consumed": False,
    })
    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_project_uniqueness_repair",
        "family": FAMILY,
        "forbidden_conflicting_project": "getgrav/grav",
        "api_request_count": int(counters["api_requests"]),
        "added_count": len(added),
        "added": added,
        "engine_seen_added_count": 0,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }
    return result, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", default=str(DEFAULT_CANDIDATES))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--target", type=int, default=20)
    args = parser.parse_args()
    path = Path(args.candidates)
    payload = json.loads(path.read_text(encoding="utf-8"))
    repaired, report = repair(payload, max_pages=max(1, args.max_pages), target=max(1, args.target))
    path.write_text(json.dumps(repaired, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
