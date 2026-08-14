from __future__ import annotations

import json
from typing import Any, Mapping

from raw_recon_corpus import ROOT
import raw_recon_v5_source_discovery as v5
from raw_recon_v7_source_firewall import HARD_SCOPE, RESEARCH_SCOPE
from raw_recon_v7_source_firewall import RULE_VERSION as FIREWALL_RULE_VERSION
from raw_recon_v7_source_firewall import VERSION as FIREWALL_VERSION
from raw_recon_v7_source_firewall import check_candidate, engine_exposure_index, research_exposure_index

VERSION = "1.2.0"
RULE_VERSION = "2026.08.14.6.33.v7.unseen.3"
OUT = ROOT / "benchmarks/raw/sources/v7_candidates.json"


def discover(**kwargs: Any) -> dict[str, Any]:
    # Hard contamination is built only from corpora Analysis actually consumed,
    # plus the pinned Corpus V1 exclusion set. Broad historical research metadata
    # is cached separately and used only to annotate/deprioritize pre-exposed
    # candidates. Neither index uses detector/admission/ranking output.
    hard_index = engine_exposure_index()
    research_index = research_exposure_index()
    original_exposure_index = v5.exposure_index
    try:
        v5.exposure_index = lambda: hard_index
        report = v5.discover(**kwargs)
    finally:
        v5.exposure_index = original_exposure_index

    pools = report.get("candidates_by_family") if isinstance(report.get("candidates_by_family"), Mapping) else {}
    filtered: dict[str, list[dict[str, Any]]] = {}
    rejected: dict[str, list[dict[str, Any]]] = {}
    research_preexposed_counts: dict[str, int] = {}
    for family, raw_rows in pools.items():
        kept: list[dict[str, Any]] = []
        denied: list[dict[str, Any]] = []
        preexposed = 0
        for raw in raw_rows or []:
            if not isinstance(raw, Mapping):
                continue
            row = dict(raw)
            check = check_candidate(row, index=hard_index, research_index=research_index)
            row["v7_firewall_allowed"] = bool(check["allowed"])
            row["v7_engine_seen"] = bool(check["engine_seen"])
            row["v7_research_preexposed"] = bool(check["research_preexposed"])
            row["v7_firewall_version"] = FIREWALL_VERSION
            row["v7_firewall_rule_version"] = FIREWALL_RULE_VERSION
            row["v7_selection_uses_v6_score"] = False
            row["v7_selection_uses_v6_case_errors"] = False
            row["v7_selection_uses_corpus_v1_labels"] = False
            row["v7_selection_uses_corpus_v1_evidence"] = False
            row["v7_selection_uses_corpus_v1_scores"] = False
            if check["allowed"]:
                if check["research_preexposed"]:
                    preexposed += 1
                kept.append(row)
            else:
                denied.append({
                    "source_root": check["source_root"],
                    "source_project": check["source_project"],
                    "engine_seen": True,
                    "engine_root_overlap": check["engine_root_overlap"],
                    "engine_project_overlap": check["engine_project_overlap"],
                    "engine_url_overlap": check["engine_url_overlap"],
                    "engine_identifier_overlap": check["engine_identifier_overlap"],
                })
        filtered[str(family)] = kept
        research_preexposed_counts[str(family)] = preexposed
        if denied:
            rejected[str(family)] = denied

    report = dict(report)
    report.update({
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_unscored_source_discovery",
        "source_firewall_version": FIREWALL_VERSION,
        "source_firewall_rule_version": FIREWALL_RULE_VERSION,
        "hard_engine_exposure_scope": HARD_SCOPE,
        "research_preexposure_scope": RESEARCH_SCOPE,
        "engine_exposure_index_cached_once": True,
        "research_exposure_index_cached_once": True,
        "candidates_by_family": filtered,
        "family_candidate_counts": {family: len(rows) for family, rows in filtered.items()},
        "research_preexposed_candidate_counts": research_preexposed_counts,
        "engine_exposure_rejections": rejected,
        "engine_exposure_rejection_count": sum(len(rows) for rows in rejected.values()),
        "scoring_executed": False,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_ranking_results": False,
        "candidate_selection_uses_v6_first_blind_score": False,
        "candidate_selection_uses_v6_first_blind_case_errors": False,
        "candidate_selection_uses_corpus_v1_labels": False,
        "candidate_selection_uses_corpus_v1_evidence": False,
        "candidate_selection_uses_corpus_v1_scores": False,
        "active_target_validation_performed": False,
    })
    report["families_without_candidates"] = sorted(family for family, rows in filtered.items() if not rows)
    return report


def main() -> int:
    report = discover()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_count": report.get("family_count"),
        "families_without_candidates": report.get("families_without_candidates"),
        "families_without_semantic_candidates": report.get("families_without_semantic_candidates"),
        "engine_exposure_rejection_count": report.get("engine_exposure_rejection_count"),
        "research_preexposed_candidate_count": sum(report.get("research_preexposed_candidate_counts", {}).values()),
        "api_request_count": report.get("api_request_count"),
        "scoring_executed": report.get("scoring_executed"),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
