from __future__ import annotations

"""Family-targeted pre-score source discovery for Real-World Corpus V1.

This stage uses only canonical CWE taxonomy as a *discovery query*. A candidate
found through a family's CWE is not thereby labeled as that family. Final family
assignment remains a separate source/human adjudication step.
"""

import argparse
import json
import os
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

import real_world_corpus_v1 as corpus
import real_world_corpus_v1_discovery as hardened
from family_reasoning import FAMILY_ORDER
from owasp_family_catalog import CANONICAL_TAXONOMY
from owasp_phase2_catalog import PHASE2_TAXONOMY
from vulnerability_knowledge_core import BUG_PROFILES

TARGET_MIN_FAMILIES = 50
TARGET_BUFFER_FAMILIES = 60
TARGETED_VERSION = "1.0.0"
TARGETED_RULE_VERSION = "2026.08.14.2"


def canonical_family_cwes() -> dict[str, tuple[str, ...]]:
    canonical = tuple(str(item) for item in FAMILY_ORDER)
    result: dict[str, set[str]] = {family: set() for family in canonical}

    for family, profile in BUG_PROFILES.items():
        if family not in result:
            continue
        taxonomy = profile.get("taxonomy") if isinstance(profile, Mapping) else {}
        if isinstance(taxonomy, Mapping):
            result[family].update(str(item).upper() for item in taxonomy.get("cwe", []) if str(item).strip())

    for catalog in (CANONICAL_TAXONOMY, PHASE2_TAXONOMY):
        for family, taxonomy in catalog.items():
            if family not in result or not isinstance(taxonomy, Mapping):
                continue
            result[family].update(str(item).upper() for item in taxonomy.get("cwe", []) if str(item).strip())

    return {family: tuple(sorted(values)) for family, values in result.items()}


def configure_hardened_firewall() -> None:
    corpus.identities_from_records = hardened.strict_identities_from_records
    corpus.normalize_advisory = hardened.normalize_advisory_with_project_fallback
    existing_names = {item[0] for item in corpus.HISTORICAL_CORPORA}
    corpus.HISTORICAL_CORPORA = corpus.HISTORICAL_CORPORA + tuple(
        item for item in hardened.EXTRA_CONSUMED_CORPORA if item[0] not in existing_names
    )


def _query_url(cwe: str) -> str:
    query = urllib.parse.urlencode(
        {
            "per_page": 100,
            "type": "reviewed",
            "sort": "published",
            "direction": "desc",
            "cwes": cwe,
        }
    )
    return f"https://api.github.com/advisories?{query}"


def find_candidate_for_family(
    family: str,
    cwes: tuple[str, ...],
    exposed: Mapping[str, set[str]],
    *,
    token: str,
    used_roots: set[str],
    used_projects: set[str],
    max_pages_per_cwe: int,
) -> tuple[dict[str, Any] | None, dict[str, int]]:
    counters: Counter[str] = Counter()
    for cwe in cwes:
        next_url = _query_url(cwe)
        pages = 0
        seen_page_heads: set[str] = set()
        while next_url and pages < max(1, int(max_pages_per_cwe)):
            rows, following = hardened._api_page(next_url, token=token)
            if not isinstance(rows, list) or not rows:
                break
            pages += 1
            counters["pages_fetched"] += 1
            counters["advisories_seen"] += len(rows)
            page_head = str(rows[0].get("ghsa_id") or "") if isinstance(rows[0], Mapping) else ""
            if page_head and page_head in seen_page_heads:
                counters["repeated_page_guard"] += 1
                break
            if page_head:
                seen_page_heads.add(page_head)

            for raw in rows:
                if not isinstance(raw, Mapping):
                    continue
                if raw.get("withdrawn_at"):
                    counters["withdrawn"] += 1
                    continue
                candidate = hardened.normalize_advisory_with_project_fallback(raw)
                root = str(candidate.get("source_root") or "").strip()
                project = corpus._project(candidate.get("source_project"))
                if not root or not project:
                    counters["missing_root_or_project"] += 1
                    continue
                if root in used_roots:
                    counters["already_selected_root"] += 1
                    continue
                if project in used_projects:
                    counters["already_selected_project"] += 1
                    continue
                reasons = corpus.exposure_reasons(candidate, exposed)
                if reasons:
                    for reason in reasons:
                        counters[reason] += 1
                    continue
                candidate = dict(candidate)
                candidate.update(
                    {
                        "family_target": family,
                        "target_cwe": cwe,
                        "targeting_basis": "canonical_cwe_query_only_not_final_family_label",
                        "family_label_adjudicated": False,
                        "source_feasibility_reviewed": False,
                        "human_verified": False,
                        "scoring_executed": False,
                    }
                )
                return candidate, dict(counters)
            next_url = following
    return None, dict(counters)


def targeted_discovery(
    *,
    token: str,
    max_pages_per_cwe: int = 3,
    target_buffer_families: int = TARGET_BUFFER_FAMILIES,
) -> dict[str, Any]:
    configure_hardened_firewall()
    exposed, historical_reports = corpus.load_historical_exposure()
    missing_history = [item["name"] for item in historical_reports if not item.get("loaded")]
    if missing_history:
        raise RuntimeError("historical_exposure_incomplete:" + ",".join(missing_history))

    family_cwes = canonical_family_cwes()
    selected: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    family_diagnostics: dict[str, Any] = {}
    used_roots: set[str] = set()
    used_projects: set[str] = set()

    # Families with fewer/more-specific CWE choices are attempted first so broad
    # shared CWE families do not consume their projects prematurely.
    ordered = sorted(
        FAMILY_ORDER,
        key=lambda family: (0 if family_cwes.get(str(family)) else 1, len(family_cwes.get(str(family), ())), str(family)),
    )
    for family_value in ordered:
        family = str(family_value)
        cwes = family_cwes.get(family, ())
        if not cwes:
            unresolved.append({"family": family, "reason": "no_canonical_cwe_for_targeted_query"})
            continue
        candidate, diagnostics = find_candidate_for_family(
            family,
            cwes,
            exposed,
            token=token,
            used_roots=used_roots,
            used_projects=used_projects,
            max_pages_per_cwe=max_pages_per_cwe,
        )
        family_diagnostics[family] = {"cwes": list(cwes), "diagnostics": diagnostics}
        if candidate is None:
            unresolved.append({"family": family, "reason": "no_fresh_independent_candidate_from_canonical_cwe", "cwes": list(cwes)})
            continue
        selected.append(candidate)
        used_roots.add(str(candidate["source_root"]))
        used_projects.add(corpus._project(candidate["source_project"]))
        if len(selected) >= int(target_buffer_families):
            break

    return {
        "version": TARGETED_VERSION,
        "rule_version": TARGETED_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_family_targeted_source_discovery",
        "scoring_executed": False,
        "target_contact_performed": False,
        "human_labels_created": False,
        "family_assignment_is_final": False,
        "target_minimum_families": TARGET_MIN_FAMILIES,
        "target_buffer_families": int(target_buffer_families),
        "canonical_family_count": len(FAMILY_ORDER),
        "families_with_cwe_queries": sum(1 for values in family_cwes.values() if values),
        "represented_family_target_count": len(selected),
        "unique_source_root_count": len(used_roots),
        "unique_source_project_count": len(used_projects),
        "selected": selected,
        "unresolved": unresolved,
        "family_diagnostics": family_diagnostics,
        "historical_exposure": historical_reports,
    }


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Family-targeted source discovery for Real-World Corpus V1")
    parser.add_argument("--output", default="benchmarks/real_world/v1/targeted_candidates.json")
    parser.add_argument("--report", default="benchmarks/real_world/v1/targeted_discovery_report.json")
    parser.add_argument("--max-pages-per-cwe", type=int, default=3)
    parser.add_argument("--target-buffer-families", type=int, default=60)
    parser.add_argument("--github-token", default="")
    args = parser.parse_args(argv)

    result = targeted_discovery(
        token=args.github_token or os.environ.get("GITHUB_TOKEN", ""),
        max_pages_per_cwe=args.max_pages_per_cwe,
        target_buffer_families=args.target_buffer_families,
    )
    _write(Path(args.output), result)
    report = {key: value for key, value in result.items() if key not in {"selected", "family_diagnostics"}}
    _write(Path(args.report), report)
    count = int(result["represented_family_target_count"])
    print(json.dumps({"ok": count >= TARGET_MIN_FAMILIES, "represented_family_targets": count, "unique_projects": result["unique_source_project_count"]}, sort_keys=True))
    if count < TARGET_MIN_FAMILIES:
        raise SystemExit(f"insufficient_family_target_coverage:{count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
