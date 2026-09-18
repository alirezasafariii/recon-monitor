from __future__ import annotations

"""Coverage expansion for all canonical Recon Monitor vulnerability families.

This stage performs public-source discovery only. It does not contact
vulnerability targets, execute payloads, create vulnerability labels, or run
Analysis scoring. Its purpose is to keep every canonical family visible in the
corpus plan and to find independent GitHub-reviewed advisory roots for coverage
deficits.

Families with canonical CWE identifiers use targeted CWE discovery. Families
without a useful CWE use a conservative semantic scan of reviewed advisories.
Ambiguous semantic matches are rejected rather than guessed.
"""

import argparse
import json
import os
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

import real_world_corpus_v1 as corpus
import real_world_corpus_v1_discovery as hardened
from family_reasoning import FAMILY_ORDER
from real_world_corpus_v1_family_match import (
    cwe_owners,
    family_terms,
    semantic_family_candidates,
    semantic_matches,
)
from real_world_corpus_v1_targeted import canonical_family_cwes

COVERAGE_EXPANDER_VERSION = "1.0.0"
COVERAGE_EXPANDER_RULE_VERSION = "2026.09.18.1"
DEFAULT_FAMILY_QUOTA = 1
RECOMMENDED_FAMILY_QUOTA = 10
# Reviewed-advisory IDs used only as discovery accelerators for sparse families.
# They do not bypass semantic/taxonomy matching, historical-exposure firewalling,
# or later feasibility/capture gates.
REVIEWED_DISCOVERY_SEEDS: dict[str, tuple[str, ...]] = {
    "business_logic": ("GHSA-7V3V-CP44-VC8M",),
    "http_verb_tampering": ("GHSA-VXRR-W42W-W76G",),
    "ssi_injection": ("GHSA-8R5J-GM3J-CX9C",),
    "host_header_injection": ("GHSA-7GCC-R8M5-44QM",),
    "client_side_resource_manipulation": ("GHSA-RFFM-9Q57-Q649",),
    "improper_inventory_management": ("GHSA-6RMH-7XCM-CPXJ",),
    "backup_unreferenced_file_exposure": ("GHSA-G39V-CVJH-8FPF",),
}

DEFAULT_MAX_PAGES_PER_FAMILY = 5


def _text(value: Any) -> str:
    return str(value or "").strip()


def _project(value: Any) -> str:
    return corpus._project(value)


def _source_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in payload.get("sources", []) or []
        if isinstance(row, Mapping)
    ]


def _attested_origins_by_family(attestation: Mapping[str, Any] | None) -> Counter[str]:
    result: Counter[str] = Counter()
    if not isinstance(attestation, Mapping):
        return result
    seen: set[tuple[str, str]] = set()
    for raw in attestation.get("records", []) or []:
        if not isinstance(raw, Mapping):
            continue
        family = _text(raw.get("family"))
        origin = _text(raw.get("case_origin_id"))
        if family and origin and (family, origin) not in seen:
            seen.add((family, origin))
            result[family] += 1
    return result


def _targeted_origins_by_family(feasibility: Mapping[str, Any]) -> Counter[str]:
    result: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    for row in _source_rows(feasibility):
        taxonomy_raw = row.get("source_taxonomy_match")
        taxonomy = taxonomy_raw if isinstance(taxonomy_raw, Mapping) else {}
        family = _text(taxonomy.get("family_target")) or _text(row.get("family_target"))
        root = _text(row.get("source_root")).upper()
        if family and root and (family, root) not in seen:
            seen.add((family, root))
            result[family] += 1
    return result


def _strong_revision_origins_by_family(feasibility: Mapping[str, Any]) -> Counter[str]:
    result: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    for row in _source_rows(feasibility):
        if _text(row.get("capture_feasibility")) != "strong_revision_boundary":
            continue
        taxonomy_raw = row.get("source_taxonomy_match")
        taxonomy = taxonomy_raw if isinstance(taxonomy_raw, Mapping) else {}
        family = _text(taxonomy.get("family_target")) or _text(row.get("family_target"))
        root = _text(row.get("source_root")).upper()
        if family and root and (family, root) not in seen:
            seen.add((family, root))
            result[family] += 1
    return result


def coverage_inventory(
    feasibility: Mapping[str, Any],
    *,
    attestation: Mapping[str, Any] | None = None,
    quota: int = DEFAULT_FAMILY_QUOTA,
) -> dict[str, Any]:
    quota = max(1, int(quota))
    cwes = canonical_family_cwes()
    targeted = _targeted_origins_by_family(feasibility)
    strong = _strong_revision_origins_by_family(feasibility)
    attested = _attested_origins_by_family(attestation)

    families: list[dict[str, Any]] = []
    for raw_family in FAMILY_ORDER:
        family = str(raw_family)
        canonical_cwes = list(cwes.get(family, ()))
        current = int(targeted.get(family, 0))
        families.append({
            "family": family,
            "canonical_cwes": canonical_cwes,
            "discovery_mode": "cwe" if canonical_cwes else "semantic",
            "semantic_terms": list(family_terms(family)),
            "targeted_origin_count": current,
            "strong_revision_origin_count": int(strong.get(family, 0)),
            "source_attested_origin_count": int(attested.get(family, 0)),
            "quota": quota,
            "deficit": max(0, quota - current),
            "quota_met": current >= quota,
        })

    missing = [row["family"] for row in families if not row["quota_met"]]
    return {
        "version": COVERAGE_EXPANDER_VERSION,
        "rule_version": COVERAGE_EXPANDER_RULE_VERSION,
        "canonical_family_count": len(FAMILY_ORDER),
        "quota": quota,
        "represented_family_count": len(FAMILY_ORDER) - len(missing),
        "missing_family_count": len(missing),
        "missing_families": missing,
        "all_families_represented": not missing,
        "families": families,
        "safety": {
            "taxonomy_is_discovery_only": True,
            "no_labels_created": True,
            "no_analysis_scoring": True,
            "no_target_contact": True,
        },
    }


def _raw_advisory_cwes(raw: Mapping[str, Any]) -> set[str]:
    return {
        _text(item.get("cwe_id") if isinstance(item, Mapping) else item).upper()
        for item in raw.get("cwes", []) or []
        if _text(item.get("cwe_id") if isinstance(item, Mapping) else item)
    }


def _raw_text(raw: Mapping[str, Any]) -> str:
    return " ".join([
        _text(raw.get("summary")),
        _text(raw.get("description")),
    ])


def candidate_family_match(
    raw: Mapping[str, Any],
    family: str,
) -> dict[str, Any]:
    family = _text(family)
    canonical = canonical_family_cwes()
    expected_cwes = {str(value).upper() for value in canonical.get(family, ())}
    advisory_cwes = _raw_advisory_cwes(raw)
    matched_cwes = sorted(expected_cwes & advisory_cwes)
    summary_text = _text(raw.get("summary"))
    full_text = _raw_text(raw)
    semantic = semantic_matches(family, summary_text)

    if matched_cwes:
        unique_cwes = [
            cwe for cwe in matched_cwes
            if cwe_owners().get(cwe, ()) == (family,)
        ]
        if unique_cwes:
            return {
                "matched": True,
                "basis": "unique_canonical_cwe",
                "matched_cwes": unique_cwes,
                "semantic_matches": semantic,
            }

        competitors = set()
        for cwe in matched_cwes:
            competitors.update(cwe_owners().get(cwe, ()))
        competitors.discard(family)
        competing_semantics = {
            other: semantic_matches(other, summary_text)
            for other in sorted(competitors)
        }
        competing_semantics = {
            other: matches
            for other, matches in competing_semantics.items()
            if matches
        }
        if semantic and not competing_semantics:
            return {
                "matched": True,
                "basis": "shared_cwe_plus_unique_semantics",
                "matched_cwes": matched_cwes,
                "semantic_matches": semantic,
            }
        return {
            "matched": False,
            "basis": "",
            "matched_cwes": matched_cwes,
            "semantic_matches": semantic,
            "reason": "shared_cwe_ambiguous",
        }

    if not expected_cwes:
        semantic_candidates = semantic_family_candidates(summary_text)
        matches = semantic_candidates.get(family, [])
        competing = {
            other: values
            for other, values in semantic_candidates.items()
            if other != family and values
        }
        if matches and not competing:
            return {
                "matched": True,
                "basis": "unique_semantic_no_cwe",
                "matched_cwes": [],
                "semantic_matches": matches,
            }
        return {
            "matched": False,
            "basis": "",
            "matched_cwes": [],
            "semantic_matches": matches,
            "reason": "semantic_no_cwe_ambiguous_or_missing",
        }

    semantic_candidates = semantic_family_candidates(text)
    fallback_matches = semantic_candidates.get(family, [])
    competing = {
        other: values
        for other, values in semantic_candidates.items()
        if other != family and values
    }
    if fallback_matches and not competing:
        return {
            "matched": True,
            "basis": "unique_semantics_cwe_fallback",
            "matched_cwes": [],
            "semantic_matches": fallback_matches,
        }

    return {
        "matched": False,
        "basis": "",
        "matched_cwes": [],
        "semantic_matches": semantic,
        "reason": "canonical_cwe_not_present",
    }


def _configure_firewall() -> tuple[dict[str, set[str]], list[dict[str, Any]]]:
    corpus.identities_from_records = hardened.strict_identities_from_records
    corpus.normalize_advisory = hardened.normalize_advisory_with_project_fallback
    existing_names = {item[0] for item in corpus.HISTORICAL_CORPORA}
    corpus.HISTORICAL_CORPORA = corpus.HISTORICAL_CORPORA + tuple(
        item
        for item in hardened.EXTRA_CONSUMED_CORPORA
        if item[0] not in existing_names
    )
    exposed, reports = corpus.load_historical_exposure()
    missing = [item["name"] for item in reports if not item.get("loaded")]
    if missing:
        raise RuntimeError("historical_exposure_incomplete:" + ",".join(missing))
    return exposed, reports


def _cwe_query(cwe: str) -> str:
    value = _text(cwe).upper()
    if value.startswith("CWE-"):
        value = value[4:]
    query = urllib.parse.urlencode({
        "per_page": 100,
        "type": "reviewed",
        "sort": "published",
        "direction": "desc",
        "cwes": value,
    })
    return f"https://api.github.com/advisories?{query}"


def _general_query() -> str:
    query = urllib.parse.urlencode({
        "per_page": 100,
        "type": "reviewed",
        "sort": "published",
        "direction": "desc",
    })
    return f"https://api.github.com/advisories?{query}"


def _candidate_from_raw(
    raw: Mapping[str, Any],
    *,
    family: str,
    match: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = hardened.normalize_advisory_with_project_fallback(raw)
    canonical = canonical_family_cwes()
    matched_cwes = list(match.get("matched_cwes", []) or [])
    target_cwe = matched_cwes[0] if matched_cwes else ""
    candidate.update({
        "family_target": family,
        "target_cwe": target_cwe or None,
        "targeting_basis": _text(match.get("basis")),
        "family_label_adjudicated": False,
        "family_assignment_is_final": False,
        "semantic_matches": list(match.get("semantic_matches", []) or []),
        "canonical_family_cwes": list(canonical.get(family, ())),
        "source_feasibility_reviewed": False,
        "human_verified": False,
        "scoring_executed": False,
    })
    return candidate


def discover_reviewed_seeds(
    family: str,
    *,
    exposed: Mapping[str, set[str]],
    token: str,
    needed: int,
    used_roots: set[str],
    used_projects: set[str],
) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    rejected: Counter[str] = Counter()
    for root in REVIEWED_DISCOVERY_SEEDS.get(_text(family), ()):
        if len(selected) >= max(0, int(needed)):
            break
        try:
            raw = hardened._api_json(
                f"https://api.github.com/advisories/{root}",
                token=token,
            )
        except Exception:
            rejected["seed_fetch_failed"] += 1
            continue
        if not isinstance(raw, Mapping):
            rejected["seed_payload_invalid"] += 1
            continue
        if raw.get("withdrawn_at"):
            rejected["seed_withdrawn"] += 1
            continue
        match = candidate_family_match(raw, family)
        if not match.get("matched"):
            rejected["seed_family_mismatch"] += 1
            continue
        candidate = _candidate_from_raw(raw, family=family, match=match)
        source_root = _text(candidate.get("source_root")).upper()
        project = _project(candidate.get("source_project"))
        if not source_root or not project:
            rejected["seed_missing_root_or_project"] += 1
            continue
        reasons = corpus.exposure_reasons(candidate, exposed)
        if reasons:
            for reason in reasons:
                rejected[f"seed_{reason}"] += 1
            continue
        if source_root in used_roots:
            rejected["seed_duplicate_or_existing_root"] += 1
            continue
        if project in used_projects:
            rejected["seed_duplicate_or_existing_project"] += 1
            continue
        used_roots.add(source_root)
        used_projects.add(project)
        selected.append(candidate)
    return {
        "selected": selected,
        "selected_count": len(selected),
        "rejected_counts": dict(sorted(rejected.items())),
    }


def discover_for_family(
    family: str,
    *,
    exposed: Mapping[str, set[str]],
    token: str,
    needed: int,
    max_pages: int,
    used_roots: set[str],
    used_projects: set[str],
) -> dict[str, Any]:
    family = _text(family)
    needed = max(0, int(needed))
    if not needed:
        return {
            "family": family,
            "selected": [],
            "selected_count": 0,
            "rejected_counts": {},
            "pages_fetched": 0,
        }

    cwes = list(canonical_family_cwes().get(family, ()))
    start_urls = [_cwe_query(cwe) for cwe in cwes] or [_general_query()]
    seed_result = discover_reviewed_seeds(
        family,
        exposed=exposed,
        token=token,
        needed=needed,
        used_roots=used_roots,
        used_projects=used_projects,
    )
    selected: list[dict[str, Any]] = list(seed_result["selected"])
    rejected: Counter[str] = Counter(seed_result["rejected_counts"])
    pages_fetched = 0
    seen_page_heads: set[str] = set()

    for start_url in start_urls:
        next_url = start_url
        family_pages = 0
        while next_url and family_pages < max(1, int(max_pages)) and len(selected) < needed:
            rows, following = hardened._api_page(next_url, token=token)
            if not isinstance(rows, list) or not rows:
                break
            family_pages += 1
            pages_fetched += 1
            page_head = _text(rows[0].get("ghsa_id") if isinstance(rows[0], Mapping) else "")
            marker = f"{start_url}|{page_head}"
            if page_head and marker in seen_page_heads:
                rejected["repeated_page_guard"] += len(rows)
                break
            if page_head:
                seen_page_heads.add(marker)

            for raw in rows:
                if not isinstance(raw, Mapping):
                    continue
                if raw.get("withdrawn_at"):
                    rejected["withdrawn"] += 1
                    continue
                match = candidate_family_match(raw, family)
                if not match.get("matched"):
                    rejected[_text(match.get("reason")) or "family_mismatch"] += 1
                    continue

                candidate = _candidate_from_raw(raw, family=family, match=match)
                root = _text(candidate.get("source_root")).upper()
                project = _project(candidate.get("source_project"))
                if not root or not project:
                    rejected["missing_root_or_project"] += 1
                    continue
                reasons = corpus.exposure_reasons(candidate, exposed)
                if reasons:
                    for reason in reasons:
                        rejected[reason] += 1
                    continue
                if root in used_roots:
                    rejected["duplicate_or_existing_root"] += 1
                    continue
                if project in used_projects:
                    rejected["duplicate_or_existing_project"] += 1
                    continue

                used_roots.add(root)
                used_projects.add(project)
                selected.append(candidate)
                if len(selected) >= needed:
                    break
            next_url = following

    return {
        "family": family,
        "selected": selected,
        "selected_count": len(selected),
        "rejected_counts": dict(sorted(rejected.items())),
        "pages_fetched": pages_fetched,
        "discovery_mode": "cwe" if cwes else "semantic",
        "canonical_cwes": cwes,
        "semantic_terms": list(family_terms(family)),
        "seed_selected_count": int(seed_result["selected_count"]),
    }


def semantic_sweep_for_families(
    families: Mapping[str, int],
    *,
    exposed: Mapping[str, set[str]],
    token: str,
    max_pages: int,
    used_roots: set[str],
    used_projects: set[str],
) -> dict[str, Any]:
    """Scan the general reviewed-advisory feed once for unresolved families."""

    remaining = {
        _text(family): max(0, int(needed))
        for family, needed in families.items()
        if _text(family) and int(needed) > 0
    }
    selected: list[dict[str, Any]] = []
    selected_counts: Counter[str] = Counter()
    rejected: Counter[str] = Counter()
    pages_fetched = 0
    next_url = _general_query()
    seen_page_heads: set[str] = set()

    while next_url and pages_fetched < max(1, int(max_pages)) and remaining:
        rows, following = hardened._api_page(next_url, token=token)
        if not isinstance(rows, list) or not rows:
            break
        pages_fetched += 1
        page_head = _text(rows[0].get("ghsa_id") if isinstance(rows[0], Mapping) else "")
        if page_head and page_head in seen_page_heads:
            rejected["repeated_page_guard"] += len(rows)
            break
        if page_head:
            seen_page_heads.add(page_head)

        for raw in rows:
            if not isinstance(raw, Mapping):
                continue
            if raw.get("withdrawn_at"):
                rejected["withdrawn"] += 1
                continue

            matching: list[tuple[str, dict[str, Any]]] = []
            for family in sorted(remaining):
                match = candidate_family_match(raw, family)
                if match.get("matched"):
                    matching.append((family, dict(match)))
            if len(matching) != 1:
                if len(matching) > 1:
                    rejected["multi_family_semantic_match"] += 1
                continue

            family, match = matching[0]
            candidate = _candidate_from_raw(raw, family=family, match=match)
            root = _text(candidate.get("source_root")).upper()
            project = _project(candidate.get("source_project"))
            if not root or not project:
                rejected["missing_root_or_project"] += 1
                continue
            reasons = corpus.exposure_reasons(candidate, exposed)
            if reasons:
                for reason in reasons:
                    rejected[reason] += 1
                continue
            if root in used_roots:
                rejected["duplicate_or_existing_root"] += 1
                continue
            if project in used_projects:
                rejected["duplicate_or_existing_project"] += 1
                continue

            used_roots.add(root)
            used_projects.add(project)
            selected.append(candidate)
            selected_counts[family] += 1
            remaining[family] -= 1
            if remaining[family] <= 0:
                remaining.pop(family, None)

        next_url = following

    return {
        "selected": selected,
        "selected_counts": dict(sorted(selected_counts.items())),
        "remaining": dict(sorted(remaining.items())),
        "pages_fetched": pages_fetched,
        "rejected_counts": dict(sorted(rejected.items())),
    }


def expand_coverage(
    feasibility: Mapping[str, Any],
    *,
    token: str,
    quota: int = DEFAULT_FAMILY_QUOTA,
    max_pages_per_family: int = DEFAULT_MAX_PAGES_PER_FAMILY,
) -> dict[str, Any]:
    """Find fresh public-source candidates until every family reaches quota."""

    quota = max(1, int(quota))
    inventory_before = coverage_inventory(feasibility, quota=quota)
    exposed, historical_reports = _configure_firewall()

    current_rows = _source_rows(feasibility)
    current_identity = hardened.strict_identities_from_records(current_rows)
    for key in exposed:
        exposed[key].update(current_identity.get(key, set()))

    used_roots = set(current_identity["roots"])
    used_projects = set(current_identity["projects"])
    selected: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {}

    deficits = {
        str(row["family"]): int(row["deficit"])
        for row in inventory_before["families"]
        if int(row["deficit"]) > 0
    }

    # Hardest families first: semantic-only, then low-CWE-cardinality families.
    cwe_map = canonical_family_cwes()
    order = sorted(
        deficits,
        key=lambda family: (
            0 if not cwe_map.get(family) else 1,
            len(cwe_map.get(family, ())),
            family,
        ),
    )
    for family in order:
        result = discover_for_family(
            family,
            exposed=exposed,
            token=token,
            needed=deficits[family],
            max_pages=max_pages_per_family,
            used_roots=used_roots,
            used_projects=used_projects,
        )
        diagnostics[family] = {
            key: value
            for key, value in result.items()
            if key != "selected"
        }
        selected.extend(result["selected"])

    selected_per_family = Counter(
        _text(row.get("family_target"))
        for row in selected
        if _text(row.get("family_target"))
    )
    semantic_deficits = {
        family: max(0, deficits[family] - int(selected_per_family.get(family, 0)))
        for family in deficits
        if max(0, deficits[family] - int(selected_per_family.get(family, 0))) > 0
    }
    semantic_sweep = semantic_sweep_for_families(
        semantic_deficits,
        exposed=exposed,
        token=token,
        max_pages=max(20, int(max_pages_per_family) * 4),
        used_roots=used_roots,
        used_projects=used_projects,
    )
    selected.extend(semantic_sweep["selected"])

    expanded_feasibility = {
        "sources": [*current_rows, *selected],
    }
    inventory_after = coverage_inventory(expanded_feasibility, quota=quota)

    return {
        "version": COVERAGE_EXPANDER_VERSION,
        "rule_version": COVERAGE_EXPANDER_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_all_family_coverage_expansion",
        "quota": quota,
        "canonical_family_count": len(FAMILY_ORDER),
        "selected_candidate_count": len(selected),
        "represented_family_count_before": int(inventory_before["represented_family_count"]),
        "represented_family_count_after": int(inventory_after["represented_family_count"]),
        "missing_family_count_after": int(inventory_after["missing_family_count"]),
        "missing_families_after": list(inventory_after["missing_families"]),
        "all_families_represented": bool(inventory_after["all_families_represented"]),
        "inventory_before": inventory_before,
        "inventory_after": inventory_after,
        "selected": selected,
        "family_diagnostics": diagnostics,
        "semantic_sweep": {
            key: value
            for key, value in semantic_sweep.items()
            if key != "selected"
        },
        "historical_exposure": historical_reports,
        "safety": {
            "reviewed_public_metadata_only": True,
            "historical_exposure_firewall_enforced": True,
            "reserved_blind_firewall_preserved": True,
            "taxonomy_is_discovery_only": True,
            "semantic_matches_are_discovery_only": True,
            "no_labels_created": True,
            "no_analysis_scoring": True,
            "no_target_contact": True,
            "no_payload_generation": True,
        },
    }


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Expand Real-World Corpus V1 coverage across all canonical families"
    )
    parser.add_argument(
        "--feasibility",
        default="benchmarks/real_world/v1/source_feasibility_final.json",
    )
    parser.add_argument(
        "--output",
        default="benchmarks/real_world/v1/coverage_expansion_candidates.json",
    )
    parser.add_argument("--quota", type=int, default=DEFAULT_FAMILY_QUOTA)
    parser.add_argument(
        "--max-pages-per-family",
        type=int,
        default=DEFAULT_MAX_PAGES_PER_FAMILY,
    )
    parser.add_argument("--github-token", default="")
    args = parser.parse_args(argv)

    feasibility = json.loads(Path(args.feasibility).read_text(encoding="utf-8"))
    if not isinstance(feasibility, Mapping):
        raise ValueError("feasibility_must_be_json_object")
    result = expand_coverage(
        feasibility,
        token=args.github_token or os.environ.get("GITHUB_TOKEN", ""),
        quota=args.quota,
        max_pages_per_family=args.max_pages_per_family,
    )
    _write(Path(args.output), result)
    print(json.dumps({
        "ok": result["all_families_represented"],
        "represented_family_count": result["represented_family_count_after"],
        "missing_family_count": result["missing_family_count_after"],
        "selected_candidate_count": result["selected_candidate_count"],
    }, sort_keys=True))
    return 0 if result["all_families_represented"] else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "COVERAGE_EXPANDER_VERSION",
    "COVERAGE_EXPANDER_RULE_VERSION",
    "DEFAULT_FAMILY_QUOTA",
    "RECOMMENDED_FAMILY_QUOTA",
    "coverage_inventory",
    "candidate_family_match",
    "discover_reviewed_seeds",
    "discover_for_family",
    "semantic_sweep_for_families",
    "expand_coverage",
]
