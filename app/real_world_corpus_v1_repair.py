from __future__ import annotations

"""Replace weak Real-World Corpus V1 sources with fresh stronger alternatives.

The pre-repair shortlist remains immutable evidence of selection history. This
stage emits a separate final shortlist. Replacement candidates must pass the
same historical exposure firewall, must not reuse any root/project already in
the 100-source set, and must provide at least a version boundary or stronger
revision boundary.

Only public GitHub advisory/source metadata is read. No target is contacted,
no vulnerable application is executed, no label is created, and no Analysis
score is consumed.
"""

import argparse
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

import real_world_corpus_v1 as corpus
import real_world_corpus_v1_discovery as hardened
import real_world_corpus_v1_feasibility as feasibility
import real_world_corpus_v1_shortlist as shortlist
import real_world_corpus_v1_targeted as targeted

REPAIR_VERSION = "1.0.0"
REPAIR_RULE_VERSION = "2026.08.14.7"
ACCEPTABLE_FEASIBILITY = frozenset({"strong_revision_boundary", "version_boundary_available"})
WEAK_FEASIBILITY = frozenset({"source_reference_available", "manual_source_research_required"})


def _text(value: Any) -> str:
    return str(value or "").strip()


def _identity(row: Mapping[str, Any]) -> tuple[str, str]:
    return _text(row.get("source_root")).upper(), corpus._project(row.get("source_project"))


def configure_firewall() -> None:
    corpus.identities_from_records = hardened.strict_identities_from_records
    corpus.normalize_advisory = hardened.normalize_advisory_with_project_fallback
    existing_names = {item[0] for item in corpus.HISTORICAL_CORPORA}
    corpus.HISTORICAL_CORPORA = corpus.HISTORICAL_CORPORA + tuple(
        item for item in hardened.EXTRA_CONSUMED_CORPORA if item[0] not in existing_names
    )


def _assess_candidate(candidate: Mapping[str, Any], *, token: str) -> dict[str, Any] | None:
    root = _text(candidate.get("source_root")).upper()
    if not root:
        return None
    advisory = feasibility._api_get_json(f"https://api.github.com/advisories/{root}", token=token)
    if not isinstance(advisory, Mapping):
        return None
    assessed = feasibility.assess_source(candidate, advisory)
    return assessed if assessed.get("capture_feasibility") in ACCEPTABLE_FEASIBILITY else None


def _current_exposure(rows: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    return hardened.strict_identities_from_records(list(rows))


def _combined_exposure(*parts: Mapping[str, set[str]]) -> dict[str, set[str]]:
    result = {"roots": set(), "projects": set(), "urls": set(), "identifiers": set()}
    for part in parts:
        for key in result:
            result[key].update(part.get(key, set()))
    return result


def find_targeted_replacement(
    weak: Mapping[str, Any],
    *,
    exposed: Mapping[str, set[str]],
    token: str,
    max_pages_per_cwe: int = 8,
) -> dict[str, Any] | None:
    family = _text(weak.get("family_target"))
    cwe = _text(weak.get("target_cwe")).upper()
    if not family or not cwe:
        return None
    next_url = targeted._query_url(cwe)
    pages = 0
    seen_heads: set[str] = set()
    while next_url and pages < max(1, int(max_pages_per_cwe)):
        rows, following = hardened._api_page(next_url, token=token)
        if not isinstance(rows, list) or not rows:
            break
        pages += 1
        head = _text(rows[0].get("ghsa_id")) if isinstance(rows[0], Mapping) else ""
        if head and head in seen_heads:
            break
        if head:
            seen_heads.add(head)
        for raw in rows:
            if not isinstance(raw, Mapping) or raw.get("withdrawn_at"):
                continue
            candidate = hardened.normalize_advisory_with_project_fallback(raw)
            if corpus.exposure_reasons(candidate, exposed):
                continue
            candidate.update({
                "family_target": family,
                "target_cwe": cwe,
                "targeting_basis": "replacement_canonical_cwe_query_only_not_final_family_label",
                "family_label_adjudicated": False,
                "final_family": None,
                "source_feasibility_status": "replacement_candidate",
                "human_verified": False,
                "scoring_executed": False,
                "target_contact_performed": False,
            })
            assessed = _assess_candidate(candidate, token=token)
            if assessed is not None and assessed.get("source_taxonomy_match", {}).get("status") == "exact_target_cwe_match":
                return assessed
        next_url = following
    return None


def find_general_replacement(
    general_candidates: Iterable[Mapping[str, Any]],
    *,
    exposed: Mapping[str, set[str]],
    token: str,
) -> dict[str, Any] | None:
    for raw in sorted((dict(row) for row in general_candidates), key=lambda row: _identity(row)):
        candidate = dict(raw)
        if corpus.exposure_reasons(candidate, exposed):
            continue
        candidate.update({
            "family_target": None,
            "target_cwe": None,
            "family_label_adjudicated": False,
            "final_family": None,
            "source_feasibility_status": "replacement_candidate",
            "human_verified": False,
            "scoring_executed": False,
            "target_contact_performed": False,
        })
        assessed = _assess_candidate(candidate, token=token)
        if assessed is not None:
            return assessed
    return None


def repair_sources(
    assessed_sources: Iterable[Mapping[str, Any]],
    general_candidates: Iterable[Mapping[str, Any]],
    *,
    token: str,
) -> dict[str, Any]:
    configure_firewall()
    sources = [dict(row) for row in assessed_sources]
    historical, historical_reports = corpus.load_historical_exposure()
    missing = [item["name"] for item in historical_reports if not item.get("loaded")]
    if missing:
        raise RuntimeError("historical_exposure_incomplete:" + ",".join(missing))

    weak_sources = [row for row in sources if _text(row.get("capture_feasibility")) in WEAK_FEASIBILITY]
    repairs: list[dict[str, Any]] = []
    current_rows = list(sources)

    for weak in sorted(weak_sources, key=_identity):
        old_root, old_project = _identity(weak)
        current_identity = _current_exposure(current_rows)
        # Include the weak source itself so it cannot be selected again.
        exposed = _combined_exposure(historical, current_identity)
        replacement = (
            find_targeted_replacement(weak, exposed=exposed, token=token)
            if _text(weak.get("family_target")) and _text(weak.get("target_cwe"))
            else find_general_replacement(general_candidates, exposed=exposed, token=token)
        )
        if replacement is None:
            raise RuntimeError(f"no_strong_fresh_replacement:{old_root}:{old_project}")

        new_root, new_project = _identity(replacement)
        index = next(i for i, row in enumerate(current_rows) if _identity(row) == (old_root, old_project))
        prepared = shortlist._prepare(replacement, source_pool=("family_targeted_replacement" if _text(weak.get("family_target")) else "general_fresh_replacement"))
        # Retain feasibility details already proven for the replacement.
        for key in (
            "advisory_fetch_status",
            "advisory_cwes",
            "source_taxonomy_match",
            "version_boundaries",
            "reference_inventory",
            "capture_feasibility",
            "variant_feasibility",
        ):
            if key in replacement:
                prepared[key] = replacement[key]
        prepared["replacement_for_source_root"] = old_root
        prepared["replacement_for_source_project"] = old_project
        prepared["replacement_reason"] = _text(weak.get("capture_feasibility"))
        current_rows[index] = prepared
        repairs.append({
            "old_source_root": old_root,
            "old_source_project": old_project,
            "old_feasibility": _text(weak.get("capture_feasibility")),
            "family_target": _text(weak.get("family_target")) or None,
            "target_cwe": _text(weak.get("target_cwe")) or None,
            "new_source_root": new_root,
            "new_source_project": new_project,
            "new_feasibility": _text(replacement.get("capture_feasibility")),
        })

    validation = shortlist.validate_shortlist(current_rows, target_roots=100, min_family_targets=50)
    remaining_weak = [
        _identity(row)[0]
        for row in current_rows
        if _text(row.get("capture_feasibility")) not in ACCEPTABLE_FEASIBILITY
    ]
    gates = {
        "shortlist_validation_passed": bool(validation["passed"]),
        "all_weak_sources_replaced": not remaining_weak,
        "repair_count_matches_initial_weak_count": len(repairs) == len(weak_sources),
        "no_human_labels_created": all(not bool(row.get("human_verified")) for row in current_rows),
        "no_scoring_executed": all(not bool(row.get("scoring_executed")) for row in current_rows),
        "no_target_contact_performed": all(not bool(row.get("target_contact_performed")) for row in current_rows),
    }
    if not all(gates.values()):
        raise RuntimeError("source_repair_gate_failed")

    return {
        "version": REPAIR_VERSION,
        "rule_version": REPAIR_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_source_repair",
        "status": "source_repair_complete",
        "initial_weak_source_count": len(weak_sources),
        "repair_count": len(repairs),
        "remaining_weak_source_count": len(remaining_weak),
        "remaining_weak_source_roots": remaining_weak,
        "repairs": repairs,
        "validation": validation,
        "gates": gates,
        "historical_exposure": historical_reports,
        "scoring_executed": False,
        "target_contact_performed": False,
        "human_labels_created": False,
        "sources": sorted(current_rows, key=_identity),
        "next_transition": "reassess_final_source_feasibility",
    }


def _read_rows(path: Path, key: str) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"missing_list:{key}:{path}")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Repair weak Real-World Corpus V1 sources")
    parser.add_argument("--feasibility", default="benchmarks/real_world/v1/source_feasibility.json")
    parser.add_argument("--general", default="benchmarks/real_world/v1/source_candidates.json")
    parser.add_argument("--output", default="benchmarks/real_world/v1/source_shortlist_final.json")
    parser.add_argument("--report", default="benchmarks/real_world/v1/source_repair_report.json")
    parser.add_argument("--github-token", default="")
    args = parser.parse_args(argv)

    result = repair_sources(
        _read_rows(Path(args.feasibility), "sources"),
        _read_rows(Path(args.general), "candidates"),
        token=args.github_token or os.environ.get("GITHUB_TOKEN", ""),
    )
    _write(Path(args.output), result)
    report = {key: value for key, value in result.items() if key != "sources"}
    _write(Path(args.report), report)
    print(json.dumps({
        "ok": True,
        "initial_weak": result["initial_weak_source_count"],
        "repaired": result["repair_count"],
        "remaining_weak": result["remaining_weak_source_count"],
        "family_targets": result["validation"]["family_target_count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
