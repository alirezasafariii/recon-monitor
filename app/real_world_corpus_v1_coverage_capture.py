from __future__ import annotations

"""Supplemental capture pipeline for Corpus V1 all-family coverage expansion.

The frozen 100-source Corpus V1 artifacts keep their historical fixed-count
gates. This module captures *supplemental* family-coverage candidates without
weakening those gates or rewriting the frozen corpus.

Only public GitHub advisory/repository metadata is read. No vulnerability target
is contacted, no payload is executed, no Analysis score is produced, and no
human verification flag is created.
"""

import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from real_world_corpus_v1_family_match import resolve_source_family
from real_world_corpus_v1_feasibility import _api_get_json, assess_source
from real_world_corpus_v1_public_capture import capture_source
from real_world_corpus_v1_revision_capture import capture_revision_pair

COVERAGE_CAPTURE_VERSION = "1.0.0"
COVERAGE_CAPTURE_RULE_VERSION = "2026.09.18.1"
_GHSA_RE = re.compile(r"^GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}$")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _candidate_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in ("selected", "candidates", "sources"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return [dict(row) for row in rows if isinstance(row, Mapping)]
    return []


def _family_status(
    assessed: Mapping[str, Any],
    source_pack: Mapping[str, Any] | None,
    revision_pair: Mapping[str, Any] | None,
) -> dict[str, Any]:
    advisory = (
        source_pack.get("advisory_snapshot")
        if isinstance(source_pack, Mapping)
        else {}
    )
    advisory = advisory if isinstance(advisory, Mapping) else {}
    resolution = resolve_source_family(assessed, advisory)
    if revision_pair is not None and resolution.get("resolved"):
        level = "exact_revision_boundary"
    elif source_pack is not None and _text(assessed.get("capture_feasibility")) == "version_boundary_available" and resolution.get("resolved"):
        level = "version_boundary"
    elif source_pack is not None and resolution.get("resolved"):
        level = "public_source_boundary"
    elif source_pack is not None:
        level = "captured_unresolved_family"
    else:
        level = "candidate_only"
    return {
        "family": _text(resolution.get("family"))
        or _text((assessed.get("source_taxonomy_match") or {}).get("family_target"))
        or _text(assessed.get("family_target")),
        "family_resolved": bool(resolution.get("resolved")),
        "family_resolution_basis": _text(resolution.get("basis")),
        "family_resolution_reasons": list(resolution.get("reasons", []) or []),
        "coverage_level": level,
    }


def capture_coverage_candidates(
    candidates: Iterable[Mapping[str, Any]],
    *,
    token: str = "",
) -> dict[str, Any]:
    rows = [dict(row) for row in candidates]
    assessed_rows: list[dict[str, Any]] = []
    source_packs: list[dict[str, Any]] = []
    revision_pairs: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    seen_roots: set[str] = set()
    seen_projects: set[str] = set()

    for raw in rows:
        root = _text(raw.get("source_root")).upper()
        project = _text(raw.get("source_project")).lower()
        family_target = _text(raw.get("family_target"))

        if not _GHSA_RE.match(root):
            failures.append({
                "source_root": root,
                "family_target": family_target,
                "stage": "candidate",
                "error": "invalid_ghsa_source_root",
            })
            continue
        if not project:
            failures.append({
                "source_root": root,
                "family_target": family_target,
                "stage": "candidate",
                "error": "missing_source_project",
            })
            continue
        if root in seen_roots:
            failures.append({
                "source_root": root,
                "family_target": family_target,
                "stage": "candidate",
                "error": "duplicate_source_root",
            })
            continue
        if project in seen_projects:
            failures.append({
                "source_root": root,
                "family_target": family_target,
                "stage": "candidate",
                "error": "duplicate_source_project",
            })
            continue
        seen_roots.add(root)
        seen_projects.add(project)

        try:
            advisory = _api_get_json(
                f"https://api.github.com/advisories/{root}",
                token=token,
            )
            if not isinstance(advisory, Mapping):
                raise ValueError("unexpected_advisory_payload")
            assessed = assess_source(raw, advisory)
            assessed_rows.append(assessed)
        except Exception as exc:
            failures.append({
                "source_root": root,
                "family_target": family_target,
                "stage": "feasibility",
                "error": type(exc).__name__,
            })
            continue

        try:
            pack = capture_source(assessed, token=token)
            source_packs.append(pack)
        except Exception as exc:
            failures.append({
                "source_root": root,
                "family_target": family_target,
                "stage": "public_source_capture",
                "error": type(exc).__name__,
            })
            cases.append({
                "source_root": root,
                "source_project": project,
                "family_target": family_target,
                **_family_status(assessed, None, None),
            })
            continue

        pair: dict[str, Any] | None = None
        if (
            _text(pack.get("candidate_fix_commit_sha"))
            and _text(pack.get("candidate_vulnerable_parent_sha"))
        ):
            try:
                pair = capture_revision_pair(pack, token=token)
                if not bool(pair.get("revision_pair_complete")):
                    raise ValueError("revision_pair_incomplete")
                revision_pairs.append(pair)
            except Exception as exc:
                failures.append({
                    "source_root": root,
                    "family_target": family_target,
                    "stage": "revision_pair_capture",
                    "error": type(exc).__name__,
                })
                pair = None

        cases.append({
            "source_root": root,
            "source_project": project,
            "family_target": family_target,
            "capture_feasibility": _text(assessed.get("capture_feasibility")),
            "candidate_fix_commit_sha": _text(pack.get("candidate_fix_commit_sha")) or None,
            "candidate_vulnerable_parent_sha": _text(pack.get("candidate_vulnerable_parent_sha")) or None,
            "revision_pair_sha256": (
                _text(pair.get("revision_pair_sha256")) if pair is not None else None
            ),
            **_family_status(assessed, pack, pair),
        })

    family_levels: dict[str, Counter[str]] = {}
    for case in cases:
        family = _text(case.get("family")) or _text(case.get("family_target"))
        if not family:
            continue
        family_levels.setdefault(family, Counter())
        family_levels[family][_text(case.get("coverage_level")) or "unknown"] += 1

    level_counts: Counter[str] = Counter(
        _text(case.get("coverage_level")) or "unknown"
        for case in cases
    )
    resolved_families = sorted({
        _text(case.get("family"))
        for case in cases
        if case.get("family_resolved") and _text(case.get("family"))
    })
    exact_families = sorted({
        _text(case.get("family"))
        for case in cases
        if case.get("coverage_level") == "exact_revision_boundary"
        and _text(case.get("family"))
    })

    return {
        "version": COVERAGE_CAPTURE_VERSION,
        "rule_version": COVERAGE_CAPTURE_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_supplemental_family_coverage_capture",
        "candidate_count": len(rows),
        "assessed_count": len(assessed_rows),
        "public_source_pack_count": len(source_packs),
        "revision_pair_count": len(revision_pairs),
        "case_count": len(cases),
        "failure_count": len(failures),
        "failures": failures,
        "coverage_level_counts": dict(sorted(level_counts.items())),
        "resolved_family_count": len(resolved_families),
        "resolved_families": resolved_families,
        "exact_revision_family_count": len(exact_families),
        "exact_revision_families": exact_families,
        "family_coverage_levels": {
            family: dict(sorted(counts.items()))
            for family, counts in sorted(family_levels.items())
        },
        "cases": cases,
        "feasibility": {
            "sources": assessed_rows,
        },
        "public_source_evidence": {
            "source_packs": source_packs,
        },
        "revision_pair_evidence": {
            "revision_pairs": revision_pairs,
        },
        "safety": {
            "frozen_v1_artifacts_not_rewritten": True,
            "public_metadata_only": True,
            "no_target_contact": True,
            "no_payload_generation": True,
            "no_analysis_scoring": True,
            "no_human_labels_created": True,
            "source_taxonomy_is_not_target_evidence": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture supplemental Corpus V1 all-family coverage candidates"
    )
    parser.add_argument(
        "--candidates",
        default="benchmarks/real_world/v1/coverage_expansion_candidates.json",
    )
    parser.add_argument(
        "--output",
        default="benchmarks/real_world/v1/coverage_expansion_capture.json",
    )
    parser.add_argument("--github-token", default="")
    args = parser.parse_args(argv)

    payload = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("coverage_candidate_payload_must_be_object")
    result = capture_coverage_candidates(
        _candidate_rows(payload),
        token=args.github_token or os.environ.get("GITHUB_TOKEN", ""),
    )
    Path(args.output).write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "candidates": result["candidate_count"],
        "resolved_families": result["resolved_family_count"],
        "exact_revision_families": result["exact_revision_family_count"],
        "revision_pairs": result["revision_pair_count"],
        "failures": result["failure_count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "COVERAGE_CAPTURE_VERSION",
    "COVERAGE_CAPTURE_RULE_VERSION",
    "capture_coverage_candidates",
]
