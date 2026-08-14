from __future__ import annotations

"""Build a deterministic pre-adjudication shortlist for Real-World Corpus V1.

The shortlist is a source-selection artifact only. ``family_target`` expresses
why a source was discovered; it is never promoted to ``final_family`` without a
separate source/human adjudication step. No Analysis scoring or target contact
is performed here.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

SHORTLIST_VERSION = "1.0.0"
SHORTLIST_RULE_VERSION = "2026.08.14.4"
TARGET_ROOTS = 100
MIN_FAMILY_TARGETS = 50


def _text(value: Any) -> str:
    return str(value or "").strip()


def _project(value: Any) -> str:
    text = _text(value).lower().strip("/")
    if text.startswith("https://github.com/"):
        text = text[len("https://github.com/"):]
    if text.endswith(".git"):
        text = text[:-4]
    return "/".join(text.split("/")[:2]) if "/" in text else text


def _stable_key(row: Mapping[str, Any]) -> tuple[str, str, str]:
    family = _text(row.get("family_target"))
    root = _text(row.get("source_root")).upper()
    project = _project(row.get("source_project"))
    return family, root, project


def _candidate_identity(row: Mapping[str, Any]) -> tuple[str, str]:
    return _text(row.get("source_root")).upper(), _project(row.get("source_project"))


def _prepare(row: Mapping[str, Any], *, source_pool: str) -> dict[str, Any]:
    prepared = dict(row)
    prepared["source_pool"] = source_pool
    prepared["selection_status"] = "pre_adjudication_shortlist"
    prepared["source_feasibility_status"] = "pending_review"
    prepared["family_label_adjudicated"] = False
    prepared["final_family"] = None
    prepared["capture_status"] = "not_started"
    prepared["human_verified"] = False
    prepared["scoring_executed"] = False
    prepared["target_contact_performed"] = False
    return prepared


def validate_shortlist(rows: Iterable[Mapping[str, Any]], *, target_roots: int = TARGET_ROOTS, min_family_targets: int = MIN_FAMILY_TARGETS) -> dict[str, Any]:
    items = [dict(row) for row in rows]
    roots = [_candidate_identity(row)[0] for row in items]
    projects = [_candidate_identity(row)[1] for row in items]
    families = {_text(row.get("family_target")) for row in items if _text(row.get("family_target"))}
    errors: list[str] = []
    if len(items) != int(target_roots):
        errors.append(f"shortlist_size:{len(items)}!=target:{target_roots}")
    if any(not root for root in roots):
        errors.append("missing_source_root")
    if any(not project for project in projects):
        errors.append("missing_source_project")
    if len(set(roots)) != len(roots):
        errors.append("duplicate_source_root")
    if len(set(projects)) != len(projects):
        errors.append("duplicate_source_project")
    if len(families) < int(min_family_targets):
        errors.append(f"family_target_coverage:{len(families)}<minimum:{min_family_targets}")
    if any(bool(row.get("human_verified")) for row in items):
        errors.append("pre_adjudication_shortlist_must_not_be_human_verified")
    if any(bool(row.get("scoring_executed")) for row in items):
        errors.append("pre_adjudication_shortlist_must_not_be_scored")
    if any(row.get("final_family") not in (None, "") for row in items):
        errors.append("pre_adjudication_shortlist_must_not_set_final_family")
    return {
        "passed": not errors,
        "errors": errors,
        "source_count": len(items),
        "unique_source_root_count": len(set(roots)),
        "unique_source_project_count": len(set(projects)),
        "family_target_count": len(families),
        "family_targets": sorted(families),
    }


def build_shortlist(
    targeted_rows: Iterable[Mapping[str, Any]],
    general_rows: Iterable[Mapping[str, Any]],
    *,
    target_roots: int = TARGET_ROOTS,
    min_family_targets: int = MIN_FAMILY_TARGETS,
) -> dict[str, Any]:
    targeted = sorted((dict(row) for row in targeted_rows), key=_stable_key)
    general = sorted((dict(row) for row in general_rows), key=_stable_key)

    selected: list[dict[str, Any]] = []
    used_roots: set[str] = set()
    used_projects: set[str] = set()
    targeted_family_seen: set[str] = set()

    # One targeted source per distinct family first. The targeted discovery
    # already tries to make roots/projects unique, but shortlist enforces this
    # independently rather than trusting upstream state.
    for row in targeted:
        family = _text(row.get("family_target"))
        root, project = _candidate_identity(row)
        if not family or not root or not project:
            continue
        if family in targeted_family_seen or root in used_roots or project in used_projects:
            continue
        selected.append(_prepare(row, source_pool="family_targeted"))
        targeted_family_seen.add(family)
        used_roots.add(root)
        used_projects.add(project)
        if len(selected) >= int(target_roots):
            break

    if len(targeted_family_seen) < int(min_family_targets):
        raise ValueError(f"insufficient_distinct_family_targets:{len(targeted_family_seen)}")

    # Fill the remaining source budget from the broad fresh pool. Root and
    # project uniqueness are preserved across both pools.
    for row in general:
        if len(selected) >= int(target_roots):
            break
        root, project = _candidate_identity(row)
        if not root or not project or root in used_roots or project in used_projects:
            continue
        selected.append(_prepare(row, source_pool="general_fresh"))
        used_roots.add(root)
        used_projects.add(project)

    validation = validate_shortlist(selected, target_roots=target_roots, min_family_targets=min_family_targets)
    if not validation["passed"]:
        raise ValueError("shortlist_validation_failed:" + ",".join(validation["errors"]))

    canonical = json.dumps(selected, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "version": SHORTLIST_VERSION,
        "rule_version": SHORTLIST_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_pre_adjudication_source_shortlist",
        "status": "pre_adjudication_shortlist_complete",
        "scoring_executed": False,
        "target_contact_performed": False,
        "human_labels_created": False,
        "family_assignment_is_final": False,
        "target_source_roots": int(target_roots),
        "minimum_family_targets": int(min_family_targets),
        "selected_family_targeted_count": sum(1 for row in selected if row.get("source_pool") == "family_targeted"),
        "selected_general_fresh_count": sum(1 for row in selected if row.get("source_pool") == "general_fresh"),
        "shortlist_sha256": hashlib.sha256(canonical).hexdigest(),
        "validation": validation,
        "sources": selected,
        "next_transition": "source_feasibility_and_family_adjudication",
    }


def _load_candidates(path: Path, key: str) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"missing_candidate_list:{key}:{path}")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the Real-World Corpus V1 pre-adjudication shortlist")
    parser.add_argument("--targeted", default="benchmarks/real_world/v1/targeted_candidates.json")
    parser.add_argument("--general", default="benchmarks/real_world/v1/source_candidates.json")
    parser.add_argument("--output", default="benchmarks/real_world/v1/source_shortlist.json")
    parser.add_argument("--report", default="benchmarks/real_world/v1/shortlist_report.json")
    args = parser.parse_args(argv)

    targeted = _load_candidates(Path(args.targeted), "selected")
    general = _load_candidates(Path(args.general), "candidates")
    result = build_shortlist(targeted, general)
    _write(Path(args.output), result)
    report = {key: value for key, value in result.items() if key != "sources"}
    _write(Path(args.report), report)
    print(json.dumps({
        "ok": True,
        "sources": result["validation"]["source_count"],
        "projects": result["validation"]["unique_source_project_count"],
        "family_targets": result["validation"]["family_target_count"],
        "targeted": result["selected_family_targeted_count"],
        "general": result["selected_general_fresh_count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
