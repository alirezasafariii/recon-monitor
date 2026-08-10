from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from analysis_postfreeze import DEFAULT_MANIFEST, PRIOR_CORPUS, ROOT, _norm, load_jsonl, load_manifest
from analysis_standards import standards_for_family
from hypothesis_admission import FAMILY_ADMISSION_POLICIES

SOURCE_REGISTRY_VALIDATOR_VERSION = "1.1.0"
DEFAULT_SOURCE_REGISTRY = ROOT / "benchmarks" / "golden" / "sources" / "v4_roots.jsonl"


def load_source_registry(path: str | Path = DEFAULT_SOURCE_REGISTRY) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        row = json.loads(text)
        if not isinstance(row, dict):
            raise ValueError(f"source registry line {line_no} is not an object")
        rows.append(row)
    return rows


def _provenance(row: Mapping[str, Any]) -> Mapping[str, Any]:
    return row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}


def _identity_sets(rows: list[dict[str, Any]]) -> tuple[set[str], set[str], set[str]]:
    roots: set[str] = set()
    urls: set[str] = set()
    refs: set[str] = set()
    for row in rows:
        root = _norm(row.get("source_root")).lower()
        provenance = _provenance(row)
        url = _norm(provenance.get("url")).lower().rstrip("/")
        ref = _norm(provenance.get("reference")).lower()
        if root:
            roots.add(root)
        if url:
            urls.add(url)
        if ref:
            refs.add(ref)
    return roots, urls, refs


def _canonical_standard_ids(family: str) -> tuple[set[str], set[str]]:
    canonical = standards_for_family(family)
    wstg = {str(item.get("id")) for item in canonical.get("wstg", []) if item.get("id")}
    cwe = {str(item.get("id")) for item in canonical.get("cwe", []) if item.get("id")}
    return wstg, cwe


def _validate_policy_adjudication(
    root: str,
    family: str,
    adjudication: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    policy = FAMILY_ADMISSION_POLICIES.get(family)
    if not policy:
        return errors

    surface = {
        _norm(value)
        for value in adjudication.get("surface", [])
        if _norm(value)
    } if isinstance(adjudication.get("surface"), list) else set()
    decisive = {
        _norm(value)
        for value in adjudication.get("decisive", [])
        if _norm(value)
    } if isinstance(adjudication.get("decisive"), list) else set()
    observed = surface | decisive
    secure_control = _norm(adjudication.get("secure_control"))

    if not surface:
        errors.append(f"{root}: adjudication surface is empty")
    if not decisive:
        errors.append(f"{root}: adjudication decisive evidence is empty")
    if not secure_control:
        errors.append(f"{root}: adjudication secure_control is empty")

    required = policy.get("required") if isinstance(policy.get("required"), list) else []
    missing_groups: list[list[str]] = []
    for group in required:
        normalized_group = {_norm(value) for value in group if _norm(value)}
        if normalized_group and not (observed & normalized_group):
            missing_groups.append(sorted(normalized_group))
    if missing_groups:
        errors.append(
            f"{root}: adjudication does not satisfy frozen {family} required groups: {missing_groups}"
        )

    # A real-positive root must carry condition-level evidence, not only attack-surface clues.
    if required:
        condition_group = {_norm(value) for value in required[-1] if _norm(value)}
        if condition_group and not (decisive & condition_group):
            errors.append(
                f"{root}: decisive evidence does not intersect the frozen {family} condition group"
            )

    blockers = {
        _norm(value)
        for value in policy.get("blocking_contradictions", set())
        if _norm(value)
    }
    if secure_control and secure_control not in blockers:
        errors.append(
            f"{root}: secure_control {secure_control!r} is not a frozen {family} blocking contradiction"
        )

    return errors


def validate_source_registry(
    registry_path: str | Path = DEFAULT_SOURCE_REGISTRY,
    manifest_path: str | Path = DEFAULT_MANIFEST,
    prior_corpus_path: str | Path = PRIOR_CORPUS,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    rows = load_source_registry(registry_path)
    prior_rows = load_jsonl(prior_corpus_path)
    prior_roots, prior_urls, prior_refs = _identity_sets(prior_rows)

    source_policy = manifest.get("source_policy") if isinstance(manifest.get("source_policy"), Mapping) else {}
    allowed_kinds = {_norm(value) for value in source_policy.get("allowed_source_kinds", []) if _norm(value)}
    target_cfg = manifest.get("collection_target") if isinstance(manifest.get("collection_target"), Mapping) else {}
    target_roots = int(target_cfg.get("new_source_roots") or 0)

    errors: list[str] = []
    warnings: list[str] = []
    roots_seen: set[str] = set()
    urls_seen: set[str] = set()
    refs_seen: set[str] = set()
    projects: set[str] = set()
    family_counts: dict[str, int] = {}

    for row in rows:
        root = _norm(row.get("source_root"))
        family = _norm(row.get("family"))
        project = _norm(row.get("source_project"))
        source_date = _norm(row.get("source_date"))
        provenance = _provenance(row)
        source_kind = _norm(provenance.get("source_kind"))
        url = _norm(provenance.get("url"))
        ref = _norm(provenance.get("reference"))
        review_status = _norm(row.get("review_status"))
        adjudication = row.get("adjudication") if isinstance(row.get("adjudication"), Mapping) else {}

        root_key = root.lower()
        url_key = url.lower().rstrip("/")
        ref_key = ref.lower()

        if not root:
            errors.append("source registry row missing source_root")
        elif root_key in roots_seen:
            errors.append(f"duplicate source_root in v4 registry: {root}")
        roots_seen.add(root_key)

        if root_key in prior_roots:
            errors.append(f"{root}: source_root already exists in analysis_golden_v3")
        if not family or family not in FAMILY_ADMISSION_POLICIES:
            errors.append(f"{root}: unknown or missing family {family!r}")
        else:
            family_counts[family] = family_counts.get(family, 0) + 1
            errors.extend(_validate_policy_adjudication(root, family, adjudication))

        if not project:
            errors.append(f"{root}: missing source_project")
        else:
            projects.add(project)
        if not source_date:
            errors.append(f"{root}: missing source_date")
        if source_kind not in allowed_kinds:
            errors.append(f"{root}: source_kind {source_kind!r} is not allowed")
        if not url.startswith("https://"):
            errors.append(f"{root}: primary-source URL must use HTTPS")
        if not ref:
            errors.append(f"{root}: missing advisory reference")

        if url_key:
            if url_key in urls_seen:
                errors.append(f"{root}: primary-source URL is reused by another v4 root")
            urls_seen.add(url_key)
            if url_key in prior_urls:
                errors.append(f"{root}: primary-source URL already exists in analysis_golden_v3")
        if ref_key:
            if ref_key in refs_seen:
                errors.append(f"{root}: advisory reference is reused by another v4 root")
            refs_seen.add(ref_key)
            if ref_key in prior_refs:
                errors.append(f"{root}: advisory reference already exists in analysis_golden_v3")

        if review_status != "primary_source_verified":
            errors.append(f"{root}: review_status must be primary_source_verified")
        if row.get("v3_overlap") is not False:
            errors.append(f"{root}: v3_overlap must be explicitly false after verification")

        standards = row.get("standards") if isinstance(row.get("standards"), Mapping) else {}
        row_wstg = {_norm(value) for value in standards.get("wstg", []) if _norm(value)}
        row_cwe = {_norm(value) for value in standards.get("cwe", []) if _norm(value)}
        if family in FAMILY_ADMISSION_POLICIES:
            canonical_wstg, canonical_cwe = _canonical_standard_ids(family)
            if not row_wstg or not row_wstg.issubset(canonical_wstg):
                errors.append(f"{root}: WSTG grounding missing or inconsistent with frozen family registry")
            if not row_cwe or not row_cwe.issubset(canonical_cwe):
                errors.append(f"{root}: CWE grounding missing or inconsistent with frozen family registry")

    count = len(rows)
    if target_roots and count > target_roots:
        errors.append(f"source registry contains {count} roots, above preregistered target {target_roots}")
    if target_roots and count < target_roots:
        warnings.append(f"collection incomplete: {count}/{target_roots} source roots verified")

    return {
        "source_registry_validator_version": SOURCE_REGISTRY_VALIDATOR_VERSION,
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
        "verified_source_roots": count,
        "target_source_roots": target_roots,
        "remaining_source_roots": max(0, target_roots - count),
        "source_projects": len(projects),
        "family_counts": dict(sorted(family_counts.items())),
        "collection_complete": bool(target_roots) and count == target_roots and not errors,
    }


def main() -> int:
    try:
        result = validate_source_registry()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"passed": False, "errors": [str(exc)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
