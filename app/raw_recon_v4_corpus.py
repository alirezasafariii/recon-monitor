from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterable, Mapping

from family_detectors.registry import DETECTOR_SPECS
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from raw_recon_v4_source_discovery import _canonical_url, _grounding_writeup_urls, _prior_exposure_index

RAW_V4_CORPUS_VALIDATOR_VERSION = "1.1.0"
RAW_V4_CORPUS_VALIDATOR_RULE_VERSION = "2026.08.12.6.26"
V4_EXACT_SOURCE_ROOTS = 36
V4_EXACT_SOURCE_PROJECTS = 36
V4_EXACT_POSITIVE_FAMILIES = 36
V4_VARIANTS = ("positive", "near_miss", "secure_negative", "sparse_noisy")
V4_ALLOWED_SOURCE_KINDS = frozenset({
    "github_reviewed_advisory",
    "project_security_advisory",
    "vendor_advisory",
    "primary_security_advisory",
})
V4_VALID_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "UNKNOWN"})

# v3 intentionally rejected every key that happened to share a name with any
# detector surface/condition. That becomes incorrect in v4 because new families
# consume real normalized artifacts whose natural field names include things like
# source-map documents, dependency inventories and WebSocket endpoints. v4 bans
# only engine control-plane labels plus the case's expected condition itself.
V4_FORBIDDEN_RAW_KEYS = frozenset({
    "family_scope",
    "evidence_namespace",
    "extractor_id",
    "extractor_version",
    "detector_signal_class",
    "detector_counts_as_target_evidence",
    "execution_family",
    "execution_strategy",
    "execution_basis",
    "admitted",
    "bug_family",
    "vulnerability_family",
    "condition_signals",
    "target_signal",
    "target_signals",
    "rule_ids",
    "cwe",
    "wstg",
    "owasp",
    "writeup",
    "evidence_for",
    "evidence_against",
})


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            keys.add(_norm(key))
            keys.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_walk_keys(child))
    return keys


def _details(case: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = case.get("raw") if isinstance(case.get("raw"), Mapping) else {}
    return raw.get("details") if isinstance(raw.get("details"), Mapping) else {}


def _variant_groups(rows: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        result[_norm(row.get("source_root"))].append(dict(row))
    return result


def validate_v4_corpus(
    cases: Iterable[Mapping[str, Any]],
    *,
    shortlist: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate Analysis 6.26 corpus integrity without detector scoring."""
    rows = [dict(row) for row in cases]
    errors: list[str] = []
    prior = _prior_exposure_index()
    grounding = _grounding_writeup_urls()
    groups = _variant_groups(rows)

    projects = {_norm(row.get("source_project")) for row in rows if _norm(row.get("source_project"))}
    positive_families = {
        _norm(row.get("family"))
        for row in rows
        if _norm(row.get("case_kind")) == "positive" and _norm(row.get("family"))
    }
    roots = {root for root in groups if root}

    prior_roots: set[str] = set()
    prior_projects: set[str] = set()
    prior_urls: set[str] = set()
    grounding_urls: set[str] = set()
    bad_variant_roots: set[str] = set()
    collision_roots: set[str] = set()
    missing_observable_delta: set[str] = set()
    label_leakage_cases: dict[str, list[str]] = {}

    prior_projects_lower = {value.lower() for value in prior["projects"]}
    seen_ids: set[str] = set()

    for row in rows:
        cid = _norm(row.get("id"))
        family = _norm(row.get("family"))
        kind = _norm(row.get("case_kind"))
        root = _norm(row.get("source_root"))
        project = _norm(row.get("source_project"))
        source_date = _norm(row.get("source_date"))
        split = _norm(row.get("split"))
        provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
        source_kind = _norm(provenance.get("source_kind"))
        raw = row.get("raw") if isinstance(row.get("raw"), Mapping) else {}
        expected = row.get("expected") if isinstance(row.get("expected"), Mapping) else {}
        url = _canonical_url(_norm(provenance.get("url")))

        if not cid:
            errors.append("v4 case missing id")
        elif cid in seen_ids:
            errors.append(f"duplicate v4 case id: {cid}")
        else:
            seen_ids.add(cid)

        if family not in FAMILY_ADMISSION_POLICIES or family not in DETECTOR_SPECS:
            errors.append(f"{cid}: unknown or unsealed family {family!r}")
        if kind not in V4_VARIANTS:
            errors.append(f"{cid}: invalid case_kind {kind!r}")
        if split != "postfreeze_holdout":
            errors.append(f"{cid}: split must be postfreeze_holdout")
        if not root:
            errors.append(f"{cid}: missing source_root")
        if not project:
            errors.append(f"{cid}: missing source_project")
        if not source_date:
            errors.append(f"{cid}: missing source_date")
        if source_kind not in V4_ALLOWED_SOURCE_KINDS:
            errors.append(f"{cid}: unsupported v4 source_kind {source_kind!r}")
        if not url.startswith("https://"):
            errors.append(f"{cid}: provenance URL must be HTTPS")
        if provenance.get("primary_source") is not True:
            errors.append(f"{cid}: provenance.primary_source must be true")

        if _norm(expected.get("family")) != family:
            errors.append(f"{cid}: expected.family must equal family")
        expected_admitted = bool(expected.get("admitted"))
        if kind == "positive" and not expected_admitted:
            errors.append(f"{cid}: positive case must expect admission")
        if kind != "positive" and expected_admitted:
            errors.append(f"{cid}: non-positive case must expect abstention for target family")

        expected_conditions = expected.get("condition_signals") or []
        if not isinstance(expected_conditions, list):
            errors.append(f"{cid}: expected.condition_signals must be a list")
            expected_conditions = []
        elif family in DETECTOR_SPECS:
            allowed = set(DETECTOR_SPECS[family].condition_signals)
            unknown = sorted({_norm(value) for value in expected_conditions if _norm(value)} - allowed)
            if unknown:
                errors.append(f"{cid}: expected condition signals are not canonical for {family}: {unknown}")

        if not raw:
            errors.append(f"{cid}: missing raw artifact")
        else:
            target = _norm(raw.get("target"))
            endpoint = _norm(raw.get("endpoint"))
            method = _norm(raw.get("method")).upper()
            if not target:
                errors.append(f"{cid}: raw.target missing")
            if not endpoint:
                errors.append(f"{cid}: raw.endpoint missing")
            if method not in V4_VALID_METHODS:
                errors.append(f"{cid}: invalid raw.method {method!r}")
            if not isinstance(raw.get("endpoint_schema", {}), Mapping):
                errors.append(f"{cid}: raw.endpoint_schema must be an object")
            if not isinstance(raw.get("details", {}), Mapping):
                errors.append(f"{cid}: raw.details must be an object")

            raw_keys = _walk_keys(raw)
            leaked = sorted(raw_keys & V4_FORBIDDEN_RAW_KEYS)
            direct_expected_leaks = sorted(raw_keys & {_norm(value) for value in expected_conditions if _norm(value)})
            leakage = sorted(set(leaked) | set(direct_expected_leaks))
            if leakage:
                label_leakage_cases[cid] = leakage
                errors.append(f"{cid}: engine control/expected labels leaked into raw artifact: {leakage}")

        if root in prior["roots"]:
            prior_roots.add(root)
        if project and (project in prior["projects"] or project.lower() in prior_projects_lower):
            prior_projects.add(project)
        if url and url in prior["urls"]:
            prior_urls.add(url)
        if url and url in grounding:
            grounding_urls.add(url)

    for root, group in sorted(groups.items()):
        kinds = [_norm(row.get("case_kind")) for row in group]
        if len(group) != 4 or set(kinds) != set(V4_VARIANTS) or len(kinds) != len(set(kinds)):
            bad_variant_roots.add(root)
            continue
        projects_for_root = {_norm(row.get("source_project")) for row in group}
        families_for_root = {_norm(row.get("family")) for row in group}
        urls_for_root = {
            _canonical_url(_norm((row.get("provenance") or {}).get("url")))
            for row in group
            if isinstance(row.get("provenance"), Mapping)
        }
        if len(projects_for_root) != 1:
            errors.append(f"{root}: source root spans multiple projects {sorted(projects_for_root)}")
        if len(families_for_root) != 1:
            errors.append(f"{root}: source root spans multiple families {sorted(families_for_root)}")
        if len(urls_for_root) != 1:
            errors.append(f"{root}: source root must have one canonical provenance URL")

        by_kind = {_norm(row.get("case_kind")): row for row in group}
        positive = by_kind["positive"]
        positive_raw = positive.get("raw") if isinstance(positive.get("raw"), Mapping) else {}
        positive_details = _details(positive)
        if not positive_details:
            missing_observable_delta.add(root)
        for control_kind in ("near_miss", "secure_negative"):
            control = by_kind[control_kind]
            control_raw = control.get("raw") if isinstance(control.get("raw"), Mapping) else {}
            if _canonical(positive_raw) == _canonical(control_raw):
                collision_roots.add(root)
            if _canonical(positive_details) == _canonical(_details(control)):
                missing_observable_delta.add(root)

    if len(rows) != V4_EXACT_SOURCE_ROOTS * len(V4_VARIANTS):
        errors.append(f"v4 case count must be exactly 144: {len(rows)}")
    if len(roots) != V4_EXACT_SOURCE_ROOTS:
        errors.append(f"v4 source roots must be exactly {V4_EXACT_SOURCE_ROOTS}: {len(roots)}")
    if len(projects) != V4_EXACT_SOURCE_PROJECTS:
        errors.append(f"v4 source projects must be exactly {V4_EXACT_SOURCE_PROJECTS}: {len(projects)}")
    if len(positive_families) != V4_EXACT_POSITIVE_FAMILIES:
        errors.append(f"v4 positive families must be exactly {V4_EXACT_POSITIVE_FAMILIES}: {len(positive_families)}")
    if bad_variant_roots:
        errors.append(f"v4 roots must have exactly four unique variants: {sorted(bad_variant_roots)}")
    if prior_roots:
        errors.append(f"v4 prior source_root overlap detected: {sorted(prior_roots)}")
    if prior_projects:
        errors.append(f"v4 prior source_project overlap detected: {sorted(prior_projects)}")
    if prior_urls:
        errors.append(f"v4 prior provenance URL overlap detected: {sorted(prior_urls)}")
    if grounding_urls:
        errors.append(f"v4 detector-grounding URL overlap detected: {sorted(grounding_urls)}")
    if collision_roots:
        errors.append(f"v4 positive/control raw collision detected: {sorted(collision_roots)}")
    if missing_observable_delta:
        errors.append(
            "v4 positive variants must contain a distinct target-observable raw.details delta: "
            + repr(sorted(missing_observable_delta))
        )

    shortlist_roots: set[str] = set()
    shortlist_projects: set[str] = set()
    shortlist_families: set[str] = set()
    if shortlist is not None:
        selected = shortlist.get("selected") if isinstance(shortlist.get("selected"), list) else []
        shortlist_roots = {_norm(row.get("source_root")) for row in selected if isinstance(row, Mapping) and _norm(row.get("source_root"))}
        shortlist_projects = {_norm(row.get("source_project")) for row in selected if isinstance(row, Mapping) and _norm(row.get("source_project"))}
        shortlist_families = {_norm(row.get("family")) for row in selected if isinstance(row, Mapping) and _norm(row.get("family"))}
        if roots != shortlist_roots:
            errors.append(f"v4 corpus roots do not exactly match audited shortlist: missing={sorted(shortlist_roots-roots)} extra={sorted(roots-shortlist_roots)}")
        if {p.lower() for p in projects} != {p.lower() for p in shortlist_projects}:
            errors.append("v4 corpus projects do not exactly match audited shortlist")
        if positive_families != shortlist_families:
            errors.append(f"v4 corpus families do not exactly match audited shortlist: missing={sorted(shortlist_families-positive_families)} extra={sorted(positive_families-shortlist_families)}")

    observable_count = max(0, len(roots) - len(missing_observable_delta))
    return {
        "validator_version": RAW_V4_CORPUS_VALIDATOR_VERSION,
        "validator_rule_version": RAW_V4_CORPUS_VALIDATOR_RULE_VERSION,
        "passed": not errors,
        "errors": errors,
        "case_count": len(rows),
        "source_root_count": len(roots),
        "source_project_count": len(projects),
        "positive_family_count": len(positive_families),
        "prior_source_root_overlap_count": len(prior_roots),
        "prior_source_project_overlap_count": len(prior_projects),
        "prior_url_overlap_count": len(prior_urls),
        "grounding_writeup_overlap_count": len(grounding_urls),
        "bad_variant_root_count": len(bad_variant_roots),
        "positive_control_raw_collision_count": len(collision_roots),
        "positive_observable_delta_count": observable_count,
        "positive_observable_delta_rate": round(observable_count / len(roots), 6) if roots else 0.0,
        "label_leakage_count": len(label_leakage_cases),
        "label_leakage_cases": label_leakage_cases,
        "audited_shortlist_root_count": len(shortlist_roots),
        "audited_shortlist_project_count": len(shortlist_projects),
        "audited_shortlist_family_count": len(shortlist_families),
        "scoring_executed": False,
    }


__all__ = [
    "RAW_V4_CORPUS_VALIDATOR_VERSION",
    "RAW_V4_CORPUS_VALIDATOR_RULE_VERSION",
    "V4_EXACT_SOURCE_ROOTS",
    "V4_EXACT_SOURCE_PROJECTS",
    "V4_EXACT_POSITIVE_FAMILIES",
    "V4_VARIANTS",
    "V4_ALLOWED_SOURCE_KINDS",
    "V4_FORBIDDEN_RAW_KEYS",
    "validate_v4_corpus",
]
