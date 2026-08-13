from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterable, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_v4_corpus import V4_FORBIDDEN_RAW_KEYS, V4_VALID_METHODS
from raw_recon_v5_source_discovery import exposure_index
import raw_recon_v4_source_discovery as v4

VERSION = "1.1.0"
RULE_VERSION = "2026.08.13.6.29"
SINGLE_VARIANTS = ("positive", "near_miss", "secure_negative", "sparse_noisy")
MULTI_VARIANTS = ("dual_positive", "a_only", "b_only", "dual_secure")


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


def _validate_raw_observation(
    raw: Mapping[str, Any],
    *,
    cid: str,
    expected_conditions: set[str],
    errors: list[str],
    leakage: dict[str, list[str]],
) -> None:
    target = _norm(raw.get("target"))
    endpoint = _norm(raw.get("endpoint"))
    method = _norm(raw.get("method")).upper()
    if not target:
        errors.append(f"{cid}: raw target missing")
    if not endpoint:
        errors.append(f"{cid}: raw endpoint missing")
    if method not in V4_VALID_METHODS:
        errors.append(f"{cid}: invalid raw method {method!r}")
    if not isinstance(raw.get("endpoint_schema", {}), Mapping):
        errors.append(f"{cid}: endpoint_schema must be an object")
    if not isinstance(raw.get("details", {}), Mapping):
        errors.append(f"{cid}: details must be an object")
    keys = _walk_keys(raw)
    leaked = sorted((keys & set(V4_FORBIDDEN_RAW_KEYS)) | (keys & expected_conditions))
    if leaked:
        leakage[cid] = leaked
        errors.append(f"{cid}: engine control/expected labels leaked into raw observation: {leaked}")


def validate_v5_corpus(
    cases: Iterable[Mapping[str, Any]],
    *,
    shortlist: Mapping[str, Any],
) -> dict[str, Any]:
    rows = [dict(row) for row in cases]
    singles = [row for row in rows if _norm(row.get("case_mode")) == "single_family_fresh"]
    multi = [row for row in rows if _norm(row.get("case_mode")) == "multi_family_hard_case"]
    errors: list[str] = []
    seen_ids: set[str] = set()
    leakage: dict[str, list[str]] = {}

    selected = shortlist.get("selected") if isinstance(shortlist.get("selected"), list) else []
    selected_rows = [dict(row) for row in selected if isinstance(row, Mapping)]
    selected_roots = {_norm(row.get("source_root")) for row in selected_rows if _norm(row.get("source_root"))}
    selected_projects = {_norm(row.get("source_project")) for row in selected_rows if _norm(row.get("source_project"))}
    selected_families = {_norm(row.get("family")) for row in selected_rows if _norm(row.get("family"))}
    selected_urls = {
        v4._canonical_url(_norm(row.get("canonical_advisory_url")))
        for row in selected_rows
        if v4._canonical_url(_norm(row.get("canonical_advisory_url")))
    }
    selected_reference_urls = {
        v4._canonical_url(_norm(value))
        for row in selected_rows
        for value in row.get("references") or []
        if v4._canonical_url(_norm(value))
    }

    if len(selected_rows) != 36 or len(selected_roots) != 36 or len(selected_projects) != 36:
        errors.append("v5 shortlist must contain exactly 36 unique roots and projects")
    if selected_families != set(DETECTOR_SPECS):
        errors.append(
            f"v5 shortlist family coverage mismatch missing={sorted(set(DETECTOR_SPECS)-selected_families)} "
            f"extra={sorted(selected_families-set(DETECTOR_SPECS))}"
        )

    prior = exposure_index()
    grounding = v4._grounding_writeup_urls()
    prior_roots = sorted(selected_roots & prior["roots"])
    prior_projects = sorted(selected_projects & prior["projects"])
    prior_urls = sorted(selected_urls & prior["urls"])
    grounding_urls = sorted(selected_urls & grounding)
    grounding_reference_urls = sorted(selected_reference_urls & grounding)
    if prior_roots:
        errors.append(f"v5 prior source-root overlap: {prior_roots}")
    if prior_projects:
        errors.append(f"v5 prior source-project overlap: {prior_projects}")
    if prior_urls:
        errors.append(f"v5 prior provenance URL overlap: {prior_urls}")
    if grounding_urls:
        errors.append(f"v5 grounding-writeup URL overlap: {grounding_urls}")
    if grounding_reference_urls:
        errors.append(f"v5 source references overlap detector-grounding writeups: {grounding_reference_urls}")

    single_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    multi_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        cid = _norm(row.get("id"))
        if not cid:
            errors.append("v5 case missing id")
        elif cid in seen_ids:
            errors.append(f"duplicate v5 case id: {cid}")
        else:
            seen_ids.add(cid)

        mode = _norm(row.get("case_mode"))
        expected = row.get("expected") if isinstance(row.get("expected"), Mapping) else {}
        expected_families = {
            _norm(value) for value in expected.get("admitted_families") or [] if _norm(value)
        }
        condition_map = expected.get("condition_signals") if isinstance(expected.get("condition_signals"), Mapping) else {}
        expected_conditions: set[str] = set()
        for family, values in condition_map.items():
            fam = _norm(family)
            if fam not in DETECTOR_SPECS:
                errors.append(f"{cid}: expected condition family is unknown: {fam}")
                continue
            allowed = set(DETECTOR_SPECS[fam].condition_signals)
            supplied = {_norm(value) for value in values or [] if _norm(value)}
            unknown = sorted(supplied - allowed)
            if unknown:
                errors.append(f"{cid}: non-canonical expected conditions for {fam}: {unknown}")
            expected_conditions.update(supplied)
        unknown_expected_families = sorted(expected_families - set(DETECTOR_SPECS))
        if unknown_expected_families:
            errors.append(f"{cid}: unknown expected admitted families {unknown_expected_families}")

        if mode == "single_family_fresh":
            family = _norm(row.get("family"))
            kind = _norm(row.get("case_kind"))
            root = _norm(row.get("source_root"))
            project = _norm(row.get("source_project"))
            if family not in DETECTOR_SPECS:
                errors.append(f"{cid}: unknown single family {family}")
            if kind not in SINGLE_VARIANTS:
                errors.append(f"{cid}: invalid single variant {kind}")
            if root not in selected_roots or project not in selected_projects:
                errors.append(f"{cid}: single source does not belong to frozen shortlist")
            wanted = {family} if kind == "positive" else set()
            if expected_families != wanted:
                errors.append(f"{cid}: single expected admission set mismatch wanted={sorted(wanted)} actual={sorted(expected_families)}")
            raw = row.get("raw") if isinstance(row.get("raw"), Mapping) else {}
            if not raw:
                errors.append(f"{cid}: single case missing raw observation")
            else:
                _validate_raw_observation(raw, cid=cid, expected_conditions=expected_conditions, errors=errors, leakage=leakage)
            single_groups[root].append(row)
        elif mode == "multi_family_hard_case":
            kind = _norm(row.get("case_kind"))
            paired = [_norm(value) for value in row.get("paired_families") or [] if _norm(value)]
            if kind not in MULTI_VARIANTS:
                errors.append(f"{cid}: invalid multi variant {kind}")
            if len(paired) != 2 or len(set(paired)) != 2 or any(f not in DETECTOR_SPECS for f in paired):
                errors.append(f"{cid}: multi case must name two distinct sealed families")
            observations = row.get("raw_observations") if isinstance(row.get("raw_observations"), list) else []
            if len(observations) != 2 or not all(isinstance(value, Mapping) for value in observations):
                errors.append(f"{cid}: multi case must contain exactly two raw observations")
            else:
                targets = {_norm(value.get("target")) for value in observations if isinstance(value, Mapping)}
                if len(targets) != 1 or not next(iter(targets), ""):
                    errors.append(f"{cid}: multi observations must share one non-empty target")
                for index, raw in enumerate(observations):
                    _validate_raw_observation(raw, cid=f"{cid}#obs{index+1}", expected_conditions=expected_conditions, errors=errors, leakage=leakage)
            wanted_by_kind = {
                "dual_positive": set(paired),
                "a_only": {paired[0]} if len(paired) == 2 else set(),
                "b_only": {paired[1]} if len(paired) == 2 else set(),
                "dual_secure": set(),
            }
            if kind in wanted_by_kind and expected_families != wanted_by_kind[kind]:
                errors.append(f"{cid}: multi expected admission set mismatch wanted={sorted(wanted_by_kind[kind])} actual={sorted(expected_families)}")
            group_key = "+".join(paired)
            multi_groups[group_key].append(row)
        else:
            errors.append(f"{cid}: invalid v5 case_mode {mode!r}")

    collision_roots: set[str] = set()
    missing_delta_roots: set[str] = set()
    positive_families: set[str] = set()
    for root, group in single_groups.items():
        kinds = [_norm(row.get("case_kind")) for row in group]
        if len(group) != 4 or set(kinds) != set(SINGLE_VARIANTS) or len(kinds) != len(set(kinds)):
            errors.append(f"{root}: single source must have exactly four unique variants")
            continue
        by_kind = {_norm(row.get("case_kind")): row for row in group}
        positive = by_kind["positive"]
        positive_families.add(_norm(positive.get("family")))
        positive_raw = positive.get("raw") if isinstance(positive.get("raw"), Mapping) else {}
        positive_details = positive_raw.get("details") if isinstance(positive_raw.get("details"), Mapping) else {}
        for control_kind in ("near_miss", "secure_negative"):
            control_raw = by_kind[control_kind].get("raw") if isinstance(by_kind[control_kind].get("raw"), Mapping) else {}
            if _canonical(positive_raw) == _canonical(control_raw):
                collision_roots.add(root)
            control_details = control_raw.get("details") if isinstance(control_raw.get("details"), Mapping) else {}
            if _canonical(positive_details) == _canonical(control_details):
                missing_delta_roots.add(root)

    if collision_roots:
        errors.append(f"v5 single positive/control raw collisions: {sorted(collision_roots)}")
    if missing_delta_roots:
        errors.append(f"v5 single positive/control observable delta missing: {sorted(missing_delta_roots)}")

    pair_family_memberships: list[str] = []
    multi_collision_groups: set[str] = set()
    for pair, group in multi_groups.items():
        kinds = [_norm(row.get("case_kind")) for row in group]
        if len(group) != 4 or set(kinds) != set(MULTI_VARIANTS) or len(kinds) != len(set(kinds)):
            errors.append(f"{pair}: multi pair must have exactly four unique variants")
            continue
        by_kind = {_norm(row.get("case_kind")): row for row in group}
        paired = [_norm(value) for value in by_kind["dual_positive"].get("paired_families") or [] if _norm(value)]
        pair_family_memberships.extend(paired)
        canonical_variants = {
            kind: _canonical(by_kind[kind].get("raw_observations") or []) for kind in MULTI_VARIANTS
        }
        if len(set(canonical_variants.values())) != 4:
            multi_collision_groups.add(pair)
    if multi_collision_groups:
        errors.append(f"v5 multi variants collide at raw-observation level: {sorted(multi_collision_groups)}")
    if sorted(pair_family_memberships) != sorted(DETECTOR_SPECS):
        errors.append("v5 dual-positive pairing must cover every family exactly once")

    if len(rows) != 216:
        errors.append(f"v5 total case count must be exactly 216: {len(rows)}")
    if len(singles) != 144:
        errors.append(f"v5 single case count must be exactly 144: {len(singles)}")
    if len(multi) != 72:
        errors.append(f"v5 multi case count must be exactly 72: {len(multi)}")
    if len(single_groups) != 36:
        errors.append(f"v5 single source-root count must be exactly 36: {len(single_groups)}")
    if positive_families != set(DETECTOR_SPECS):
        errors.append("v5 single positive family coverage must be exactly all 36 families")
    if len(multi_groups) != 18:
        errors.append(f"v5 multi pair count must be exactly 18: {len(multi_groups)}")

    observable_roots = max(0, len(single_groups) - len(missing_delta_roots))
    return {
        "validator_version": VERSION,
        "validator_rule_version": RULE_VERSION,
        "passed": not errors,
        "errors": errors,
        "case_count": len(rows),
        "single_case_count": len(singles),
        "multi_case_count": len(multi),
        "single_source_root_count": len(single_groups),
        "shortlist_source_root_count": len(selected_roots),
        "shortlist_source_project_count": len(selected_projects),
        "positive_family_count": len(positive_families),
        "multi_pair_count": len(multi_groups),
        "prior_source_root_overlap_count": len(prior_roots),
        "prior_source_project_overlap_count": len(prior_projects),
        "prior_url_overlap_count": len(prior_urls),
        "grounding_writeup_overlap_count": len(grounding_urls),
        "grounding_reference_overlap_count": len(grounding_reference_urls),
        "label_leakage_count": len(leakage),
        "label_leakage_cases": leakage,
        "single_positive_control_collision_count": len(collision_roots),
        "single_positive_observable_delta_rate": round(observable_roots / len(single_groups), 6) if single_groups else 0.0,
        "multi_raw_collision_count": len(multi_collision_groups),
        "scoring_executed": False,
    }