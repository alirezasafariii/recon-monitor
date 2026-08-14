from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Iterable, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_v4_corpus import V4_FORBIDDEN_RAW_KEYS, V4_VALID_METHODS
from raw_recon_v6_source_firewall import validate_shortlist

VERSION = "1.1.0"
RULE_VERSION = "2026.08.14.6.31.1"
SINGLE_VARIANTS = {"positive", "near_miss", "secure_negative", "sparse_noisy"}
PAIR_VARIANTS = {"dual_positive", "a_only", "b_only", "dual_secure"}
TRIAD_VARIANTS = {"triple_positive", "ab_only", "c_only", "triple_secure", "sparse_interference"}
SUSPICIOUS_ID_KEYS = {"trace_id", "fixture_id", "label", "family", "expected_family", "expected_families"}


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _identity(value: Any) -> str:
    return _norm(value).casefold()


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


def _walk_scalars(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], str]]:
    out: list[tuple[tuple[str, ...], str]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            out.extend(_walk_scalars(child, path + (_norm(key),)))
    elif isinstance(value, list):
        for pos, child in enumerate(value):
            out.extend(_walk_scalars(child, path + (str(pos),)))
    elif isinstance(value, (str, int, float, bool)):
        out.append((path, _norm(value)))
    return out


def _marker_in_text(marker: str, text: str) -> bool:
    marker = _identity(marker)
    text = _identity(text)
    if not marker or not text:
        return False
    return re.search(rf"(?<![a-z0-9]){re.escape(marker)}(?![a-z0-9])", text) is not None


def _validate_observation(
    raw: Mapping[str, Any],
    cid: str,
    expected_conditions: set[str],
    errors: list[str],
    leakage: dict[str, list[str]],
) -> None:
    if not _norm(raw.get("target")):
        errors.append(f"{cid}: target missing")
    if not _norm(raw.get("endpoint")):
        errors.append(f"{cid}: endpoint missing")
    if _norm(raw.get("method")).upper() not in V4_VALID_METHODS:
        errors.append(f"{cid}: invalid method")
    if not isinstance(raw.get("endpoint_schema", {}), Mapping):
        errors.append(f"{cid}: endpoint_schema must be an object")
    if not isinstance(raw.get("details", {}), Mapping):
        errors.append(f"{cid}: details must be an object")

    leak_hits: set[str] = set()
    keys = {_identity(value) for value in _walk_keys(raw)}
    forbidden_keys = {_identity(value) for value in V4_FORBIDDEN_RAW_KEYS}
    leak_hits.update(f"key:{value}" for value in sorted(keys & forbidden_keys))

    machine_markers = set(DETECTOR_SPECS)
    for spec in DETECTOR_SPECS.values():
        machine_markers.update(str(value) for value in spec.condition_signals)
    machine_markers.update(expected_conditions)

    for path, scalar in _walk_scalars(raw):
        leaf = _identity(path[-1]) if path else ""
        for marker in machine_markers:
            if _marker_in_text(marker, scalar):
                leak_hits.add(f"value:{'.'.join(path)}:{marker}")
        if leaf in SUSPICIOUS_ID_KEYS:
            for family in DETECTOR_SPECS:
                prefix = family[:8]
                if prefix and prefix in _identity(scalar):
                    leak_hits.add(f"derived-id:{'.'.join(path)}:{prefix}")

    if leak_hits:
        leakage[cid] = sorted(leak_hits)
        errors.append(f"{cid}: benchmark labels leaked into raw observation")


def _expected_source(by_family: Mapping[str, Mapping[str, Any]], group: list[str]) -> tuple[str, str]:
    roots = [str(by_family[family]["source_root"]) for family in group]
    projects = [str(by_family[family]["source_project"]) for family in group]
    return "+".join(roots), "+".join(projects)


def validate_v6_corpus(
    cases: Iterable[Mapping[str, Any]],
    shortlist: Mapping[str, Any],
    *,
    require_literal_single_capture: bool = True,
) -> dict[str, Any]:
    rows = [dict(row) for row in cases]
    selected = [dict(row) for row in shortlist.get("selected") or [] if isinstance(row, Mapping)]
    firewall = validate_shortlist(selected, required_count=36)
    errors = list(firewall.get("errors") or [])
    leakage: dict[str, list[str]] = {}
    seen: set[str] = set()
    singles: dict[str, list[dict[str, Any]]] = defaultdict(list)
    pairs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    triads: dict[str, list[dict[str, Any]]] = defaultdict(list)
    literal_single_count = 0

    selected_families = {_norm(row.get("family")) for row in selected}
    if selected_families != set(DETECTOR_SPECS):
        errors.append("v6 shortlist family coverage mismatch")
    by_family = {_norm(row.get("family")): row for row in selected}

    for row in rows:
        cid = _norm(row.get("id"))
        if not cid or cid in seen:
            errors.append(f"duplicate or missing case id: {cid!r}")
        seen.add(cid)

        expected = row.get("expected") if isinstance(row.get("expected"), Mapping) else {}
        expected_families = {_norm(value) for value in expected.get("admitted_families") or [] if _norm(value)}
        top_level_expected = {_norm(value) for value in row.get("expected_families") or [] if _norm(value)}
        if top_level_expected != expected_families:
            errors.append(f"{cid}: top-level expected_families contradict expected.admitted_families")

        condition_map = expected.get("condition_signals") if isinstance(expected.get("condition_signals"), Mapping) else {}
        condition_families = {_norm(value) for value in condition_map}
        if condition_families != expected_families:
            errors.append(f"{cid}: expected condition families contradict admitted families")
        expected_conditions: set[str] = set()
        for family, values in condition_map.items():
            family = _norm(family)
            if family not in DETECTOR_SPECS:
                errors.append(f"{cid}: unknown expected family {family}")
                continue
            supplied = {_norm(value) for value in values or [] if _norm(value)}
            if supplied - set(DETECTOR_SPECS[family].condition_signals):
                errors.append(f"{cid}: non-canonical expected condition")
            expected_conditions.update(supplied)

        mode = _norm(row.get("case_mode"))
        kind = _norm(row.get("case_kind"))
        if mode == "single_family_fresh_v6":
            family = _norm(row.get("family"))
            if family not in by_family:
                errors.append(f"{cid}: single family absent from shortlist")
                continue
            if kind not in SINGLE_VARIANTS:
                errors.append(f"{cid}: invalid single variant")
            wanted = {family} if kind == "positive" else set()
            if expected_families != wanted:
                errors.append(f"{cid}: single expected-set mismatch")

            source = by_family[family]
            if _identity(row.get("source_root")) != _identity(source.get("source_root")):
                errors.append(f"{cid}: source_root does not match shortlist family source")
            if _identity(row.get("source_project")) != _identity(source.get("source_project")):
                errors.append(f"{cid}: source_project does not match shortlist family source")

            provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
            if provenance.get("literal_capture") is True:
                literal_single_count += 1
            elif require_literal_single_capture:
                errors.append(f"{cid}: fresh single case is not a literal capture")

            raw = row.get("raw") if isinstance(row.get("raw"), Mapping) else {}
            _validate_observation(raw, cid, expected_conditions, errors, leakage)
            singles[_identity(row.get("source_root"))].append(row)

        elif mode == "2_family_interference_v6":
            group = [_norm(value) for value in row.get("paired_families") or [] if _norm(value)]
            if kind not in PAIR_VARIANTS or len(group) != 2 or len(set(group)) != 2 or any(family not in by_family for family in group):
                errors.append(f"{cid}: invalid pair contract")
            else:
                expected_root, expected_project = _expected_source(by_family, group)
                if _identity(row.get("source_root")) != _identity(expected_root):
                    errors.append(f"{cid}: pair source_root does not match shortlist sources")
                if _identity(row.get("source_project")) != _identity(expected_project):
                    errors.append(f"{cid}: pair source_project does not match shortlist sources")
            observations = [value for value in row.get("raw_observations") or [] if isinstance(value, Mapping)]
            if len(observations) != 2:
                errors.append(f"{cid}: pair must have two observations")
            for pos, raw in enumerate(observations):
                _validate_observation(raw, f"{cid}#obs{pos+1}", expected_conditions, errors, leakage)
            wanted = {
                "dual_positive": set(group),
                "a_only": {group[0]} if len(group) == 2 else set(),
                "b_only": {group[1]} if len(group) == 2 else set(),
                "dual_secure": set(),
            }
            if kind in wanted and expected_families != wanted[kind]:
                errors.append(f"{cid}: pair expected-set mismatch")
            pairs["+".join(group)].append(row)

        elif mode == "3_family_interference_v6":
            group = [_norm(value) for value in row.get("triad_families") or [] if _norm(value)]
            if kind not in TRIAD_VARIANTS or len(group) != 3 or len(set(group)) != 3 or any(family not in by_family for family in group):
                errors.append(f"{cid}: invalid triad contract")
            else:
                expected_root, expected_project = _expected_source(by_family, group)
                if _identity(row.get("source_root")) != _identity(expected_root):
                    errors.append(f"{cid}: triad source_root does not match shortlist sources")
                if _identity(row.get("source_project")) != _identity(expected_project):
                    errors.append(f"{cid}: triad source_project does not match shortlist sources")
            observations = [value for value in row.get("raw_observations") or [] if isinstance(value, Mapping)]
            if len(observations) != 3:
                errors.append(f"{cid}: triad must have three observations")
            for pos, raw in enumerate(observations):
                _validate_observation(raw, f"{cid}#obs{pos+1}", expected_conditions, errors, leakage)
            wanted = {
                "triple_positive": set(group),
                "ab_only": set(group[:2]),
                "c_only": {group[2]} if len(group) == 3 else set(),
                "triple_secure": set(),
                "sparse_interference": set(),
            }
            if kind in wanted and expected_families != wanted[kind]:
                errors.append(f"{cid}: triad expected-set mismatch")
            triads["+".join(group)].append(row)
        else:
            errors.append(f"{cid}: invalid case mode {mode!r}")

    for root, group in singles.items():
        kinds = {_norm(row.get("case_kind")) for row in group}
        if len(group) != 4 or kinds != SINGLE_VARIANTS:
            errors.append(f"{root}: single source variant set mismatch")
        canonical = [_canonical(row.get("raw")) for row in group]
        if len(set(canonical)) != len(canonical):
            errors.append(f"{root}: single raw variants collide")

    pair_members: list[str] = []
    for key, group in pairs.items():
        kinds = {_norm(row.get("case_kind")) for row in group}
        if len(group) != 4 or kinds != PAIR_VARIANTS:
            errors.append(f"{key}: pair variant set mismatch")
        pair_members.extend([_norm(value) for value in group[0].get("paired_families") or []])
        canonical = [_canonical(row.get("raw_observations")) for row in group]
        if len(set(canonical)) != len(canonical):
            errors.append(f"{key}: pair raw variants collide")

    triad_members: list[str] = []
    for key, group in triads.items():
        kinds = {_norm(row.get("case_kind")) for row in group}
        if len(group) != 5 or kinds != TRIAD_VARIANTS:
            errors.append(f"{key}: triad variant set mismatch")
        triad_members.extend([_norm(value) for value in group[0].get("triad_families") or []])
        canonical = [_canonical(row.get("raw_observations")) for row in group]
        if len(set(canonical)) != len(canonical):
            errors.append(f"{key}: triad raw variants collide")

    if sorted(pair_members) != sorted(DETECTOR_SPECS):
        errors.append("v6 pairs must cover every family exactly once")
    if sorted(triad_members) != sorted(DETECTOR_SPECS):
        errors.append("v6 triads must cover every family exactly once")
    if (len(rows), len(singles), len(pairs), len(triads)) != (276, 36, 18, 12):
        errors.append("v6 corpus cardinality contract failed")
    if require_literal_single_capture and literal_single_count != 144:
        errors.append(f"v6 fresh singles require 144 literal captures: {literal_single_count}")

    return {
        "validator_version": VERSION,
        "validator_rule_version": RULE_VERSION,
        "passed": not errors,
        "errors": errors,
        "case_count": len(rows),
        "single_case_count": sum(len(group) for group in singles.values()),
        "pair_case_count": sum(len(group) for group in pairs.values()),
        "triad_case_count": sum(len(group) for group in triads.values()),
        "single_source_count": len(singles),
        "pair_group_count": len(pairs),
        "triad_group_count": len(triads),
        "literal_single_capture_count": literal_single_count,
        "literal_single_capture_required": require_literal_single_capture,
        "label_leakage_count": len(leakage),
        "label_leakage_cases": leakage,
        "source_firewall": firewall,
        "scoring_executed": False,
    }
