from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from family_reasoners import FAMILY_REASONER_PROFILES
from raw_recon_corpus import ROOT

VERSION = "2.0.0"
RULE_VERSION = "2026.08.14.6.31.2"
SHORTLIST = ROOT / "benchmarks/raw/sources/v6_shortlist.json"
CAPTURES = ROOT / "benchmarks/raw/sources/v6_literal_captures.jsonl"
CORPUS = ROOT / "benchmarks/raw/analysis_raw_v6.jsonl"
REPORT = ROOT / "benchmarks/raw/sources/v6_materialization_report.json"
SINGLE_VARIANTS = ("positive", "near_miss", "secure_negative", "sparse_noisy")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _identity(value: Any) -> str:
    return str(value or "").strip().casefold()


def _relation(a: str, b: str) -> int:
    score = 0
    if b in FAMILY_REASONER_PROFILES[a].confounders:
        score += 2
    if a in FAMILY_REASONER_PROFILES[b].confounders:
        score += 2
    return score


def _groups(size: int) -> list[tuple[str, ...]]:
    remaining = set(DETECTOR_SPECS)
    groups: list[tuple[str, ...]] = []
    while remaining:
        seed = max(sorted(remaining), key=lambda name: sum(_relation(name, other) for other in remaining if other != name))
        chosen = [seed]
        remaining.remove(seed)
        while len(chosen) < size:
            candidate = max(sorted(remaining), key=lambda name: (sum(_relation(name, member) for member in chosen), name))
            chosen.append(candidate)
            remaining.remove(candidate)
        groups.append(tuple(chosen))
    return groups


def _load_captures() -> list[dict[str, Any]]:
    if not CAPTURES.exists():
        raise RuntimeError(
            "literal v6 capture set is missing; create benchmarks/raw/sources/v6_literal_captures.jsonl "
            "with four real raw captures per selected family before materialization"
        )
    return [json.loads(line) for line in CAPTURES.read_text(encoding="utf-8").splitlines() if line.strip()]


def _validate_capture(row: Mapping[str, Any], selected: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    family = str(row.get("family") or "")
    kind = str(row.get("case_kind") or "")
    if family not in selected:
        raise RuntimeError(f"literal capture has unknown/unselected family: {family!r}")
    if kind not in SINGLE_VARIANTS:
        raise RuntimeError(f"{family}: invalid literal capture case_kind {kind!r}")

    source = selected[family]
    if _identity(row.get("source_root")) != _identity(source.get("source_root")):
        raise RuntimeError(f"{family}/{kind}: capture source_root does not match shortlist")
    if _identity(row.get("source_project")) != _identity(source.get("source_project")):
        raise RuntimeError(f"{family}/{kind}: capture source_project does not match shortlist")

    raw = row.get("raw") if isinstance(row.get("raw"), Mapping) else None
    if not raw:
        raise RuntimeError(f"{family}/{kind}: literal capture raw object is missing")
    for required in ("target", "endpoint", "method", "endpoint_schema", "details"):
        if required not in raw:
            raise RuntimeError(f"{family}/{kind}: raw.{required} is required")

    provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
    if provenance.get("literal_capture") is not True:
        raise RuntimeError(f"{family}/{kind}: provenance.literal_capture must be true")
    capture_reference = str(provenance.get("capture_reference") or provenance.get("url") or "").strip()
    if not capture_reference:
        raise RuntimeError(f"{family}/{kind}: literal capture provenance reference is required")
    captured_at = str(provenance.get("captured_at") or row.get("source_date") or "").strip()
    if not captured_at:
        raise RuntimeError(f"{family}/{kind}: capture timestamp/date is required")

    signals = [str(value) for value in row.get("expected_condition_signals") or [] if str(value)]
    allowed_signals = set(DETECTOR_SPECS[family].condition_signals)
    if set(signals) - allowed_signals:
        raise RuntimeError(f"{family}/{kind}: expected_condition_signals contain non-canonical detector signal")
    if kind == "positive" and not signals:
        raise RuntimeError(f"{family}/positive: at least one canonical expected condition signal is required")
    if kind != "positive" and signals:
        raise RuntimeError(f"{family}/{kind}: negative/non-positive literal capture cannot carry expected condition signals")

    normalized = dict(row)
    normalized["raw"] = copy.deepcopy(dict(raw))
    normalized["provenance"] = {
        **dict(provenance),
        "literal_capture": True,
        "captured_at": captured_at,
        "capture_sha256": _sha256_json(raw),
    }
    normalized["expected_condition_signals"] = signals
    return normalized


def _expected(families: list[str], positive_capture: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "admitted_families": list(families),
        "condition_signals": {
            family: list(positive_capture[family].get("expected_condition_signals") or [])
            for family in families
        },
    }


def _single(capture: Mapping[str, Any], positive_capture: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    family = str(capture["family"])
    kind = str(capture["case_kind"])
    families = [family] if kind == "positive" else []
    return {
        "id": f"v6-{capture['source_root']}-{kind}",
        "source_root": capture["source_root"],
        "source_project": capture["source_project"],
        "source_date": capture.get("source_date") or capture["provenance"].get("captured_at"),
        "family": family,
        "expected_families": families,
        "case_kind": kind,
        "case_mode": "single_family_fresh_v6",
        "rank_required": kind != "sparse_noisy",
        "provenance": copy.deepcopy(capture["provenance"]),
        "raw": copy.deepcopy(capture["raw"]),
        "expected": _expected(families, positive_capture),
    }


def _composite(
    captures: Mapping[str, Mapping[str, Mapping[str, Any]]],
    positive_capture: Mapping[str, Mapping[str, Any]],
    group_size: int,
) -> list[dict[str, Any]]:
    groups = _groups(group_size)
    cases: list[dict[str, Any]] = []
    if group_size == 2:
        variants = (
            ("dual_positive", ("positive", "positive"), (0, 1)),
            ("a_only", ("positive", "secure_negative"), (0,)),
            ("b_only", ("secure_negative", "positive"), (1,)),
            ("dual_secure", ("secure_negative", "secure_negative"), ()),
        )
    else:
        variants = (
            ("triple_positive", ("positive", "positive", "positive"), (0, 1, 2)),
            ("ab_only", ("positive", "positive", "secure_negative"), (0, 1)),
            ("c_only", ("secure_negative", "secure_negative", "positive"), (2,)),
            ("triple_secure", ("secure_negative", "secure_negative", "secure_negative"), ()),
            ("sparse_interference", ("near_miss", "sparse_noisy", "near_miss"), ()),
        )

    for index, group in enumerate(groups, start=1):
        for case_kind, kinds, expected_indexes in variants:
            selected_captures = [captures[family][kinds[pos]] for pos, family in enumerate(group)]
            expected_families = [group[pos] for pos in expected_indexes]
            cases.append({
                "id": f"v6-g{group_size}-{index:02d}-{case_kind}",
                "source_root": "+".join(str(row["source_root"]) for row in selected_captures),
                "source_project": "+".join(str(row["source_project"]) for row in selected_captures),
                "source_date": max(str(row.get("source_date") or row["provenance"].get("captured_at") or "") for row in selected_captures),
                "family": group[0],
                "paired_families" if group_size == 2 else "triad_families": list(group),
                "expected_families": expected_families,
                "case_kind": case_kind,
                "case_mode": f"{group_size}_family_interference_v6",
                "rank_required": bool(expected_families),
                "provenance": {
                    "composite": True,
                    "literal_capture": True,
                    "composition_only": True,
                    "sources": [copy.deepcopy(row["provenance"]) for row in selected_captures],
                },
                "raw_observations": [copy.deepcopy(row["raw"]) for row in selected_captures],
                "expected": _expected(expected_families, positive_capture),
            })
    return cases


def materialize() -> dict[str, Any]:
    shortlist = json.loads(SHORTLIST.read_text(encoding="utf-8"))
    if shortlist.get("selection_executes_scoring") is not False:
        raise RuntimeError("v6 shortlist must remain unscored")
    selected_rows = [dict(row) for row in shortlist.get("selected") or [] if isinstance(row, Mapping)]
    selected = {str(row.get("family") or ""): row for row in selected_rows}
    if len(selected_rows) != 36 or set(selected) != set(DETECTOR_SPECS):
        raise RuntimeError("v6 shortlist must contain exactly one source for every family")

    literal = [_validate_capture(row, selected) for row in _load_captures()]
    by_family: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in literal:
        family = str(row["family"])
        kind = str(row["case_kind"])
        if kind in by_family[family]:
            raise RuntimeError(f"{family}: duplicate literal capture for {kind}")
        by_family[family][kind] = row

    if set(by_family) != set(DETECTOR_SPECS):
        missing = sorted(set(DETECTOR_SPECS) - set(by_family))
        extra = sorted(set(by_family) - set(DETECTOR_SPECS))
        raise RuntimeError(f"literal capture family coverage mismatch missing={missing} extra={extra}")
    for family, variants in by_family.items():
        if set(variants) != set(SINGLE_VARIANTS):
            raise RuntimeError(f"{family}: literal capture variant coverage mismatch {sorted(variants)}")
        hashes = {_sha256_json(variants[kind]["raw"]) for kind in SINGLE_VARIANTS}
        if len(hashes) != 4:
            raise RuntimeError(f"{family}: literal raw variants must be distinct")

    positive_capture = {family: variants["positive"] for family, variants in by_family.items()}
    singles = [_single(by_family[family][kind], positive_capture) for family in sorted(by_family) for kind in SINGLE_VARIANTS]
    pairs = _composite(by_family, positive_capture, 2)
    triads = _composite(by_family, positive_capture, 3)
    cases = singles + pairs + triads
    if (len(singles), len(pairs), len(triads), len(cases)) != (144, 72, 60, 276):
        raise RuntimeError("v6 literal materialization count contract failed")

    CORPUS.write_text("\n".join(_canonical(row) for row in cases) + "\n", encoding="utf-8")
    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_literal_raw_materialization_unscored",
        "scoring_executed": False,
        "fresh_raw_claim": True,
        "raw_capture_mode": "literal_source_capture",
        "literal_single_capture_count": 144,
        "input_capture_count": len(literal),
        "single_case_count": len(singles),
        "pair_case_count": len(pairs),
        "triad_case_count": len(triads),
        "case_count": len(cases),
        "family_count": 36,
        "pair_groups": [list(group) for group in _groups(2)],
        "triad_groups": [list(group) for group in _groups(3)],
        "shortlist_sha256": hashlib.sha256(SHORTLIST.read_bytes()).hexdigest(),
        "literal_capture_input_sha256": hashlib.sha256(CAPTURES.read_bytes()).hexdigest(),
        "corpus_sha256": hashlib.sha256(CORPUS.read_bytes()).hexdigest(),
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    print(json.dumps(materialize(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
