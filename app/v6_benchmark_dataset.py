from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from family_reasoners import FAMILY_REASONER_PROFILES
from raw_recon_corpus import ROOT
from raw_recon_v4_materialize import EXPECTED_CONDITION, V4_VARIANTS, _fixture_target, _source_date, _template

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.31"
SHORTLIST = ROOT / "benchmarks/raw/sources/v6_shortlist.json"
CORPUS = ROOT / "benchmarks/raw/analysis_raw_v6.jsonl"
REPORT = ROOT / "benchmarks/raw/sources/v6_materialization_report.json"


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
            candidate = max(
                sorted(remaining),
                key=lambda name: (sum(_relation(name, member) for member in chosen), name),
            )
            chosen.append(candidate)
            remaining.remove(candidate)
        groups.append(tuple(chosen))
    return groups


def _noise(raw: Mapping[str, Any], family: str) -> dict[str, Any]:
    out = copy.deepcopy(dict(raw))
    details = dict(out.get("details") or {}) if isinstance(out.get("details"), Mapping) else {}
    details["fixture_transport"] = {"capture": "normalized", "trace_id": f"v6-{family[:8]}", "retry_count": 0}
    details["unrelated_observation"] = {"server_hint": "fixture", "timing_bucket": "normal"}
    out["details"] = details
    out["category"] = str(out.get("category") or "") + " normalized-v6"
    return out


def _observation(template: Mapping[str, Any], target: str, family: str) -> dict[str, Any]:
    return {"target": target, **_noise(template, family)}


def _provenance(row: Mapping[str, Any]) -> dict[str, Any]:
    canonical = str(row.get("canonical_advisory_url") or "")
    return {
        "url": canonical,
        "source_kind": str(row.get("source_kind") or row.get("advisory_source_type") or "github_security_advisory"),
        "advisory_source_type": str(row.get("advisory_source_type") or ""),
        "primary_source": bool(row.get("repository_advisory_url")) or "/security/advisories/" in canonical,
        "literal_capture": False,
    }


def _expected(families: list[str]) -> dict[str, Any]:
    return {
        "admitted_families": list(families),
        "condition_signals": {family: [EXPECTED_CONDITION[family]] for family in families},
    }


def _single(row: Mapping[str, Any], kind: str, template: Mapping[str, Any]) -> dict[str, Any]:
    family = str(row["family"])
    project = str(row["source_project"])
    families = [family] if kind == "positive" else []
    return {
        "id": f"v6-{row['source_root']}-{kind}",
        "source_root": row["source_root"],
        "source_project": project,
        "source_date": _source_date(row),
        "family": family,
        "expected_families": families,
        "case_kind": kind,
        "case_mode": "single_family_fresh_v6",
        "rank_required": kind != "sparse_noisy",
        "provenance": _provenance(row),
        "raw": _observation(template, _fixture_target(project), family),
        "expected": _expected(families),
    }


def _composite(selected: list[dict[str, Any]], group_size: int) -> list[dict[str, Any]]:
    by_family = {str(row["family"]): row for row in selected}
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
        rows = [by_family[family] for family in group]
        templates = [_template(family, row) for family, row in zip(group, rows)]
        target = f"v6-g{group_size}-{index:02d}.fixture.invalid"
        for case_kind, kinds, expected_indexes in variants:
            expected_families = [group[pos] for pos in expected_indexes]
            cases.append({
                "id": f"v6-g{group_size}-{index:02d}-{case_kind}",
                "source_root": "+".join(str(row["source_root"]) for row in rows),
                "source_project": "+".join(str(row["source_project"]) for row in rows),
                "source_date": max(_source_date(row) for row in rows),
                "family": group[0],
                "paired_families" if group_size == 2 else "triad_families": list(group),
                "expected_families": expected_families,
                "case_kind": case_kind,
                "case_mode": f"{group_size}_family_interference_v6",
                "rank_required": bool(expected_families),
                "provenance": {"composite": True, "sources": [_provenance(row) for row in rows]},
                "raw_observations": [_observation(templates[pos][kinds[pos]], target, family) for pos, family in enumerate(group)],
                "expected": _expected(expected_families),
            })
    return cases


def materialize() -> dict[str, Any]:
    shortlist = json.loads(SHORTLIST.read_text(encoding="utf-8"))
    if shortlist.get("selection_executes_scoring") is not False:
        raise RuntimeError("v6 shortlist must remain unscored")
    selected = [dict(row) for row in shortlist.get("selected") or [] if isinstance(row, Mapping)]
    if len(selected) != 36 or {str(row.get("family") or "") for row in selected} != set(DETECTOR_SPECS):
        raise RuntimeError("v6 shortlist must contain exactly one source for every family")

    singles: list[dict[str, Any]] = []
    for row in selected:
        family = str(row["family"])
        variants = _template(family, row)
        if set(variants) != set(V4_VARIANTS):
            raise RuntimeError(f"template variant mismatch for {family}")
        singles.extend(_single(row, kind, variants[kind]) for kind in V4_VARIANTS)
    pairs = _composite(selected, 2)
    triads = _composite(selected, 3)
    cases = singles + pairs + triads
    if (len(singles), len(pairs), len(triads), len(cases)) != (144, 72, 60, 276):
        raise RuntimeError("v6 materialization count contract failed")

    CORPUS.write_text("\n".join(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for row in cases) + "\n", encoding="utf-8")
    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_materialized_unscored",
        "scoring_executed": False,
        "single_case_count": len(singles),
        "pair_case_count": len(pairs),
        "triad_case_count": len(triads),
        "case_count": len(cases),
        "family_count": 36,
        "pair_groups": [list(group) for group in _groups(2)],
        "triad_groups": [list(group) for group in _groups(3)],
        "shortlist_sha256": hashlib.sha256(SHORTLIST.read_bytes()).hexdigest(),
        "corpus_sha256": hashlib.sha256(CORPUS.read_bytes()).hexdigest(),
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    print(json.dumps(materialize(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
