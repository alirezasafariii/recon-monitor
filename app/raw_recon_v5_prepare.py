from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from raw_recon_v4_materialize import EXPECTED_CONDITION, V4_VARIANTS, _fixture_target, _source_date, _template
from raw_recon_v4_source_audit import HARD_ANCHORS, audit_row
from raw_recon_v5_source_discovery import exposure_index

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.29"
CANDIDATES = ROOT / "benchmarks/raw/sources/v5_candidates.json"
SHORTLIST = ROOT / "benchmarks/raw/sources/v5_shortlist.json"
CORPUS = ROOT / "benchmarks/raw/analysis_raw_v5.jsonl"
FREEZE = ROOT / "benchmarks/raw/sources/v5_freeze_manifest.json"
REPORT = ROOT / "benchmarks/raw/sources/v5_prepare_report.json"


def _select(candidates: Mapping[str, Any]) -> list[dict[str, Any]]:
    pools_raw = candidates.get("candidates_by_family") if isinstance(candidates.get("candidates_by_family"), Mapping) else {}
    semantic: dict[str, list[dict[str, Any]]] = {}
    for family in sorted(DETECTOR_SPECS):
        rows: list[dict[str, Any]] = []
        for raw in pools_raw.get(family, []) or []:
            if not isinstance(raw, Mapping):
                continue
            passed, hits, score = audit_row(family, raw)
            if not passed:
                continue
            row = dict(raw)
            row["source_family_audit_score"] = score
            row["source_family_audit_group_hits"] = hits
            row["source_family_audit_version"] = "v5-pre-score"
            rows.append(row)
        rows.sort(key=lambda x: (int(x["source_family_audit_score"]), x.get("published_at") or "", x.get("source_root") or ""), reverse=True)
        semantic[family] = rows

    order = sorted(semantic, key=lambda f: (len(semantic[f]), f))
    used_roots: set[str] = set()
    used_projects: set[str] = set()
    selected: dict[str, dict[str, Any]] = {}
    for family in order:
        choice = None
        for row in semantic[family]:
            root = str(row.get("source_root") or "")
            project = str(row.get("source_project") or "")
            if root and project and root not in used_roots and project not in used_projects:
                choice = row
                break
        if choice is None:
            raise RuntimeError(f"v5 semantic/uniqueness selection failed for {family}; candidates={len(semantic[family])}")
        selected[family] = choice
        used_roots.add(str(choice["source_root"]))
        used_projects.add(str(choice["source_project"]))
    if set(selected) != set(HARD_ANCHORS) or len(used_roots) != 36 or len(used_projects) != 36:
        raise RuntimeError("v5 selected-source partition is incomplete or not unique")
    return [selected[family] for family in sorted(selected)]


def _noise(raw: Mapping[str, Any], family: str, kind: str) -> dict[str, Any]:
    out = copy.deepcopy(dict(raw))
    details = out.get("details") if isinstance(out.get("details"), Mapping) else {}
    details = dict(details)
    details["fixture_transport"] = {"capture": "normalized", "trace_id": f"v5-{family[:8]}-{kind}", "retry_count": 0}
    details["unrelated_observation"] = {"server_hint": "fixture", "timing_bucket": "normal"}
    out["details"] = details
    out["category"] = str(out.get("category") or "") + " normalized-v5"
    return out


def _single_case(row: Mapping[str, Any], kind: str, raw_template: Mapping[str, Any]) -> dict[str, Any]:
    family = str(row["family"])
    condition = EXPECTED_CONDITION[family]
    project = str(row["source_project"])
    raw = {"target": _fixture_target(project), **_noise(raw_template, family, kind)}
    return {
        "id": f"v5-{row['source_root']}-{kind}",
        "source_root": row["source_root"],
        "source_project": project,
        "source_date": _source_date(row),
        "family": family,
        "expected_families": [family] if kind == "positive" else [],
        "case_kind": kind,
        "case_mode": "single_family_fresh",
        "rank_required": kind != "sparse_noisy",
        "provenance": {"url": row["canonical_advisory_url"], "primary_source": True, "literal_capture": False},
        "raw": raw,
        "expected": {"admitted_families": [family] if kind == "positive" else [], "condition_signals": {family: [condition] if kind == "positive" else []}},
    }


def _merge_schema(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    keys = {"query_parameters", "body_fields", "path_parameters", "object_identifiers", "authentication_hints"}
    return {key: sorted(set(a.get(key) or []) | set(b.get(key) or [])) for key in keys}


def _merge_raw(a: Mapping[str, Any], b: Mapping[str, Any], target: str, pair_id: str) -> dict[str, Any]:
    da = a.get("details") if isinstance(a.get("details"), Mapping) else {}
    db = b.get("details") if isinstance(b.get("details"), Mapping) else {}
    details = copy.deepcopy(dict(da))
    for key, value in db.items():
        if key not in details:
            details[key] = copy.deepcopy(value)
        else:
            details[f"secondary_{key}"] = copy.deepcopy(value)
    details["composite_fixture"] = {"pair": pair_id, "normalized": True}
    return {
        "target": target,
        "endpoint": str(a.get("endpoint") or b.get("endpoint") or "/fixture"),
        "method": str(a.get("method") or b.get("method") or "GET"),
        "endpoint_schema": _merge_schema(
            a.get("endpoint_schema") if isinstance(a.get("endpoint_schema"), Mapping) else {},
            b.get("endpoint_schema") if isinstance(b.get("endpoint_schema"), Mapping) else {},
        ),
        "business_context": f"{a.get('business_context') or 'general'} + {b.get('business_context') or 'general'}",
        "category": f"{a.get('category') or ''} | {b.get('category') or ''} | composite-v5",
        "details": details,
    }


def _multi_cases(selected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_family = {str(row["family"]): row for row in selected}
    families = sorted(by_family)
    # Deterministic disjoint pairing. Pairing is frozen before scoring and uses no engine output.
    pairs = list(zip(families[:18], reversed(families[18:])))
    cases: list[dict[str, Any]] = []
    for index, (fa, fb) in enumerate(pairs, start=1):
        ra, rb = by_family[fa], by_family[fb]
        ta, tb = _template(fa, ra), _template(fb, rb)
        target = f"v5-pair-{index:02d}.fixture.invalid"
        pair_id = f"{fa}+{fb}"
        variants = (
            ("dual_positive", "positive", "positive", [fa, fb]),
            ("a_only", "positive", "secure_negative", [fa]),
            ("b_only", "secure_negative", "positive", [fb]),
            ("dual_secure", "secure_negative", "secure_negative", []),
        )
        for kind, ka, kb, expected_families in variants:
            raw = _merge_raw(ta[ka], tb[kb], target, pair_id)
            expected_conditions = {
                family: [EXPECTED_CONDITION[family]]
                for family in expected_families
            }
            cases.append({
                "id": f"v5-multi-{index:02d}-{kind}",
                "source_root": f"{ra['source_root']}+{rb['source_root']}",
                "source_project": f"{ra['source_project']}+{rb['source_project']}",
                "source_date": max(_source_date(ra), _source_date(rb)),
                "family": fa,
                "expected_families": list(expected_families),
                "case_kind": kind,
                "case_mode": "multi_family_hard_case",
                "rank_required": bool(expected_families),
                "provenance": {"primary_source": True, "composite": True, "urls": [ra["canonical_advisory_url"], rb["canonical_advisory_url"]]},
                "raw": raw,
                "expected": {"admitted_families": list(expected_families), "condition_signals": expected_conditions},
            })
    return cases


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare() -> dict[str, Any]:
    candidates = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    selected = _select(candidates)
    shortlist = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "selection_executes_scoring": False,
        "selection_uses_detector_output": False,
        "selection_uses_v4_result": False,
        "selected": selected,
    }
    SHORTLIST.write_text(json.dumps(shortlist, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    singles: list[dict[str, Any]] = []
    for row in selected:
        variants = _template(str(row["family"]), row)
        if set(variants) != set(V4_VARIANTS):
            raise RuntimeError(f"template variant mismatch for {row['family']}")
        for kind in V4_VARIANTS:
            singles.append(_single_case(row, kind, variants[kind]))
    multi = _multi_cases(selected)
    cases = singles + multi
    CORPUS.write_text("\n".join(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for row in cases) + "\n", encoding="utf-8")

    prior = exposure_index()
    roots = {str(row["source_root"]) for row in selected}
    projects = {str(row["source_project"]) for row in selected}
    urls = {str(row["canonical_advisory_url"]) for row in selected}
    prior_root_overlap = sorted(roots & prior["roots"])
    prior_project_overlap = sorted(projects & prior["projects"])
    prior_url_overlap = sorted(urls & prior["urls"])
    if prior_root_overlap or prior_project_overlap or prior_url_overlap:
        raise RuntimeError(f"v5 novelty firewall failed roots={prior_root_overlap} projects={prior_project_overlap} urls={prior_url_overlap}")
    if len(singles) != 144 or len(multi) != 72 or len(cases) != 216:
        raise RuntimeError(f"v5 case-count contract failed singles={len(singles)} multi={len(multi)} total={len(cases)}")

    freeze = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_status": "sealed_unscored",
        "first_blind_max_runs": 1,
        "mutation_policy": "corpus shortlist sources and expected labels are immutable after this freeze",
        "case_count": len(cases),
        "single_case_count": len(singles),
        "multi_case_count": len(multi),
        "family_count": 36,
        "source_root_count": len(roots),
        "source_project_count": len(projects),
        "prior_root_overlap_count": 0,
        "prior_project_overlap_count": 0,
        "prior_url_overlap_count": 0,
        "scoring_executed": False,
        "protected_sha256": {
            "benchmarks/raw/sources/v5_candidates.json": _sha(CANDIDATES),
            "benchmarks/raw/sources/v5_shortlist.json": _sha(SHORTLIST),
            "benchmarks/raw/analysis_raw_v5.jsonl": _sha(CORPUS),
        },
        "pre_registered_gates": {
            "single_existing_raw_gates": "unchanged RAW_QUALITY_GATES",
            "multi_exact_admission_set_accuracy_min": 0.90,
            "multi_expected_condition_recall_min": 0.85,
            "multi_unexpected_promotion_rate_max": 0.05,
            "multi_dual_positive_both_admitted_min": 0.80,
            "multi_dual_secure_rejection_min": 0.95,
            "multi_expected_family_top3_coverage_min": 0.90,
        },
    }
    FREEZE.write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = {**freeze, "shortlist_sha256": _sha(SHORTLIST), "corpus_sha256": _sha(CORPUS)}
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    report = prepare()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
