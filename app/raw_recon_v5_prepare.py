from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from raw_recon_v4_materialize import EXPECTED_CONDITION, V4_VARIANTS, _fixture_target, _source_date, _template
from raw_recon_v5_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION, HARD_ANCHORS, audit_row
from raw_recon_v5_source_discovery import exposure_index

VERSION = "1.3.0"
RULE_VERSION = "2026.08.13.6.29"
CANDIDATES = ROOT / "benchmarks/raw/sources/v5_candidates.json"
EXACT_SUPPLEMENT = ROOT / "benchmarks/raw/sources/v5_exact_source_supplement.json"
SHORTLIST = ROOT / "benchmarks/raw/sources/v5_shortlist.json"
CORPUS = ROOT / "benchmarks/raw/analysis_raw_v5.jsonl"
FREEZE = ROOT / "benchmarks/raw/sources/v5_freeze_manifest.json"
REPORT = ROOT / "benchmarks/raw/sources/v5_prepare_report.json"


def _load_exact_supplement() -> dict[str, dict[str, Any]]:
    if not EXACT_SUPPLEMENT.exists():
        raise RuntimeError("v5 exact source supplement is required before source selection")
    value = json.loads(EXACT_SUPPLEMENT.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or bool(value.get("scoring_executed")):
        raise RuntimeError("v5 exact source supplement scoring contract failed")
    rows = value.get("selected") if isinstance(value.get("selected"), list) else []
    selected: dict[str, dict[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        family = str(raw.get("family") or "")
        if not family or family in selected:
            raise RuntimeError(f"v5 exact supplement duplicate/empty family: {family!r}")
        if not bool(raw.get("freshness_validated")) or not bool(raw.get("exact_source_audit_passed")):
            raise RuntimeError(f"v5 exact supplement source did not pass pre-score contracts: {family}")
        selected[family] = dict(raw)
    expected = {
        "dom_xss", "graphql_authorization", "graphql_data_exposure",
        "improper_inventory_management", "postmessage_trust",
        "sensitive_business_flow_abuse", "software_supply_chain_failure",
        "source_map_exposure", "unsafe_api_consumption", "websocket_authorization",
    }
    if set(selected) != expected:
        raise RuntimeError(f"v5 exact supplement family mismatch missing={sorted(expected-set(selected))} extra={sorted(set(selected)-expected)}")
    return selected


def _select(candidates: Mapping[str, Any]) -> list[dict[str, Any]]:
    pools_raw = candidates.get("candidates_by_family") if isinstance(candidates.get("candidates_by_family"), Mapping) else {}
    semantic: dict[str, list[dict[str, Any]]] = {}
    exact_supplement = _load_exact_supplement()
    for family in sorted(DETECTOR_SPECS):
        source_rows = [dict(row) for row in pools_raw.get(family, []) or [] if isinstance(row, Mapping)]
        if family in exact_supplement:
            source_rows.append(dict(exact_supplement[family]))
        rows: list[dict[str, Any]] = []
        seen_roots: set[str] = set()
        for raw in source_rows:
            root = str(raw.get("source_root") or "")
            if not root or root in seen_roots:
                continue
            seen_roots.add(root)
            if bool(raw.get("exact_source_audit_passed")):
                passed = True
                hits = [list(group) for group in raw.get("source_family_audit_group_hits") or []]
                score = int(raw.get("source_family_audit_score") or 0)
            else:
                passed, hits, score = audit_row(family, raw)
            if not passed:
                continue
            row = dict(raw)
            row["source_family_audit_score"] = score
            row["source_family_audit_group_hits"] = hits
            row.setdefault("source_family_audit_version", AUDIT_VERSION)
            row.setdefault("source_family_audit_rule_version", AUDIT_RULE_VERSION)
            rows.append(row)
        rows.sort(
            key=lambda x: (
                1 if x.get("exact_source_audit_passed") else 0,
                int(x["source_family_audit_score"]),
                1 if x.get("advisory_source_type") == "reviewed" else 0,
                x.get("published_at") or "",
                x.get("source_root") or "",
            ),
            reverse=True,
        )
        semantic[family] = rows

    zero_semantic = sorted(family for family, rows in semantic.items() if not rows)
    if zero_semantic:
        raise RuntimeError(
            "v5 source semantic audit has zero eligible candidates for: " + ", ".join(zero_semantic)
        )

    order = sorted(semantic, key=lambda f: (0 if f in exact_supplement else 1, len(semantic[f]), f))
    used_roots: set[str] = set()
    used_projects: set[str] = set()
    selected: dict[str, dict[str, Any]] = {}
    uniqueness_blocked: dict[str, int] = {}
    for family in order:
        choice = None
        blocked = 0
        for row in semantic[family]:
            root = str(row.get("source_root") or "")
            project = str(row.get("source_project") or "")
            if not root or not project or root in used_roots or project in used_projects:
                blocked += 1
                continue
            choice = row
            break
        if choice is None:
            uniqueness_blocked[family] = blocked
            raise RuntimeError(
                f"v5 semantic/uniqueness selection failed for {family}; "
                f"semantic_candidates={len(semantic[family])}; uniqueness_blocked={blocked}"
            )
        selected[family] = choice
        used_roots.add(str(choice["source_root"]))
        used_projects.add(str(choice["source_project"]))
    if set(selected) != set(HARD_ANCHORS) or set(selected) != set(DETECTOR_SPECS):
        raise RuntimeError("v5 selected-source family partition is incomplete")
    if len(used_roots) != 36 or len(used_projects) != 36:
        raise RuntimeError("v5 selected-source root/project uniqueness contract failed")
    for family, exact_row in exact_supplement.items():
        if str(selected[family].get("source_root") or "") != str(exact_row.get("source_root") or ""):
            raise RuntimeError(f"v5 exact source was not selected for {family}")
    return [selected[family] for family in sorted(selected)]


def _noise(raw: Mapping[str, Any], family: str, kind: str) -> dict[str, Any]:
    out = copy.deepcopy(dict(raw))
    details = out.get("details") if isinstance(out.get("details"), Mapping) else {}
    details = dict(details)
    details["fixture_transport"] = {
        "capture": "normalized",
        "trace_id": f"v5-{family[:8]}",
        "retry_count": 0,
    }
    details["unrelated_observation"] = {"server_hint": "fixture", "timing_bucket": "normal"}
    out["details"] = details
    out["category"] = str(out.get("category") or "") + " normalized-v5"
    return out


def _observation(raw_template: Mapping[str, Any], *, target: str, family: str, kind: str) -> dict[str, Any]:
    return {"target": target, **_noise(raw_template, family, kind)}


def _is_primary_source(row: Mapping[str, Any]) -> bool:
    repository_advisory = str(row.get("repository_advisory_url") or "")
    canonical = str(row.get("canonical_advisory_url") or "")
    return bool(repository_advisory) or "/security/advisories/" in canonical


def _source_provenance(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "url": row["canonical_advisory_url"],
        "source_kind": str(
            row.get("source_kind") or row.get("advisory_source_type") or "github_security_advisory"
        ),
        "advisory_source_type": str(row.get("advisory_source_type") or ""),
        "primary_source": _is_primary_source(row),
        "literal_capture": False,
    }


def _single_case(row: Mapping[str, Any], kind: str, raw_template: Mapping[str, Any]) -> dict[str, Any]:
    family = str(row["family"])
    condition = EXPECTED_CONDITION[family]
    project = str(row["source_project"])
    raw = _observation(raw_template, target=_fixture_target(project), family=family, kind=kind)
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
        "provenance": _source_provenance(row),
        "raw": raw,
        "expected": {
            "admitted_families": [family] if kind == "positive" else [],
            "condition_signals": {family: [condition] if kind == "positive" else []},
        },
    }


def _multi_cases(selected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_family = {str(row["family"]): row for row in selected}
    families = sorted(by_family)
    pairs = list(zip(families[:18], reversed(families[18:])))
    cases: list[dict[str, Any]] = []
    for index, (fa, fb) in enumerate(pairs, start=1):
        ra, rb = by_family[fa], by_family[fb]
        ta, tb = _template(fa, ra), _template(fb, rb)
        target = f"v5-pair-{index:02d}.fixture.invalid"
        variants = (
            ("dual_positive", "positive", "positive", [fa, fb]),
            ("a_only", "positive", "secure_negative", [fa]),
            ("b_only", "secure_negative", "positive", [fb]),
            ("dual_secure", "secure_negative", "secure_negative", []),
        )
        for case_kind, kind_a, kind_b, expected_families in variants:
            observations = [
                _observation(ta[kind_a], target=target, family=fa, kind=kind_a),
                _observation(tb[kind_b], target=target, family=fb, kind=kind_b),
            ]
            expected_conditions = {
                family: [EXPECTED_CONDITION[family]] for family in expected_families
            }
            cases.append({
                "id": f"v5-multi-{index:02d}-{case_kind}",
                "source_root": f"{ra['source_root']}+{rb['source_root']}",
                "source_project": f"{ra['source_project']}+{rb['source_project']}",
                "source_date": max(_source_date(ra), _source_date(rb)),
                "family": fa,
                "paired_families": [fa, fb],
                "expected_families": list(expected_families),
                "case_kind": case_kind,
                "case_mode": "multi_family_hard_case",
                "rank_required": bool(expected_families),
                "provenance": {
                    "composite": True,
                    "sources": [_source_provenance(ra), _source_provenance(rb)],
                },
                "raw_observations": observations,
                "expected": {
                    "admitted_families": list(expected_families),
                    "condition_signals": expected_conditions,
                },
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
        "source_audit_version": AUDIT_VERSION,
        "source_audit_rule_version": AUDIT_RULE_VERSION,
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
    CORPUS.write_text(
        "\n".join(
            json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            for row in cases
        ) + "\n",
        encoding="utf-8",
    )

    prior = exposure_index()
    roots = {str(row["source_root"]) for row in selected}
    projects = {str(row["source_project"]) for row in selected}
    urls = {str(row["canonical_advisory_url"]) for row in selected}
    prior_root_overlap = sorted(roots & prior["roots"])
    prior_project_overlap = sorted(projects & prior["projects"])
    prior_url_overlap = sorted(urls & prior["urls"])
    if prior_root_overlap or prior_project_overlap or prior_url_overlap:
        raise RuntimeError(
            f"v5 novelty firewall failed roots={prior_root_overlap} "
            f"projects={prior_project_overlap} urls={prior_url_overlap}"
        )
    if len(singles) != 144 or len(multi) != 72 or len(cases) != 216:
        raise RuntimeError(
            f"v5 case-count contract failed singles={len(singles)} multi={len(multi)} total={len(cases)}"
        )
    if any(len(row.get("raw_observations") or []) != 2 for row in multi):
        raise RuntimeError(
            "each v5 multi-family case must contain exactly two independent stored observations"
        )

    source_kind_counts: dict[str, int] = {}
    primary_source_count = 0
    for row in selected:
        kind = str(row.get("source_kind") or row.get("advisory_source_type") or "unknown")
        source_kind_counts[kind] = source_kind_counts.get(kind, 0) + 1
        primary_source_count += int(_is_primary_source(row))

    protected_files = {
        "benchmarks/raw/sources/v5_candidates.json": _sha(CANDIDATES),
        "benchmarks/raw/sources/v5_shortlist.json": _sha(SHORTLIST),
        "benchmarks/raw/analysis_raw_v5.jsonl": _sha(CORPUS),
    }
    if EXACT_SUPPLEMENT.exists():
        protected_files["benchmarks/raw/sources/v5_exact_source_supplement.json"] = _sha(
            EXACT_SUPPLEMENT
        )

    freeze = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_status": "sealed_unscored",
        "first_blind_max_runs": 1,
        "mutation_policy": "corpus shortlist sources expected labels gates and source supplements are immutable after this freeze",
        "case_count": len(cases),
        "single_case_count": len(singles),
        "multi_case_count": len(multi),
        "multi_observation_model": "two_independent_stored_target_observations",
        "family_count": 36,
        "source_root_count": len(roots),
        "source_project_count": len(projects),
        "source_kind_counts": source_kind_counts,
        "primary_source_count": primary_source_count,
        "prior_root_overlap_count": 0,
        "prior_project_overlap_count": 0,
        "prior_url_overlap_count": 0,
        "scoring_executed": False,
        "protected_sha256": protected_files,
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
