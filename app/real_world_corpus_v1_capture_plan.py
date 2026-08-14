from __future__ import annotations

"""Build the 400-case controlled-capture plan for Real-World Corpus V1.

The plan is intentionally pre-label and pre-score. It defines what must be
observed from public source material or an isolated controlled source replay,
but it does not execute vulnerable software, contact targets, assign final
families, or fabricate human verdicts.
"""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

CAPTURE_PLAN_VERSION = "1.0.0"
CAPTURE_PLAN_RULE_VERSION = "2026.08.14.6"
SOURCE_COUNT = 100
VARIANTS = ("positive", "near_miss", "secure_negative", "sparse_noisy")
CASE_COUNT = SOURCE_COUNT * len(VARIANTS)
MIN_FAMILY_TARGETS = 50
QUALITY_DIMENSIONS = (
    "reliability",
    "specificity",
    "directness",
    "freshness",
    "independence",
    "reproducibility",
    "uncertainty",
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _slug(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")


def _method_for(source: Mapping[str, Any], variant: str) -> tuple[str, str]:
    feasibility = _text(source.get("capture_feasibility"))
    variant_map = source.get("variant_feasibility") if isinstance(source.get("variant_feasibility"), Mapping) else {}
    variant_state = _text(variant_map.get(variant))

    if feasibility == "manual_source_research_required":
        return "blocked_manual_source_research", "blocked"
    if variant == "near_miss":
        return "manual_control_design_then_controlled_observation", "control_design_required"
    if variant == "sparse_noisy":
        return "minimal_source_metadata_observation", "ready_to_collect"
    if feasibility == "strong_revision_boundary":
        method = (
            "controlled_vulnerable_revision_observation"
            if variant == "positive"
            else "controlled_patched_revision_observation"
        )
        return method, "ready_to_collect"
    if feasibility == "version_boundary_available":
        method = (
            "controlled_vulnerable_version_observation"
            if variant == "positive"
            else "controlled_patched_version_observation"
        )
        return method, "ready_to_collect"
    if feasibility == "source_reference_available":
        return "source_reference_research_then_controlled_observation", "source_research_required"
    return "manual_capture_design_required", variant_state or "blocked"


def _review_template() -> dict[str, Any]:
    return {
        "final_family": None,
        "label": None,
        "label_source": None,
        "reviewer_id": None,
        "reviewed_at": None,
        "evidence_snapshot_id": None,
        "evidence_quality": {dimension: None for dimension in QUALITY_DIMENSIONS},
        "human_verified": False,
    }


def case_for_source(source: Mapping[str, Any], variant: str) -> dict[str, Any]:
    root = _text(source.get("source_root")).upper()
    project = _text(source.get("source_project")).lower()
    family_target = _text(source.get("family_target")) or None
    method, design_status = _method_for(source, variant)
    origin = f"rwv1:{root}"
    return {
        "case_id": f"rwv1-{_slug(root)}-{variant}",
        "case_origin_id": origin,
        "source_root": root,
        "source_project": project,
        "family_target": family_target,
        "target_cwe": _text(source.get("target_cwe")) or None,
        "source_taxonomy_match": source.get("source_taxonomy_match"),
        "variant": variant,
        "capture_method": method,
        "capture_design_status": design_status,
        "capture_execution_status": "not_started",
        "capture_feasibility": _text(source.get("capture_feasibility")),
        "version_boundaries": source.get("version_boundaries", []),
        "reference_inventory": source.get("reference_inventory", {}),
        "evaluation_role": "fresh_candidate",
        "proposed_provenance": "curated_real_world_replay",
        "public_source_only": True,
        "source_acquisition_network_only": True,
        "vulnerability_target_network_access_allowed": False,
        "state_mutation_allowed": False,
        "credential_use_allowed": False,
        "payload_generation_allowed": False,
        "scoring_executed": False,
        "target_contact_performed": False,
        "family_assignment_is_final": False,
        "review": _review_template(),
    }


def validate_plan(cases: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [dict(row) for row in cases]
    origin_counts = Counter(_text(row.get("case_origin_id")) for row in rows)
    roots = {_text(row.get("source_root")) for row in rows if _text(row.get("source_root"))}
    projects = {_text(row.get("source_project")) for row in rows if _text(row.get("source_project"))}
    family_targets = {_text(row.get("family_target")) for row in rows if _text(row.get("family_target"))}
    variants_by_origin: dict[str, set[str]] = {}
    for row in rows:
        variants_by_origin.setdefault(_text(row.get("case_origin_id")), set()).add(_text(row.get("variant")))

    errors: list[str] = []
    if len(rows) != CASE_COUNT:
        errors.append(f"case_count:{len(rows)}!=400")
    if len(roots) != SOURCE_COUNT:
        errors.append(f"source_root_count:{len(roots)}!=100")
    if len(projects) != SOURCE_COUNT:
        errors.append(f"source_project_count:{len(projects)}!=100")
    if any(count != 4 for count in origin_counts.values()) or len(origin_counts) != SOURCE_COUNT:
        errors.append("each_source_origin_must_have_exactly_four_cases")
    if any(values != set(VARIANTS) for values in variants_by_origin.values()):
        errors.append("each_origin_must_have_exact_variant_contract")
    if len(family_targets) < MIN_FAMILY_TARGETS:
        errors.append(f"family_target_count:{len(family_targets)}<50")
    if any(row.get("review", {}).get("label") is not None for row in rows):
        errors.append("pre_capture_plan_must_not_contain_labels")
    if any(bool(row.get("review", {}).get("human_verified")) for row in rows):
        errors.append("pre_capture_plan_must_not_be_human_verified")
    if any(bool(row.get("scoring_executed")) for row in rows):
        errors.append("pre_capture_plan_must_not_be_scored")
    if any(bool(row.get("target_contact_performed")) for row in rows):
        errors.append("pre_capture_plan_must_not_contact_targets")
    if any(bool(row.get("vulnerability_target_network_access_allowed")) for row in rows):
        errors.append("capture_plan_must_forbid_target_network_access")

    design_counts = Counter(_text(row.get("capture_design_status")) for row in rows)
    return {
        "passed": not errors,
        "errors": errors,
        "case_count": len(rows),
        "source_origin_count": len(origin_counts),
        "unique_source_root_count": len(roots),
        "unique_source_project_count": len(projects),
        "family_target_count": len(family_targets),
        "design_status_counts": dict(sorted(design_counts.items())),
        "blocked_case_count": int(design_counts.get("blocked", 0)),
        "control_design_required_count": int(design_counts.get("control_design_required", 0)),
        "ready_to_collect_count": int(design_counts.get("ready_to_collect", 0)),
        "source_research_required_count": int(design_counts.get("source_research_required", 0)),
    }


def build_capture_plan(sources: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    source_rows = sorted(
        (dict(row) for row in sources),
        key=lambda row: (_text(row.get("source_root")), _text(row.get("source_project"))),
    )
    if len(source_rows) != SOURCE_COUNT:
        raise ValueError(f"source_count:{len(source_rows)}!=100")
    cases = [case_for_source(source, variant) for source in source_rows for variant in VARIANTS]
    validation = validate_plan(cases)
    if not validation["passed"]:
        raise ValueError("capture_plan_validation_failed:" + ",".join(validation["errors"]))
    canonical = json.dumps(cases, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "version": CAPTURE_PLAN_VERSION,
        "rule_version": CAPTURE_PLAN_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_controlled_capture_plan",
        "status": (
            "capture_plan_complete_with_research_blockers"
            if validation["blocked_case_count"] or validation["source_research_required_count"]
            else "capture_plan_complete"
        ),
        "plan_sha256": hashlib.sha256(canonical).hexdigest(),
        "variant_contract": list(VARIANTS),
        "scoring_executed": False,
        "target_contact_performed": False,
        "human_labels_created": False,
        "family_assignment_is_final": False,
        "validation": validation,
        "cases": cases,
        "next_transition": "resolve_source_research_and_near_miss_control_design_before_capture_execution",
    }


def _load_sources(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("sources")
    if not isinstance(rows, list):
        raise ValueError("source_feasibility_sources_missing")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Real-World Corpus V1 400-case capture plan")
    parser.add_argument("--feasibility", default="benchmarks/real_world/v1/source_feasibility.json")
    parser.add_argument("--output", default="benchmarks/real_world/v1/capture_plan.json")
    parser.add_argument("--report", default="benchmarks/real_world/v1/capture_plan_report.json")
    args = parser.parse_args(argv)

    result = build_capture_plan(_load_sources(Path(args.feasibility)))
    _write(Path(args.output), result)
    report = {key: value for key, value in result.items() if key != "cases"}
    _write(Path(args.report), report)
    print(json.dumps({"ok": True, **result["validation"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
