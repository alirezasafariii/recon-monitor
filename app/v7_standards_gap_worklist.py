from __future__ import annotations

"""Build a fail-closed acquisition worklist from unresolved V7 adjudication rows."""

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from researcher_logic import researcher_logic_for_family

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.standards-gap-worklist.1"
ADJUDICATION = ROOT / "benchmarks/raw/sources/v7_standards_adjudication.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_standards_gap_worklist.json"


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _priority(*, case_kind: str, family_mapping_required: bool) -> int:
    if family_mapping_required and case_kind == "positive":
        return 0
    if case_kind == "positive":
        return 1
    if case_kind == "secure_negative":
        return 2
    if case_kind == "near_miss":
        return 3
    return 4


def _missing_requirements(case_kind: str, literal: Mapping[str, Any]) -> list[str]:
    missing: list[str] = []
    aligned = literal.get("family_source_aligned") is True
    condition = bool(literal.get("condition_hits"))
    control = bool(literal.get("blocking_control_hits"))
    override = bool(literal.get("override_hits"))
    fixed = literal.get("fixed_shape_observed") is True
    test = literal.get("test_control_shape_observed") is True
    partial = literal.get("partial_shape_observed") is True
    if not aligned:
        missing.append("literal_family_identity_or_surface")
    if case_kind == "positive":
        if not condition:
            missing.append("literal_decisive_condition")
        if control and not override:
            missing.append("control_is_present_without_literal_override")
    elif case_kind == "secure_negative":
        if condition:
            missing.append("decisive_condition_must_be_absent")
        if not (control or fixed):
            missing.append("literal_blocking_control_or_fixed_state")
    elif case_kind == "near_miss":
        if condition:
            missing.append("decisive_condition_must_be_absent")
        if not (control or test):
            missing.append("independent_control_or_test_shape")
    elif case_kind == "sparse_noisy":
        if condition:
            missing.append("decisive_condition_must_be_absent")
        if not partial:
            missing.append("partial_or_noisy_source_shape")
    return missing


def _seed_terms(family: str, case_kind: str) -> dict[str, list[str]]:
    spec = DETECTOR_SPECS[family]
    logic = researcher_logic_for_family(family)
    condition = list(spec.condition_signals[:8])
    controls = list(spec.blocking_controls[:8])
    surfaces = list(spec.surface_terms[:8])
    identity = list(spec.identity_signals[:8])
    writeup = []
    for lesson in logic.get("writeup_logic") or []:
        if isinstance(lesson, Mapping):
            for key in ("lesson", "pattern", "signal", "condition", "control", "title"):
                value = text(lesson.get(key))
                if value:
                    writeup.append(value)
        else:
            value = text(lesson)
            if value:
                writeup.append(value)
    if case_kind == "positive":
        required = identity + surfaces + condition
    elif case_kind in {"secure_negative", "near_miss"}:
        required = identity + surfaces + controls
    else:
        required = identity + surfaces
    return {
        "identity_terms": identity,
        "surface_terms": surfaces,
        "condition_terms": condition,
        "control_terms": controls,
        "writeup_lesson_terms": writeup[:12],
        "preferred_query_terms": list(dict.fromkeys(required))[:20],
    }


def build() -> dict[str, Any]:
    adj = load(ADJUDICATION)
    if adj.get("family_count") != 36 or adj.get("variant_count") != 144:
        raise RuntimeError("V7 standards gap worklist requires the complete 36/144 adjudication")
    if adj.get("scoring_executed") is not False or adj.get("first_blind_consumed") is not False:
        raise RuntimeError("V7 standards gap worklist requires an unconsumed blind")
    if adj.get("standards_count_as_target_evidence") is not False or adj.get("writeups_count_as_target_evidence") is not False:
        raise RuntimeError("V7 standards gap worklist scientific boundary drift")

    rows: list[dict[str, Any]] = []
    by_family: Counter[str] = Counter()
    by_kind: Counter[str] = Counter()
    by_decision: Counter[str] = Counter()
    by_binding: Counter[str] = Counter()
    priority_counts: Counter[int] = Counter()

    for family_row in adj.get("families") or []:
        if not isinstance(family_row, Mapping):
            continue
        family = text(family_row.get("family"))
        mapping_required = family_row.get("literal_family_adjudication_required") is True
        for variant in family_row.get("variants") or []:
            if not isinstance(variant, Mapping) or variant.get("accepted_for_v7") is True:
                continue
            case_kind = text(variant.get("case_kind"))
            literal = variant.get("literal_source_layer") if isinstance(variant.get("literal_source_layer"), Mapping) else {}
            source = variant.get("source_material") if isinstance(variant.get("source_material"), Mapping) else {}
            standards = variant.get("standards_rubric_layer") if isinstance(variant.get("standards_rubric_layer"), Mapping) else {}
            priority = _priority(case_kind=case_kind, family_mapping_required=mapping_required)
            row = {
                "priority": priority,
                "family": family,
                "capture_id": variant.get("capture_id"),
                "case_kind": case_kind,
                "decision": variant.get("decision"),
                "reason": variant.get("reason"),
                "family_mapping_required": mapping_required,
                "missing_requirements": _missing_requirements(case_kind, literal),
                "current_literal_state": {
                    "family_source_aligned": literal.get("family_source_aligned"),
                    "identity_hits": literal.get("identity_hits") or [],
                    "surface_hits": literal.get("surface_hits") or [],
                    "condition_hits": literal.get("condition_hits") or [],
                    "blocking_control_hits": literal.get("blocking_control_hits") or [],
                    "override_hits": literal.get("override_hits") or [],
                    "confounder_hits": literal.get("confounder_hits") or [],
                    "eligible_source_token_count": literal.get("eligible_source_token_count"),
                },
                "source_binding": {
                    "artifact": source.get("artifact"),
                    "artifact_sha256": source.get("artifact_sha256"),
                    "binding_mode": source.get("binding_mode"),
                    "matched_row_count": source.get("matched_row_count"),
                    "resolution_stage": source.get("resolution_stage"),
                },
                "standards_rubric": {
                    "principle": standards.get("principle"),
                    "wstg_ids": standards.get("wstg_ids") or [],
                    "owasp_ids": standards.get("owasp_ids") or [],
                    "cwe_ids": standards.get("cwe_ids") or [],
                    "counts_as_target_evidence": False,
                },
                "acquisition_seeds": _seed_terms(family, case_kind),
                "engine_output_allowed_as_evidence": False,
                "standards_count_as_target_evidence": False,
                "writeups_count_as_target_evidence": False,
            }
            rows.append(row)
            by_family[family] += 1
            by_kind[case_kind] += 1
            by_decision[text(variant.get("decision"))] += 1
            by_binding[text(source.get("binding_mode")) or "unknown"] += 1
            priority_counts[priority] += 1

    rows.sort(key=lambda row: (row["priority"], row["family"], row["case_kind"], text(row["capture_id"])))
    if len(rows) != adj.get("unresolved_variant_count"):
        raise RuntimeError("V7 standards gap worklist unresolved count drift")

    result = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_standards_guided_unresolved_acquisition_worklist_unscored",
        "adjudication_sha256": adj.get("adjudication_sha256"),
        "source_assignment_commit": adj.get("source_assignment_commit"),
        "engine_baseline_commit": adj.get("engine_baseline_commit"),
        "unresolved_variant_count": len(rows),
        "by_family": dict(sorted(by_family.items(), key=lambda item: (-item[1], item[0]))),
        "by_case_kind": dict(sorted(by_kind.items())),
        "by_decision": dict(sorted(by_decision.items())),
        "by_binding_mode": dict(sorted(by_binding.items())),
        "by_priority": {str(k): v for k, v in sorted(priority_counts.items())},
        "priority_policy": {
            "0": "positive rows for families requiring explicit family mapping adjudication",
            "1": "other positive rows",
            "2": "secure-negative rows",
            "3": "near-miss rows",
            "4": "sparse/noisy rows",
        },
        "quality_policy": {
            "use_wstg_owasp_cwe_as_rubric": True,
            "use_frozen_writeup_lessons_as_rubric": True,
            "literal_upstream_source_required_for_acceptance": True,
            "lower_threshold_to_force_acceptance": False,
            "fail_closed_on_ambiguity": True,
        },
        "human_review_required": False,
        "human_verified_record_count": 0,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "worklist": rows,
    }
    result["worklist_sha256"] = sha_json({k: v for k, v in result.items() if k != "worklist_sha256"})
    return result


def main() -> int:
    result = build()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {k: v for k, v in result.items() if k != "worklist"}
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
