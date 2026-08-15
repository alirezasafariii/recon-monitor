from __future__ import annotations

"""Map the 18 residual V7 gaps to sixth-pass explicit-release/tree candidates.

Structural candidate availability is not semantic adjudication. This queue never alters
source assignments, original drafts, evidence publication, scoring, or First Blind state.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.sixth-pass.resolve.1"
RESIDUAL = ROOT / "benchmarks/raw/sources/v7_residual_unresolved_worklist.json"
SIXTH = ROOT / "benchmarks/raw/sources/v7_sixth_pass_reference_tree_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_sixth_pass_resolution_queue.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_sixth_pass_resolution_queue_report.json"


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def release_ref(pair: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "parent_sha": pair.get("parent_sha"),
        "fix_sha": pair.get("fix_sha"),
        "fixed_release_tag": pair.get("fixed_release_tag"),
        "adjacent_older_tag": pair.get("adjacent_older_tag"),
        "source_code_parent_snippet_count": int(pair.get("source_code_parent_snippet_count") or 0),
        "source_code_fix_snippet_count": int(pair.get("source_code_fix_snippet_count") or 0),
        "semantic_role": pair.get("semantic_role"),
    }


def tree_test_ref(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "path": row.get("path"),
        "ref": row.get("ref"),
        "tree_sha": row.get("tree_sha"),
        "path_term_match_count": int(row.get("path_term_match_count") or 0),
        "file_sha256": row.get("file_sha256"),
        "test_case_count": int(row.get("test_case_count") or 0),
        "semantic_role": row.get("semantic_role"),
    }


def main() -> int:
    freeze = assert_capture_source_freeze()
    residual = load(RESIDUAL)
    sixth = load(SIXTH)
    for doc in (residual, sixth):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 sixth-pass resolution input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 sixth-pass resolution requires unconsumed inputs")
    if residual.get("unresolved_item_count") != 18 or residual.get("unresolved_family_count") != 14:
        raise RuntimeError("V7 sixth-pass resolution residual coverage drift")
    if sixth.get("residual_input_count") != 18 or sixth.get("family_result_count") != 14:
        raise RuntimeError("V7 sixth-pass candidate coverage drift")
    if sixth.get("candidate_semantics_adjudicated") is not False or sixth.get("evidence_published") is not False:
        raise RuntimeError("V7 sixth-pass candidates unexpectedly adjudicated/published")

    candidate_by = {
        text(x.get("family")): x
        for x in sixth.get("families") or []
        if isinstance(x, Mapping)
    }
    items = []
    for family_row in residual.get("families") or []:
        if not isinstance(family_row, Mapping):
            continue
        family = text(family_row.get("family"))
        source = candidate_by.get(family)
        if source is None:
            raise RuntimeError(f"{family}: missing sixth-pass candidate row")
        if text(source.get("source_root")) != text(family_row.get("source_root")):
            raise RuntimeError(f"{family}: source_root drift")
        if text(source.get("source_project")).casefold() != text(family_row.get("source_project")).casefold():
            raise RuntimeError(f"{family}: source_project drift")

        release_pairs = [
            x for x in source.get("explicit_release_boundary_candidates") or []
            if isinstance(x, Mapping)
            and int(x.get("source_code_parent_snippet_count") or 0) > 0
            and int(x.get("source_code_fix_snippet_count") or 0) > 0
        ]
        tree_rows = [
            x for x in (source.get("tree_test_acquisition") or {}).get("selected_test_files") or []
            if isinstance(x, Mapping) and int(x.get("test_case_count") or 0) > 0
        ]

        for capture_id, required_path, kind in zip(
            family_row.get("capture_ids") or [],
            family_row.get("required_evidence_paths") or [],
            family_row.get("unresolved_case_kinds") or [],
        ):
            kind = text(kind)
            if kind in {"positive", "secure_negative"}:
                relevant_release = release_pairs
                relevant_tests = []
                required_shape = "sixth_pass_two_sided_explicit_release_boundary"
            elif kind == "near_miss":
                relevant_release = []
                relevant_tests = tree_rows
                required_shape = "sixth_pass_adjacent_same_source_tree_test_candidates"
            else:
                relevant_release = []
                relevant_tests = []
                required_shape = "unsupported_residual_kind"
            count = len(relevant_release) + len(relevant_tests)
            items.append({
                "family": family,
                "case_kind": kind,
                "capture_id": capture_id,
                "source_root": family_row.get("source_root"),
                "source_project": family_row.get("source_project"),
                "required_evidence_path": required_path,
                "required_candidate_shape": required_shape,
                "resolution_status": "candidate_material_available_for_human_review" if count else "still_unresolved_after_sixth_pass",
                "candidate_count": count,
                "release_boundary_refs": [release_ref(x) for x in relevant_release],
                "tree_test_refs": [tree_test_ref(x) for x in relevant_tests],
                "human_semantic_decision": None,
                "human_semantic_notes": None,
                "candidate_semantics_adjudicated": False,
                "source_replacement_used": False,
                "synthetic_fixture_used": False,
                "cross_variant_mutation_used": False,
                "evidence_published": False,
                "publication_authorized": False,
                "scoring_executed": False,
                "first_blind_consumed": False,
            })

    if len(items) != 18:
        raise RuntimeError(f"V7 sixth-pass resolution item coverage {len(items)} != 18")
    available = [x for x in items if x["resolution_status"] == "candidate_material_available_for_human_review"]
    unresolved = [x for x in items if x["resolution_status"] == "still_unresolved_after_sixth_pass"]
    by_kind = {}
    for kind in ("positive", "near_miss", "secure_negative", "sparse_noisy"):
        subset = [x for x in items if x["case_kind"] == kind]
        by_kind[kind] = {
            "sixth_pass_input_count": len(subset),
            "new_candidate_available_count": sum(x["resolution_status"] == "candidate_material_available_for_human_review" for x in subset),
            "still_unresolved_count": sum(x["resolution_status"] == "still_unresolved_after_sixth_pass" for x in subset),
        }

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_sixth_pass_resolution_queue_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sixth_pass_input_count": len(items),
        "new_candidate_available_count": len(available),
        "still_unresolved_count": len(unresolved),
        "families_with_new_candidate_material": len({x["family"] for x in available}),
        "families_still_unresolved": len({x["family"] for x in unresolved}),
        "cumulative_candidate_available_count": 48 + len(available),
        "cumulative_candidate_missing_count": len(unresolved),
        "by_case_kind": by_kind,
        "candidate_semantics_adjudicated": False,
        "human_adjudication_performed": False,
        "evidence_published": False,
        "publication_authorized": False,
        "source_assignment_locked": True,
        "source_replacement_allowed": False,
        "source_replacement_used": False,
        "synthetic_fixture_allowed": False,
        "synthetic_fixture_used": False,
        "cross_variant_mutation_allowed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
    }
    document = dict(report)
    document["items"] = items
    document["resolution_queue_sha256"] = sha_json(items)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
