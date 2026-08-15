from __future__ import annotations

"""Build review-only V7 capture drafts from frozen unseen public-source evidence.

The builder never publishes benchmark evidence, never assigns an engine-derived
label, never scores Analysis, and never executes third-party code. Drafts merely
bind each frozen capture requirement to available literal source observations so
a human can adjudicate semantic suitability before any future publication step.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "2.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.drafts.1"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
BOUNDARY = ROOT / "benchmarks/raw/sources/v7_boundary_evidence.json"
SNIPPETS = ROOT / "benchmarks/raw/sources/v7_unseen_source_snippet_candidates.json"
PLAN = ROOT / "benchmarks/raw/sources/v7_literal_capture_plan.json"
DRAFT_ROOT = ROOT / "benchmarks/raw/sources/v7_capture_drafts"
REPORT = ROOT / "benchmarks/raw/sources/v7_capture_drafts_report.json"


def text(value: Any) -> str:
    return str(value or "").strip()


def slug(value: Any) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in text(value).casefold()).strip("-")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def first_source_snippet(pack: Mapping[str, Any], side: str) -> tuple[str, Mapping[str, Any]] | None:
    key = "parent_snippets" if side == "parent" else "fix_snippets"
    for file_row in pack.get("files") or []:
        if not isinstance(file_row, Mapping):
            continue
        for snippet in file_row.get(key) or []:
            if isinstance(snippet, Mapping) and text(snippet.get("text")):
                return text(file_row.get("filename")), snippet
    return None


def first_control(pack: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]] | None:
    for file_row in pack.get("files") or []:
        if not isinstance(file_row, Mapping):
            continue
        for snippet in file_row.get("upstream_test_control_candidates") or []:
            if isinstance(snippet, Mapping) and text(snippet.get("text")):
                return text(file_row.get("filename")), snippet
    return None


def base_draft(
    requirement: Mapping[str, Any],
    source: Mapping[str, Any],
    *,
    capture_reference: str,
    capture_method: str,
    snapshot_role: str,
    payload: Any,
    raw_details: Mapping[str, Any],
    draft_basis: str,
    notes: str,
) -> dict[str, Any]:
    family = text(requirement.get("family"))
    kind = text(requirement.get("case_kind"))
    return {
        "draft_version": VERSION,
        "rule_version": RULE_VERSION,
        "capture_id": requirement.get("capture_id"),
        "family": family,
        "case_kind": kind,
        "source_root": requirement.get("source_root"),
        "source_project": requirement.get("source_project"),
        "required_evidence_path": requirement.get("required_evidence_path"),
        "created_at": now(),
        "capture_reference": capture_reference,
        "capture_method": capture_method,
        "collector": {
            "kind": "v7_engine_unseen_public_source_draft",
            "version": VERSION,
            "third_party_code_executed": False,
            "target_contact_performed": False,
        },
        "source_snapshot": {
            "reference": capture_reference,
            "snapshot_role": snapshot_role,
            "payload": payload,
            "frozen_canonical_snapshot_sha256": source.get("snapshot_sha256"),
        },
        "raw": {
            "method": "UNKNOWN",
            "details": dict(raw_details),
        },
        "draft_adjudication": {
            "basis": draft_basis,
            "notes": notes,
            "semantic_review_required": True,
            "human_adjudication_complete": False,
            "publication_authorized": False,
            "detector_output_used": False,
            "admission_output_used": False,
            "ranking_output_used": False,
            "v6_first_blind_score_used": False,
            "v6_first_blind_case_errors_used": False,
            "corpus_v1_labels_used": False,
            "corpus_v1_evidence_used": False,
            "corpus_v1_scores_used": False,
        },
        "synthetic_fixture_generated": False,
        "cross_variant_mutation_used": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def write_draft(capture: Mapping[str, Any]) -> str:
    path = DRAFT_ROOT / f"{slug(capture['family'])}--{slug(capture['case_kind'])}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(capture, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return path.relative_to(ROOT).as_posix()


def build() -> dict[str, Any]:
    freeze = assert_capture_source_freeze()
    research = json.loads(RESEARCH.read_text())
    boundary = json.loads(BOUNDARY.read_text())
    snippets = json.loads(SNIPPETS.read_text())
    plan = json.loads(PLAN.read_text())

    if research.get("version") != "2.2.0":
        raise RuntimeError("exact-identity V7 research required")
    if research.get("exact_frozen_root_match_count") != 36 or research.get("ghsa_alias_resolution_count") != 0:
        raise RuntimeError("V7 exact GHSA identity freeze required")
    if plan.get("source_assignment_commit") != freeze["source_assignment_commit"]:
        raise RuntimeError("V7 capture plan assignment drift")
    if boundary.get("source_assignment_commit") != freeze["source_assignment_commit"]:
        raise RuntimeError("V7 boundary assignment drift")
    if snippets.get("source_assignment_commit") != freeze["source_assignment_commit"]:
        raise RuntimeError("V7 snippet assignment drift")
    if snippets.get("exact_pair_source_count") != boundary.get("exact_revision_pair_count"):
        raise RuntimeError("V7 exact pair inventory drift")
    for doc in (research, boundary, snippets, plan):
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 pre-scoring contract violated")

    research_by = {
        text(row.get("family")): row
        for row in research.get("entries") or []
        if isinstance(row, Mapping)
    }
    boundary_by = {
        text(row.get("family")): row
        for row in boundary.get("sources") or []
        if isinstance(row, Mapping)
    }
    snippet_by = {
        text(row.get("family")): row
        for row in snippets.get("sources") or []
        if isinstance(row, Mapping)
    }
    requirements = [row for row in plan.get("requirements") or [] if isinstance(row, Mapping)]
    if len(requirements) != 144:
        raise RuntimeError(f"V7 plan must contain 144 requirements, got {len(requirements)}")

    seen_capture_ids: set[str] = set()
    rows: list[dict[str, Any]] = []
    for requirement in requirements:
        family = text(requirement.get("family"))
        kind = text(requirement.get("case_kind"))
        capture_id = text(requirement.get("capture_id"))
        if capture_id in seen_capture_ids:
            raise RuntimeError(f"duplicate capture id: {capture_id}")
        seen_capture_ids.add(capture_id)
        if family not in research_by or family not in boundary_by or family not in snippet_by:
            raise RuntimeError(f"{family}: missing frozen source inventory")

        source = research_by[family]
        bound = boundary_by[family]
        pack = snippet_by[family]
        if text(requirement.get("source_root")) != text(source.get("source_root")):
            raise RuntimeError(f"{family}: source_root drift between plan and research")
        if text(requirement.get("source_project")) != text(source.get("source_project")):
            raise RuntimeError(f"{family}: source_project drift between plan and research")
        if text(requirement.get("source_snapshot_sha256")) != text(source.get("snapshot_sha256")):
            raise RuntimeError(f"{family}: canonical source snapshot drift")

        targeted = bool(requirement.get("family_literal_adjudication_required"))
        capture: dict[str, Any] | None = None
        reason: str | None = None

        if kind == "sparse_noisy":
            canonical_payload = source.get("snapshot_payload") if isinstance(source.get("snapshot_payload"), Mapping) else {}
            versions = []
            for item in bound.get("version_boundaries") or []:
                if isinstance(item, Mapping):
                    versions.append(
                        {
                            "ecosystem": item.get("ecosystem"),
                            "package": item.get("package"),
                            "vulnerable_version_range": item.get("vulnerable_version_range"),
                            "patched_version": item.get("patched_version"),
                        }
                    )
            capture = base_draft(
                requirement,
                source,
                capture_reference=text(source.get("canonical_reference")),
                capture_method="passive_source_snapshot",
                snapshot_role="canonical_source_partial_metadata",
                payload={
                    "ghsa_id": source.get("observed_ghsa_id"),
                    "version_boundaries": versions[:3],
                    "description": canonical_payload.get("description"),
                },
                raw_details={
                    "observation_kind": "partial_public_source_metadata",
                    "version_boundary_count": len(versions),
                },
                draft_basis="source_observation_candidate",
                notes="Partial frozen public-source metadata candidate; deliberately insufficient for positive admission until semantic review.",
            )

        elif kind in {"positive", "secure_negative"}:
            side = "parent" if kind == "positive" else "fix"
            item = first_source_snippet(pack, side)
            if item:
                filename, snippet = item
                revision_sha = text(pack.get("parent_sha" if side == "parent" else "fix_sha"))
                reference = (
                    f"https://github.com/{source.get('source_project')}/blob/{revision_sha}/{filename}"
                    if revision_sha
                    else text(source.get("canonical_reference"))
                )
                observation = (
                    "exact_vulnerable_parent_source_neighborhood"
                    if kind == "positive"
                    else "exact_patched_source_neighborhood"
                )
                capture = base_draft(
                    requirement,
                    source,
                    capture_reference=reference,
                    capture_method="passive_source_snapshot",
                    snapshot_role=(
                        "linked_upstream_parent_candidate"
                        if kind == "positive"
                        else "linked_upstream_fixed_candidate"
                    ),
                    payload={
                        "revision_sha": revision_sha,
                        "source_file": filename,
                        "line_start": snippet.get("line_start"),
                        "line_end": snippet.get("line_end"),
                        "source_excerpt": snippet.get("text"),
                        "source_excerpt_sha256": snippet.get("text_sha256"),
                        "file_sha256": snippet.get("file_sha256"),
                    },
                    raw_details={
                        "observation_kind": observation,
                        "revision_sha": revision_sha,
                        "source_file": filename,
                    },
                    draft_basis="source_observation_candidate" if kind == "positive" else "patched_control_candidate",
                    notes=(
                        "Exact upstream vulnerable-parent source neighborhood candidate; semantic review must confirm it proves the frozen family condition."
                        if kind == "positive"
                        else "Exact upstream fixed-revision source neighborhood candidate; semantic review must confirm the decisive condition is absent."
                    ),
                )
            else:
                reason = f"no exact {side} source snippet available"

        elif kind == "near_miss":
            item = first_control(pack)
            if item:
                filename, snippet = item
                revision_sha = text(pack.get("fix_sha"))
                reference = (
                    f"https://github.com/{source.get('source_project')}/blob/{revision_sha}/{filename}"
                    if revision_sha
                    else text(source.get("canonical_reference"))
                )
                capture = base_draft(
                    requirement,
                    source,
                    capture_reference=reference,
                    capture_method="repository_test_fixture",
                    snapshot_role="upstream_control_candidate",
                    payload={
                        "revision_sha": revision_sha,
                        "source_file": filename,
                        "test_control_excerpt": snippet.get("text"),
                        "test_control_excerpt_sha256": snippet.get("text_sha256"),
                        "control_keyword_match": snippet.get("control_keyword_match"),
                    },
                    raw_details={
                        "observation_kind": "upstream_control_test_candidate",
                        "revision_sha": revision_sha,
                        "source_file": filename,
                    },
                    draft_basis="repository_test_control_candidate",
                    notes="Independent upstream control-like test excerpt candidate; semantic review must verify it is a genuine confounder and not a positive condition.",
                )
            else:
                reason = "no upstream control-like test snippet available"
        else:
            reason = f"unsupported frozen case kind: {kind}"

        if capture is not None:
            capture["draft_sha256"] = sha_json(capture)
            draft_path = write_draft(capture)
            if targeted:
                status = "blocked_family_literal_adjudication"
                block_reason = "independent literal family confirmation required before any variant can be published"
            else:
                status = "draft_ready_for_human_semantic_review"
                block_reason = None
            rows.append(
                {
                    "capture_id": capture_id,
                    "family": family,
                    "case_kind": kind,
                    "status": status,
                    "draft_path": draft_path,
                    "draft_sha256": capture["draft_sha256"],
                    "block_reason": block_reason,
                    "publication_authorized": False,
                }
            )
        else:
            rows.append(
                {
                    "capture_id": capture_id,
                    "family": family,
                    "case_kind": kind,
                    "status": "blocked_missing_literal_source",
                    "draft_path": None,
                    "draft_sha256": None,
                    "block_reason": reason,
                    "publication_authorized": False,
                }
            )

    status_counts: dict[str, int] = {}
    kind_counts: dict[str, dict[str, int]] = {}
    for row in rows:
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
        kind = row["case_kind"]
        kind_counts.setdefault(kind, {})[row["status"]] = kind_counts.setdefault(kind, {}).get(row["status"], 0) + 1

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_capture_draft_build_unscored",
        "planned_count": 144,
        "draft_count": sum(bool(row["draft_path"]) for row in rows),
        "missing_literal_source_count": sum(row["status"] == "blocked_missing_literal_source" for row in rows),
        "targeted_family_blocked_count": sum(row["status"] == "blocked_family_literal_adjudication" for row in rows),
        "ready_for_human_semantic_review_count": sum(row["status"] == "draft_ready_for_human_semantic_review" for row in rows),
        "status_counts": status_counts,
        "case_kind_status_counts": kind_counts,
        "rows": rows,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
        "publication_authorized": False,
        "evidence_published": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "third_party_code_executed": False,
        "target_contact_performed": False,
    }
    return report


def main() -> int:
    report = build()
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "planned_count",
                    "draft_count",
                    "missing_literal_source_count",
                    "targeted_family_blocked_count",
                    "ready_for_human_semantic_review_count",
                    "status_counts",
                    "case_kind_status_counts",
                    "evidence_published",
                    "scoring_executed",
                    "first_blind_consumed",
                )
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
