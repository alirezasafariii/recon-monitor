from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.review.packets.1"
QUEUE = ROOT / "benchmarks/raw/sources/v7_semantic_review_queue.json"
DRAFT_REPORT = ROOT / "benchmarks/raw/sources/v7_capture_drafts_report.json"
LABEL_SCHEMA = ROOT / "benchmarks/raw/sources/v7_literal_label_schema.json"
PLAN = ROOT / "benchmarks/raw/sources/v7_literal_capture_plan.json"
BOUNDARY = ROOT / "benchmarks/raw/sources/v7_boundary_evidence.json"
SNIPPETS = ROOT / "benchmarks/raw/sources/v7_unseen_source_snippet_candidates.json"
PACKETS = ROOT / "benchmarks/raw/sources/v7_semantic_review_packets.json"
WORKLIST = ROOT / "benchmarks/raw/sources/v7_missing_literal_source_worklist.json"
KINDS = ("positive", "near_miss", "secure_negative", "sparse_noisy")


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def main() -> int:
    freeze = assert_capture_source_freeze()
    queue = load(QUEUE)
    drafts = load(DRAFT_REPORT)
    schema = load(LABEL_SCHEMA)
    plan = load(PLAN)
    boundary = load(BOUNDARY)
    snippets = load(SNIPPETS)

    for doc in (queue, drafts, plan, boundary, snippets):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 review packet input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 review packets require unconsumed pre-scoring inputs")
    if queue.get("human_adjudication_performed") is not False:
        raise RuntimeError("review queue unexpectedly claims human adjudication")
    if drafts.get("evidence_published") is not False or drafts.get("publication_authorized") is not False:
        raise RuntimeError("review packets require unpublished drafts")
    if plan.get("required_capture_count") != 144:
        raise RuntimeError("V7 plan coverage drift")

    queue_by = {text(x.get("family")): x for x in queue.get("families") or [] if isinstance(x, Mapping)}
    draft_rows = [x for x in drafts.get("rows") or [] if isinstance(x, Mapping)]
    draft_by = {(text(x.get("family")), text(x.get("case_kind"))): x for x in draft_rows}
    requirements = [x for x in plan.get("requirements") or [] if isinstance(x, Mapping)]
    req_by = {(text(x.get("family")), text(x.get("case_kind"))): x for x in requirements}
    boundary_by = {text(x.get("family")): x for x in boundary.get("sources") or [] if isinstance(x, Mapping)}
    snippet_by = {text(x.get("family")): x for x in snippets.get("sources") or [] if isinstance(x, Mapping)}
    schema_families = schema.get("families") if isinstance(schema.get("families"), Mapping) else {}

    if len(queue_by) != 36 or len(draft_by) != 144 or len(req_by) != 144:
        raise RuntimeError("V7 review packet coverage drift")

    packets = []
    work_items = []
    for family in sorted(queue_by):
        q = queue_by[family]
        family_schema = schema_families.get(family) if isinstance(schema_families.get(family), Mapping) else {}
        bound = boundary_by.get(family, {})
        snippet = snippet_by.get(family, {})
        variants = []
        for kind in KINDS:
            row = draft_by[(family, kind)]
            req = req_by[(family, kind)]
            draft_path = text(row.get("draft_path"))
            draft_doc: dict[str, Any] | None = None
            if draft_path:
                path = ROOT / draft_path
                if not path.exists():
                    raise RuntimeError(f"{family}/{kind}: referenced draft is missing")
                loaded = json.loads(path.read_text())
                if not isinstance(loaded, dict):
                    raise RuntimeError(f"{family}/{kind}: draft must be object")
                draft_doc = loaded
                if draft_doc.get("scoring_executed") is not False or draft_doc.get("first_blind_consumed") is not False:
                    raise RuntimeError(f"{family}/{kind}: draft consumed scoring state")
                if draft_doc.get("draft_adjudication", {}).get("publication_authorized") is not False:
                    raise RuntimeError(f"{family}/{kind}: draft publication unexpectedly authorized")

            variants.append(
                {
                    "case_kind": kind,
                    "status": row.get("status"),
                    "capture_id": row.get("capture_id"),
                    "required_evidence_path": req.get("required_evidence_path"),
                    "variant_purpose": req.get("variant_purpose"),
                    "draft_path": row.get("draft_path"),
                    "draft_sha256": row.get("draft_sha256"),
                    "capture_reference": draft_doc.get("capture_reference") if draft_doc else None,
                    "snapshot_role": (draft_doc.get("source_snapshot") or {}).get("snapshot_role") if draft_doc else None,
                    "observation_kind": (draft_doc.get("raw") or {}).get("details", {}).get("observation_kind") if draft_doc else None,
                    "block_reason": row.get("block_reason"),
                    "human_semantic_decision": None,
                    "human_semantic_notes": None,
                }
            )

            if row.get("status") == "blocked_missing_literal_source":
                work_items.append(
                    {
                        "family": family,
                        "case_kind": kind,
                        "capture_id": row.get("capture_id"),
                        "source_root": req.get("source_root"),
                        "source_project": req.get("source_project"),
                        "canonical_source_reference": req.get("canonical_source_reference"),
                        "required_evidence_path": req.get("required_evidence_path"),
                        "variant_purpose": req.get("variant_purpose"),
                        "missing_reason": row.get("block_reason"),
                        "exact_revision_pair_available": bool(bound.get("exact_revision_pair_available")),
                        "candidate_fix_commit": bound.get("candidate_fix_commit"),
                        "candidate_parent_commit": bound.get("candidate_parent_commit"),
                        "version_boundary_count": len(bound.get("version_boundaries") or []),
                        "changed_test_reference_count": len(bound.get("changed_test_references") or []),
                        "existing_parent_snippet_count": int(snippet.get("parent_snippet_count") or 0),
                        "existing_fix_snippet_count": int(snippet.get("fix_snippet_count") or 0),
                        "existing_test_control_candidate_count": int(snippet.get("test_control_candidate_count") or 0),
                        "source_replacement_allowed": False,
                        "synthetic_fixture_allowed": False,
                        "cross_variant_mutation_allowed": False,
                        "scoring_allowed": False,
                        "first_blind_consumption_allowed": False,
                        "recommended_acquisition": (
                            "search_same_frozen_project_for_upstream_regression_or_control_evidence"
                            if kind == "near_miss"
                            else "resolve_same_frozen_source_to_exact_revision_or_upstream_literal_observation"
                        ),
                    }
                )

        packets.append(
            {
                "family": family,
                "source_root": req_by[(family, "positive")].get("source_root"),
                "source_project": req_by[(family, "positive")].get("source_project"),
                "literal_family_adjudication_required": q.get("literal_family_adjudication_required"),
                "next_action": q.get("next_action"),
                "priority": q.get("priority"),
                "condition_signals_vocabulary": list(family_schema.get("condition_signals") or []),
                "blocking_controls_vocabulary": list(family_schema.get("blocking_controls") or []),
                "override_signals_vocabulary": list(family_schema.get("override_signals") or []),
                "schema_role": family_schema.get("schema_role"),
                "review_instruction": "Compare each draft only against frozen source evidence and the vocabulary below. Do not use Analysis output as evidence. Record a human decision separately; this packet does not adjudicate.",
                "variants": variants,
                "family_adjudication_decision": None,
                "family_adjudication_notes": None,
            }
        )

    packet_doc = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_human_review_packets_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "family_count": 36,
        "variant_count": 144,
        "packet_count": len(packets),
        "packets": packets,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
        "human_adjudication_performed": False,
        "publication_authorized": False,
        "evidence_published": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }
    work_doc = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_missing_literal_source_worklist_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "work_item_count": len(work_items),
        "families_with_missing_items": len({x["family"] for x in work_items}),
        "items": work_items,
        "source_assignment_locked": True,
        "source_replacement_allowed": False,
        "synthetic_fixture_allowed": False,
        "cross_variant_mutation_allowed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
        "human_adjudication_performed": False,
        "publication_authorized": False,
        "evidence_published": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }
    if work_doc["work_item_count"] != drafts.get("missing_literal_source_count"):
        raise RuntimeError("missing-source worklist count drift")
    if work_doc["families_with_missing_items"] != queue.get("family_action_counts", {}).get("acquire_missing_literal_sources_then_review"):
        raise RuntimeError("missing-source family count drift")

    PACKETS.write_text(json.dumps(packet_doc, indent=2, sort_keys=True) + "\n")
    WORKLIST.write_text(json.dumps(work_doc, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "packet_count": packet_doc["packet_count"],
        "variant_count": packet_doc["variant_count"],
        "work_item_count": work_doc["work_item_count"],
        "families_with_missing_items": work_doc["families_with_missing_items"],
        "human_adjudication_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
