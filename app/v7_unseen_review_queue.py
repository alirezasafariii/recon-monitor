from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.review.queue.1"
DRAFT_REPORT = ROOT / "benchmarks/raw/sources/v7_capture_drafts_report.json"
SNIPPET_REPORT = ROOT / "benchmarks/raw/sources/v7_unseen_source_snippet_candidates_report.json"
PLAN = ROOT / "benchmarks/raw/sources/v7_literal_capture_plan.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_semantic_review_queue.json"

KINDS = ("positive", "near_miss", "secure_negative", "sparse_noisy")


def text(value: Any) -> str:
    return str(value or "").strip()


def main() -> int:
    freeze = assert_capture_source_freeze()
    drafts = json.loads(DRAFT_REPORT.read_text())
    snippets = json.loads(SNIPPET_REPORT.read_text())
    plan = json.loads(PLAN.read_text())
    for doc in (drafts, snippets, plan):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 review queue input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 review queue requires pre-scoring inputs")
    if drafts.get("planned_count") != 144 or len(drafts.get("rows") or []) != 144:
        raise RuntimeError("V7 draft report must cover all 144 requirements")
    if drafts.get("publication_authorized") is not False or drafts.get("evidence_published") is not False:
        raise RuntimeError("V7 drafts must remain unpublished")

    targeted = set(plan.get("literal_adjudication_required_families") or [])
    rows = [r for r in drafts.get("rows") or [] if isinstance(r, Mapping)]
    by_family: dict[str, dict[str, Mapping[str, Any]]] = {}
    for row in rows:
        family = text(row.get("family"))
        kind = text(row.get("case_kind"))
        if kind not in KINDS:
            raise RuntimeError(f"{family}: unexpected case kind {kind}")
        by_family.setdefault(family, {})[kind] = row
    if len(by_family) != 36 or any(set(v) != set(KINDS) for v in by_family.values()):
        raise RuntimeError("V7 review queue family/variant coverage drift")

    families = []
    for family in sorted(by_family):
        variants = by_family[family]
        statuses = {kind: text(variants[kind].get("status")) for kind in KINDS}
        missing = [kind for kind in KINDS if statuses[kind] == "blocked_missing_literal_source"]
        reviewable = [kind for kind in KINDS if statuses[kind] == "draft_ready_for_human_semantic_review"]
        family_blocked = [kind for kind in KINDS if statuses[kind] == "blocked_family_literal_adjudication"]
        blockers = []
        if family in targeted:
            blockers.append("independent_literal_family_adjudication")
        if missing:
            blockers.append("missing_literal_source:" + ",".join(missing))
        if not blockers and reviewable:
            next_action = "human_semantic_review"
            priority = 1
        elif family in targeted and not missing:
            next_action = "independent_family_adjudication_then_human_semantic_review"
            priority = 1
        elif reviewable or family_blocked:
            next_action = "acquire_missing_literal_sources_then_review"
            priority = 2
        else:
            next_action = "acquire_literal_sources"
            priority = 3
        families.append(
            {
                "family": family,
                "literal_family_adjudication_required": family in targeted,
                "variant_status": statuses,
                "reviewable_variants": reviewable,
                "family_blocked_variants": family_blocked,
                "missing_variants": missing,
                "draft_coverage_count": 4 - len(missing),
                "blockers": blockers,
                "next_action": next_action,
                "priority": priority,
            }
        )

    action_counts = Counter(x["next_action"] for x in families)
    output = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_semantic_review_queue_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "family_count": 36,
        "variant_count": 144,
        "draft_count": drafts["draft_count"],
        "ready_for_human_semantic_review_count": drafts["ready_for_human_semantic_review_count"],
        "targeted_family_blocked_count": drafts["targeted_family_blocked_count"],
        "missing_literal_source_count": drafts["missing_literal_source_count"],
        "family_action_counts": dict(sorted(action_counts.items())),
        "families": families,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
        "human_adjudication_performed": False,
        "publication_authorized": False,
        "evidence_published": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }
    OUTPUT.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: output[k] for k in ("family_count", "variant_count", "draft_count", "ready_for_human_semantic_review_count", "targeted_family_blocked_count", "missing_literal_source_count", "family_action_counts", "scoring_executed", "first_blind_consumed")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
