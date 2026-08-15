from __future__ import annotations

"""Generate and validate the independent human-review contract for Fresh Blind V7.

The contract uses three reviewer slots. Each family is assigned to two independent
reviewers; a third reviewer is the tie-breaker if the primary decisions disagree.
No slot is considered human until a real reviewer supplies identity and attestation.
The engine output is explicitly forbidden as review evidence.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.human-review-contract.1"
PACKET = ROOT / "benchmarks/raw/sources/v7_semantic_review_packet_v2.json"
TEMPLATE = ROOT / "benchmarks/raw/sources/v7_human_review_template.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_human_review_template_report.json"
REVIEWER_SLOTS = ("reviewer_a", "reviewer_b", "reviewer_c")
PAIR_CYCLE = (
    ("reviewer_a", "reviewer_b"),
    ("reviewer_b", "reviewer_c"),
    ("reviewer_c", "reviewer_a"),
)
VARIANT_DECISIONS = (
    "accept_candidate_as_variant",
    "reject_candidate",
    "needs_additional_source_material",
)
FAMILY_DECISIONS = (
    "confirm_family_mapping",
    "reject_family_mapping",
    "needs_additional_source_material",
)
ATTESTATION_TEXT = (
    "I personally reviewed the frozen source material assigned to this reviewer slot, "
    "did not use Analysis/engine predictions as evidence, and recorded my own decisions."
)


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


def blank_vote(slot: str) -> dict[str, Any]:
    return {
        "reviewer_slot": slot,
        "reviewer_id": None,
        "reviewed_at": None,
        "decision": None,
        "notes": None,
        "source_material_checked": False,
        "engine_output_used": False,
    }


def build_template() -> dict[str, Any]:
    freeze = assert_capture_source_freeze()
    packet = load(PACKET)
    if packet.get("source_assignment_commit") != freeze["source_assignment_commit"]:
        raise RuntimeError("V7 human review contract packet assignment drift")
    if packet.get("variant_count") != 144 or packet.get("family_count") != 36:
        raise RuntimeError("V7 human review contract packet coverage drift")
    if packet.get("human_review_complete") is not False or packet.get("human_verified_record_count") != 0:
        raise RuntimeError("V7 packet unexpectedly claims human review completion")
    if packet.get("scoring_executed") is not False or packet.get("first_blind_consumed") is not False:
        raise RuntimeError("V7 human review contract requires unconsumed packet")

    families = sorted(
        [p for p in packet.get("packets") or [] if isinstance(p, Mapping)],
        key=lambda p: text(p.get("family")),
    )
    if len(families) != 36:
        raise RuntimeError("V7 human review contract family count drift")

    assignments = []
    reviewer_load = {slot: {"family_count": 0, "variant_count": 0} for slot in REVIEWER_SLOTS}
    for index, family_packet in enumerate(families):
        family = text(family_packet.get("family"))
        primary_slots = PAIR_CYCLE[index % len(PAIR_CYCLE)]
        tie_breaker = next(slot for slot in REVIEWER_SLOTS if slot not in primary_slots)
        variants = []
        for variant in family_packet.get("variants") or []:
            if not isinstance(variant, Mapping):
                continue
            variants.append({
                "capture_id": variant.get("capture_id"),
                "case_kind": variant.get("case_kind"),
                "required_evidence_path": variant.get("required_evidence_path"),
                "review_material": variant.get("review_material"),
                "primary_votes": [blank_vote(slot) for slot in primary_slots],
                "tie_break_vote": blank_vote(tie_breaker),
                "tie_break_required": None,
                "consensus_decision": None,
                "consensus_notes": None,
                "human_verified": False,
            })
        if len(variants) != 4:
            raise RuntimeError(f"{family}: human review contract variant count drift")

        family_review = None
        if family_packet.get("literal_family_adjudication_required") is True:
            family_review = {
                "required": True,
                "primary_votes": [blank_vote(slot) for slot in primary_slots],
                "tie_break_vote": blank_vote(tie_breaker),
                "tie_break_required": None,
                "consensus_decision": None,
                "consensus_notes": None,
                "human_verified": False,
            }

        for slot in primary_slots:
            reviewer_load[slot]["family_count"] += 1
            reviewer_load[slot]["variant_count"] += 4
        assignments.append({
            "family": family,
            "source_root": family_packet.get("source_root"),
            "source_project": family_packet.get("source_project"),
            "literal_family_adjudication_required": bool(family_packet.get("literal_family_adjudication_required")),
            "primary_reviewer_slots": list(primary_slots),
            "tie_breaker_slot": tie_breaker,
            "family_review": family_review,
            "variants": variants,
        })

    if {slot: load["family_count"] for slot, load in reviewer_load.items()} != {
        "reviewer_a": 24,
        "reviewer_b": 24,
        "reviewer_c": 24,
    }:
        raise RuntimeError(f"V7 reviewer family load imbalance: {reviewer_load}")
    if any(load["variant_count"] != 96 for load in reviewer_load.values()):
        raise RuntimeError(f"V7 reviewer variant load imbalance: {reviewer_load}")

    result = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_independent_human_semantic_review_template_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "review_protocol": {
            "required_unique_human_reviewers": 3,
            "primary_reviews_per_family": 2,
            "primary_reviews_per_variant": 2,
            "tie_breaker_required_on_disagreement": True,
            "family_origin_atomic_assignment": True,
            "engine_output_allowed_as_evidence": False,
            "reviewer_attestation_text": ATTESTATION_TEXT,
            "allowed_variant_decisions": list(VARIANT_DECISIONS),
            "allowed_family_decisions": list(FAMILY_DECISIONS),
        },
        "reviewers": {
            slot: {
                "actual_reviewer_id": None,
                "reviewer_display_name": None,
                "reviewer_attestation": None,
                "attested_at": None,
            }
            for slot in REVIEWER_SLOTS
        },
        "reviewer_load": reviewer_load,
        "family_count": 36,
        "variant_count": 144,
        "family_adjudication_required_count": sum(bool(x["literal_family_adjudication_required"]) for x in assignments),
        "assignments": assignments,
        "human_review_started": False,
        "human_review_complete": False,
        "human_verified_record_count": 0,
        "semantic_adjudication_complete": False,
        "evidence_published": False,
        "publication_authorized": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
        "semantic_review_packet_sha256": packet.get("packet_set_sha256"),
    }
    result["template_sha256"] = sha_json({k: v for k, v in result.items() if k != "template_sha256"})
    return result


def validate_structure(doc: Mapping[str, Any], require_complete: bool = False) -> dict[str, Any]:
    freeze = assert_capture_source_freeze()
    if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
        raise RuntimeError("V7 review submission source assignment drift")
    if doc.get("family_count") != 36 or doc.get("variant_count") != 144:
        raise RuntimeError("V7 review submission coverage drift")
    protocol = doc.get("review_protocol") if isinstance(doc.get("review_protocol"), Mapping) else {}
    if protocol.get("engine_output_allowed_as_evidence") is not False:
        raise RuntimeError("V7 review submission allows engine output as evidence")
    if protocol.get("required_unique_human_reviewers") != 3:
        raise RuntimeError("V7 review submission reviewer diversity contract drift")

    reviewers = doc.get("reviewers") if isinstance(doc.get("reviewers"), Mapping) else {}
    if set(reviewers) != set(REVIEWER_SLOTS):
        raise RuntimeError("V7 review submission reviewer slots drift")
    reviewer_ids = []
    if require_complete:
        for slot in REVIEWER_SLOTS:
            meta = reviewers.get(slot) if isinstance(reviewers.get(slot), Mapping) else {}
            reviewer_id = text(meta.get("actual_reviewer_id"))
            if not reviewer_id:
                raise RuntimeError(f"{slot}: actual human reviewer ID missing")
            if meta.get("reviewer_attestation") != ATTESTATION_TEXT:
                raise RuntimeError(f"{slot}: reviewer attestation missing or changed")
            if not text(meta.get("attested_at")):
                raise RuntimeError(f"{slot}: reviewer attested_at missing")
            reviewer_ids.append(reviewer_id.casefold())
        if len(set(reviewer_ids)) != 3:
            raise RuntimeError("V7 review requires three distinct human reviewer IDs")

    assignments = [x for x in doc.get("assignments") or [] if isinstance(x, Mapping)]
    if len(assignments) != 36:
        raise RuntimeError("V7 review submission family assignment count drift")
    capture_ids = []
    accepted_variant_count = 0
    rejected_or_more_source_count = 0
    disagreements = 0

    for family in assignments:
        family_name = text(family.get("family"))
        primary_slots = [text(x) for x in family.get("primary_reviewer_slots") or []]
        tie_slot = text(family.get("tie_breaker_slot"))
        if len(primary_slots) != 2 or len(set(primary_slots)) != 2 or tie_slot in primary_slots:
            raise RuntimeError(f"{family_name}: reviewer assignment malformed")
        family_review = family.get("family_review")
        if family.get("literal_family_adjudication_required") is True:
            if not isinstance(family_review, Mapping):
                raise RuntimeError(f"{family_name}: required family review missing")
            if require_complete:
                _validate_vote_set(family_name + "/family", family_review, primary_slots, tie_slot, FAMILY_DECISIONS)
        elif family_review is not None:
            raise RuntimeError(f"{family_name}: unexpected family review object")

        variants = [x for x in family.get("variants") or [] if isinstance(x, Mapping)]
        if len(variants) != 4:
            raise RuntimeError(f"{family_name}: review variant count drift")
        for variant in variants:
            capture_id = text(variant.get("capture_id"))
            if not capture_id:
                raise RuntimeError(f"{family_name}: empty capture ID")
            capture_ids.append(capture_id)
            if require_complete:
                consensus, disagreed = _validate_vote_set(
                    capture_id,
                    variant,
                    primary_slots,
                    tie_slot,
                    VARIANT_DECISIONS,
                )
                disagreements += int(disagreed)
                if consensus == "accept_candidate_as_variant":
                    accepted_variant_count += 1
                else:
                    rejected_or_more_source_count += 1

    if len(capture_ids) != 144 or len(set(capture_ids)) != 144:
        raise RuntimeError("V7 review submission capture IDs are not exactly 144 unique values")
    return {
        "family_count": 36,
        "variant_count": 144,
        "complete_validation": require_complete,
        "accepted_variant_count": accepted_variant_count,
        "rejected_or_more_source_count": rejected_or_more_source_count,
        "disagreement_count": disagreements,
        "human_review_complete": bool(require_complete and accepted_variant_count == 144),
        "ready_for_evidence_materialization": bool(require_complete and accepted_variant_count == 144),
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def _validate_vote_set(
    label: str,
    review: Mapping[str, Any],
    primary_slots: list[str],
    tie_slot: str,
    allowed_decisions: tuple[str, ...],
) -> tuple[str, bool]:
    votes = [x for x in review.get("primary_votes") or [] if isinstance(x, Mapping)]
    if [text(v.get("reviewer_slot")) for v in votes] != primary_slots:
        raise RuntimeError(f"{label}: primary reviewer slots drift")
    decisions = []
    reviewer_ids = []
    for vote in votes:
        decision = text(vote.get("decision"))
        if decision not in allowed_decisions:
            raise RuntimeError(f"{label}: invalid/missing primary decision {decision!r}")
        if vote.get("source_material_checked") is not True:
            raise RuntimeError(f"{label}: source material was not attested checked")
        if vote.get("engine_output_used") is not False:
            raise RuntimeError(f"{label}: engine output was used in review")
        reviewer_id = text(vote.get("reviewer_id"))
        if not reviewer_id or not text(vote.get("reviewed_at")):
            raise RuntimeError(f"{label}: reviewer identity/time missing")
        decisions.append(decision)
        reviewer_ids.append(reviewer_id.casefold())
    if len(set(reviewer_ids)) != 2:
        raise RuntimeError(f"{label}: two primary votes are not independent reviewers")

    disagreed = decisions[0] != decisions[1]
    if not disagreed:
        consensus = decisions[0]
        if review.get("tie_break_required") not in (False, None):
            raise RuntimeError(f"{label}: tie break marked required despite agreement")
    else:
        if review.get("tie_break_required") is not True:
            raise RuntimeError(f"{label}: disagreement requires tie break")
        tie = review.get("tie_break_vote") if isinstance(review.get("tie_break_vote"), Mapping) else {}
        if text(tie.get("reviewer_slot")) != tie_slot:
            raise RuntimeError(f"{label}: tie-break reviewer slot drift")
        decision = text(tie.get("decision"))
        if decision not in allowed_decisions:
            raise RuntimeError(f"{label}: invalid/missing tie-break decision")
        if tie.get("source_material_checked") is not True or tie.get("engine_output_used") is not False:
            raise RuntimeError(f"{label}: invalid tie-break evidence attestation")
        tie_reviewer_id = text(tie.get("reviewer_id"))
        if not tie_reviewer_id or not text(tie.get("reviewed_at")):
            raise RuntimeError(f"{label}: tie-break reviewer identity/time missing")
        if tie_reviewer_id.casefold() in set(reviewer_ids):
            raise RuntimeError(f"{label}: tie-break reviewer is not independent")
        consensus = decision

    if review.get("consensus_decision") != consensus:
        raise RuntimeError(f"{label}: recorded consensus decision does not match votes")
    if review.get("human_verified") is not True:
        raise RuntimeError(f"{label}: completed review is not marked human_verified")
    return consensus, disagreed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    if args.validate:
        result = validate_structure(load(args.validate), require_complete=args.require_complete)
        print(json.dumps(result, sort_keys=True))
        return 0
    template = build_template()
    TEMPLATE.write_text(json.dumps(template, indent=2, sort_keys=True) + "\n")
    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "family_count": template["family_count"],
        "variant_count": template["variant_count"],
        "family_adjudication_required_count": template["family_adjudication_required_count"],
        "reviewer_load": template["reviewer_load"],
        "required_unique_human_reviewers": 3,
        "primary_reviews_per_variant": 2,
        "tie_breaker_required_on_disagreement": True,
        "human_review_started": False,
        "human_review_complete": False,
        "human_verified_record_count": 0,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": template["engine_baseline_commit"],
        "source_assignment_commit": template["source_assignment_commit"],
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
