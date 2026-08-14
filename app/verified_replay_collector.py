from __future__ import annotations

"""Offline collector for analyst-reviewed replay drafts.

The collector reads existing Investigation decisions and stored Potential Finding
metadata only. It never contacts a target and never changes Analysis, admission,
confirmation, or calibration activation. Evidence-quality dimensions remain an
explicit reviewer step before a draft can satisfy the verified replay contract.
"""

import hashlib
import json
from typing import Any, Mapping

from family_reasoning import FAMILY_ORDER
from meta_ranker import rank_bug_proximity
from verified_replay_contract import (
    EVIDENCE_QUALITY_DIMENSIONS,
    validate_verified_replay_record,
)
from vulnerability_knowledge import rank_families, retrieve_writeups

VERIFIED_REPLAY_COLLECTOR_VERSION = "1.0.0"
VERIFIED_REPLAY_COLLECTOR_RULE_VERSION = "2026.08.14.1"
DECISIVE_REVIEW_DECISIONS = frozenset({"confirmed_by_analyst", "rejected"})
NON_HUMAN_ACTORS = frozenset({"", "system", "automation", "autopilot", "investigation-preview"})
CANONICAL_FAMILIES = frozenset(str(family) for family in FAMILY_ORDER)


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return default


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _evidence_snapshot_id(candidate: Mapping[str, Any]) -> str:
    """Hash evidence state only; the analyst label is deliberately excluded."""

    material = {
        "candidate_fingerprint": str(candidate.get("candidate_fingerprint") or ""),
        "analysis_id": str(candidate.get("analysis_id") or ""),
        "source_run_id": str(candidate.get("source_run_id") or ""),
        "family": str(candidate.get("bug_family") or ""),
        "variant": str(candidate.get("bug_variant") or ""),
        "endpoint": str(candidate.get("endpoint") or ""),
        "likelihood_score": int(candidate.get("likelihood_score") or 0),
        "evidence_strength": int(candidate.get("evidence_strength") or 0),
        "evidence_coverage": int(candidate.get("evidence_coverage") or 0),
        "support": _loads(candidate.get("supporting_evidence_json"), []),
        "contradict": _loads(candidate.get("contradicting_evidence_json"), []),
        "missing": _loads(candidate.get("missing_evidence_json"), []),
        "rule_ids": _loads(candidate.get("rule_ids_json"), []),
    }
    digest = hashlib.sha256(_stable_json(material).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _rank_snapshot(candidate: Mapping[str, Any]) -> dict[str, int]:
    family = str(candidate.get("bug_family") or "")
    endpoint = str(candidate.get("endpoint") or "")
    summary = str(candidate.get("summary") or "")
    support = [dict(item) for item in _loads(candidate.get("supporting_evidence_json"), []) if isinstance(item, Mapping)]
    contradict = [dict(item) for item in _loads(candidate.get("contradicting_evidence_json"), []) if isinstance(item, Mapping)]
    family_rankings = rank_families(support, contradict, endpoint=endpoint, summary=summary, limit=100)
    writeups = retrieve_writeups(
        support,
        contradict,
        endpoint=endpoint,
        summary=summary,
        family=family,
        limit=5,
    )
    ranked = rank_bug_proximity(support, contradict, family_rankings, writeups, limit=100)
    matched = next(
        (item for item in ranked.get("rankings", []) if str(item.get("family") or "") == family),
        {},
    )
    return {
        "decision_readiness_score": max(0, min(100, int(matched.get("decision_readiness_score") or 0))),
        "bug_proximity_score": max(0, min(100, int(matched.get("bug_proximity_score") or 0))),
        "target_evidence_confidence": max(0, min(100, int(matched.get("target_evidence_confidence") or 0))),
    }


def _latest_decisive_events(db: Any, *, limit: int) -> list[dict[str, Any]]:
    rows = [
        dict(row)
        for row in db.all(
            "SELECT case_id,actor,details_json,created_at FROM security_case_events "
            "WHERE event_type='investigation_cluster_decision' ORDER BY created_at ASC"
        )
    ]
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        details = _loads(row.get("details_json"), {})
        decision = str(details.get("decision") or "") if isinstance(details, Mapping) else ""
        actor = str(row.get("actor") or "").strip()
        if decision not in DECISIVE_REVIEW_DECISIONS:
            continue
        if actor.lower() in NON_HUMAN_ACTORS:
            continue
        row["decision"] = decision
        row["primary_family"] = str(details.get("primary_family") or "") if isinstance(details, Mapping) else ""
        latest[str(row.get("case_id") or "")] = row
    ordered = sorted(latest.values(), key=lambda row: str(row.get("created_at") or ""), reverse=True)
    return ordered[: max(1, int(limit))]


def _candidate_rows(db: Any, case_id: str, family: str, decision: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in db.all(
            "SELECT bc.* FROM security_case_members m JOIN bug_candidates bc ON bc.candidate_id=m.member_id "
            "WHERE m.case_id=? AND m.member_type='candidate' AND bc.bug_family=? AND bc.analyst_decision=? "
            "ORDER BY bc.investigation_value DESC,bc.priority_score DESC",
            (case_id, family, decision),
        )
    ]


def collect_verified_replay_drafts(db: Any, *, limit: int = 1000) -> dict[str, Any]:
    """Collect auditable review drafts from existing analyst decisions."""

    drafts: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    seen_snapshots: set[str] = set()

    for event in _latest_decisive_events(db, limit=limit):
        case_id = str(event.get("case_id") or "")
        case = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
        if not case:
            skipped.append({"case_id": case_id, "reason": "missing_case"})
            continue
        case_row = dict(case)
        family = str(event.get("primary_family") or case_row.get("primary_family") or "").strip()
        if family not in CANONICAL_FAMILIES:
            skipped.append({"case_id": case_id, "family": family, "reason": "unknown_family"})
            continue
        decision = str(event.get("decision") or "")
        candidates = _candidate_rows(db, case_id, family, decision)
        if not candidates:
            skipped.append({"case_id": case_id, "family": family, "reason": "no_matching_reviewed_candidate"})
            continue

        for candidate in candidates:
            snapshot_id = _evidence_snapshot_id(candidate)
            if snapshot_id in seen_snapshots:
                skipped.append({"case_id": case_id, "family": family, "reason": "duplicate_evidence_snapshot"})
                continue
            seen_snapshots.add(snapshot_id)
            support = [dict(item) for item in _loads(candidate.get("supporting_evidence_json"), []) if isinstance(item, Mapping)]
            contradict = [dict(item) for item in _loads(candidate.get("contradicting_evidence_json"), []) if isinstance(item, Mapping)]
            scores = _rank_snapshot(candidate)
            candidate_id = str(candidate.get("candidate_id") or "")
            draft = {
                "id": f"review:{case_id}:{candidate_id}",
                "family": family,
                "label": decision == "confirmed_by_analyst",
                **scores,
                "signals": [str(item.get("type") or "") for item in support if str(item.get("type") or "").strip()],
                "contradictions": [str(item.get("type") or "") for item in contradict if str(item.get("type") or "").strip()],
                "provenance": "human_verified_replay",
                "human_verified": True,
                "label_source": "investigation_cluster_decision",
                "reviewer_id": str(event.get("actor") or "").strip(),
                "reviewed_at": str(event.get("created_at") or "").strip(),
                "case_origin_id": f"{case_id}:{candidate_id}",
                "evidence_snapshot_id": snapshot_id,
                "evidence_quality": {},
                "review_context": {
                    "case_id": case_id,
                    "candidate_id": candidate_id,
                    "analysis_id": str(candidate.get("analysis_id") or ""),
                    "source_run_id": str(candidate.get("source_run_id") or ""),
                    "endpoint": str(candidate.get("endpoint") or ""),
                    "decision": decision,
                    "analyst_note": str(candidate.get("analyst_note") or ""),
                    "evidence_strength": int(candidate.get("evidence_strength") or 0),
                    "evidence_coverage": int(candidate.get("evidence_coverage") or 0),
                },
                "missing_for_contract": [f"evidence_quality.{name}" for name in EVIDENCE_QUALITY_DIMENSIONS],
            }
            drafts.append(draft)

    positives = sum(1 for row in drafts if bool(row.get("label")))
    return {
        "collector_version": VERIFIED_REPLAY_COLLECTOR_VERSION,
        "rule_version": VERIFIED_REPLAY_COLLECTOR_RULE_VERSION,
        "draft_count": len(drafts),
        "positive_drafts": positives,
        "negative_drafts": len(drafts) - positives,
        "family_count": len({str(row.get("family") or "") for row in drafts}),
        "drafts": drafts,
        "skipped": skipped,
        "safety": {
            "offline_only": True,
            "network_requests": False,
            "changes_analysis_decisions": False,
            "changes_calibration_activation": False,
            "labels_come_from_human_investigation_decisions": True,
            "evidence_snapshot_excludes_label": True,
            "evidence_quality_requires_explicit_review": True,
        },
    }


def finalize_verified_replay_draft(draft: Mapping[str, Any], evidence_quality: Mapping[str, Any]) -> dict[str, Any]:
    """Attach an explicit quality review and run the canonical contract validator."""

    row = dict(draft)
    row.pop("missing_for_contract", None)
    row["evidence_quality"] = dict(evidence_quality)
    return validate_verified_replay_record(row)
