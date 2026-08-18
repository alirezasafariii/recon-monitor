from __future__ import annotations

import json
import re
import time
import uuid
from collections import defaultdict
from typing import Any, Iterable, Mapping

from core import Database, json_dumps, sha256_text, utc_now
from correlation_engine import (
    CORRELATION_ENGINE_VERSION,
    CORRELATION_RULE_VERSION,
    build_correlation_context,
)
from family_reasoning import (
    FAMILY_REASONING_RULE_VERSION,
    FAMILY_REASONING_VERSION,
    admission_policy_map,
)
from family_evidence_scope import scope_family_evidence
from family_specs.registry import get_detection_spec
from family_specs.taxonomy_attribution import evaluate_taxonomy_attribution
from researcher_logic import researcher_logic_for_family
from meta_ranker import META_RANKER_RULE_VERSION, META_RANKER_VERSION, rank_bug_proximity
from vulnerability_knowledge import (
    KNOWLEDGE_ENGINE_VERSION,
    KNOWLEDGE_RULE_VERSION,
    knowledge_context,
    knowledge_for_family,
    retrieve_writeups,
)

ADMISSION_ENGINE_VERSION = "2.1.0"
ADMISSION_RULE_VERSION = "2026.08.16.1"

# Admission is intentionally stricter than hypothesis generation. Signals that
# fail admission remain persisted in analysis_hypotheses so recall is preserved.
# External knowledge, historical priors, correlation and LLM context are NEVER
# consulted while calculating `complete` below. Every known vulnerability family
# now receives its policy from the single Family Reasoning catalog.
FAMILY_ADMISSION_POLICIES: dict[str, dict[str, Any]] = admission_policy_map()


def _taxonomy_attribution(
    family: str,
    *,
    admitted: bool,
    decisive_signals: Iterable[str],
) -> dict[str, Any] | None:
    try:
        spec = get_detection_spec(family)
    except KeyError:
        return None
    return evaluate_taxonomy_attribution(
        spec, admitted=admitted, decisive_signals=decisive_signals
    )


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _merge(items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in items:
        item = dict(raw)
        key = json_dumps(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def hypothesis_fingerprint(target: str, family: str, variant: str, endpoint: str) -> str:
    normalized_endpoint = re.sub(r"\b\d{2,}\b", "{n}", str(endpoint or "").lower())
    normalized_endpoint = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "{uuid}", normalized_endpoint, flags=re.I)
    return sha256_text("|".join([target, family, variant, normalized_endpoint]))


_HISTORICAL_FAMILY_SCORE_CACHE_TTL = 30.0
_HISTORICAL_FAMILY_SCORE_CACHE: dict[
    tuple[int, str],
    tuple[float, dict[str, int]],
] = {}


def _historical_family_scores(db: Database, target: str) -> dict[str, int]:
    # Non-evidentiary analyst-history prior with short read-through cache.
    key = (id(db), str(target))
    now = time.monotonic()

    cached = _HISTORICAL_FAMILY_SCORE_CACHE.get(key)
    if cached is not None:
        created_at, value = cached
        if now - created_at < _HISTORICAL_FAMILY_SCORE_CACHE_TTL:
            return dict(value)

    rows = db.all(
        "SELECT bug_family,analyst_decision,COUNT(*) count "
        "FROM bug_candidates "
        "WHERE target=? AND analyst_decision<>'unreviewed' "
        "GROUP BY bug_family,analyst_decision",
        (target,),
    )

    decision_weight = {
        "confirmed_by_analyst": 100,
        "needs_more_evidence": 70,
        "duplicate": 30,
        "rejected": 5,
        "out_of_scope": 5,
    }

    grouped: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["bug_family"])].append(
            (
                str(row["analyst_decision"]),
                int(row["count"] or 0),
            )
        )

    result: dict[str, int] = {}
    for family, values in grouped.items():
        reviewed = sum(count for _, count in values)
        if reviewed <= 0:
            continue

        weighted = (
            sum(
                decision_weight.get(decision, 50) * count
                for decision, count in values
            )
            / reviewed
        )

        reliability = min(1.0, reviewed / 8.0)

        result[family] = max(
            0,
            min(
                100,
                int(round(50 + (weighted - 50) * reliability)),
            ),
        )

    _HISTORICAL_FAMILY_SCORE_CACHE[key] = (
        now,
        dict(result),
    )

    if len(_HISTORICAL_FAMILY_SCORE_CACHE) > 64:
        oldest_key = min(
            _HISTORICAL_FAMILY_SCORE_CACHE,
            key=lambda item: _HISTORICAL_FAMILY_SCORE_CACHE[item][0],
        )
        if oldest_key != key:
            _HISTORICAL_FAMILY_SCORE_CACHE.pop(oldest_key, None)

    return result


def _classification_context(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]],
    *,
    endpoint: str = "",
    summary: str = "",
    historical_scores: Mapping[str, Any] | None = None,
    correlation_scores: Mapping[str, Any] | None = None,
    llm_advisory_scores: Mapping[str, Any] | None = None,
    admission_by_family: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build non-evidentiary taxonomy/writeup/meta-ranking context.

    This function is intentionally called only *after* admission state has been
    calculated. Its output is persisted for explanation and tagging but never
    changes required groups, independent source counts, blocking contradictions,
    or the admitted boolean.
    """
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in contradict]
    context = knowledge_context(
        family,
        support_items,
        contradict_items,
        endpoint=endpoint,
        summary=summary,
    )
    broader_writeups = retrieve_writeups(
        support_items,
        contradict_items,
        endpoint=endpoint,
        summary=summary,
        family=None,
        limit=50,
    )
    context["meta_ranker"] = rank_bug_proximity(
        support_items,
        contradict_items,
        context.get("family_rankings", []),
        broader_writeups,
        historical_scores=historical_scores,
        correlation_scores=correlation_scores,
        llm_advisory_scores=llm_advisory_scores,
        admission_by_family=admission_by_family,
        limit=3,
    )
    return context


def assess_admission(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    raw_support_items = [dict(item) for item in support]
    raw_contradict_items = [dict(item) for item in (contradict or [])]
    support_scope = scope_family_evidence(
        family, raw_support_items, annotate_unscoped=False, channel="admission"
    )
    contradict_scope = scope_family_evidence(
        family, raw_contradict_items, annotate_unscoped=False, channel="admission"
    )
    support_items = list(support_scope["accepted"])
    contradict_items = list(contradict_scope["accepted"])

    # Only typed, family-compatible target-evidence records participate in
    # admission. Knowledge projections intentionally have no evidence ``type``.
    typed_support_items = [
        item for item in support_items if str(item.get("type") or "").strip()
    ]
    types = {str(item.get("type") or "") for item in typed_support_items}
    contradiction_types = {
        str(item.get("type") or "") for item in contradict_items
        if str(item.get("type") or "").strip()
    }
    sources = {
        str(item.get("source_group") or item.get("source") or item.get("type") or "unknown")
        for item in typed_support_items
    }
    policy = FAMILY_ADMISSION_POLICIES.get(family)
    scope_diagnostics = {
        "version": support_scope["version"],
        "rule_version": support_scope["rule_version"],
        "rejected_cross_family_support": int(support_scope["rejected_count"]),
        "rejected_cross_family_contradictions": int(contradict_scope["rejected_count"]),
    }

    # Unknown families fail closed. Candidate generation should never silently
    # promote a family that has no reviewed evidence contract.
    if not policy:
        result = {
            "state": "shadow_signal",
            "admitted": False,
            "policy": "missing-family-reasoning-policy",
            "required_satisfied": [],
            "required_missing": [["family reasoning policy"]],
            "independent_sources": len(sources),
            "decisive_signals": [],
            "blocking_contradictions": [],
            "confirmation_required": [],
            "validation_level": "offline",
            "reason": "Retained as a hidden hypothesis because no reviewed Family Reasoning policy exists for this family.",
            "family_reasoning_version": FAMILY_REASONING_VERSION,
            "family_reasoning_rule_version": FAMILY_REASONING_RULE_VERSION,
            "evidence_scope": scope_diagnostics,
        }
        taxonomy = _taxonomy_attribution(
            family, admitted=False, decisive_signals=result["decisive_signals"]
        )
        if taxonomy is not None:
            result["taxonomy_attribution"] = taxonomy
        result["knowledge_references"] = knowledge_for_family(family)
        result["knowledge_context"] = _classification_context(
            family,
            support_items,
            contradict_items,
            admission_by_family={family: result},
        )
        return result

    satisfied: list[list[str]] = []
    missing: list[list[str]] = []
    decisive: set[str] = set()
    for group in policy.get("required", []):
        matches = sorted(set(group) & types)
        if matches:
            satisfied.append(matches)
            decisive.update(matches)
        else:
            missing.append(sorted(group))

    source_ok = len(sources) >= int(policy.get("min_independent_sources", 1))
    blocking = sorted(set(policy.get("blocking_contradictions", set())) & contradiction_types)
    override = bool(set(policy.get("override_signals", set())) & types)
    blocked = bool(blocking) and not override
    complete = not missing and source_ok and not blocked

    if complete:
        state = "admitted"
        reason = f"Admission complete: {policy.get('label')}."
    elif blocked:
        state = "shadow_contradicted"
        reason = f"Retained as a hidden hypothesis because stored target evidence supports an enforcing or non-vulnerable interpretation: {', '.join(blocking)}."
    elif satisfied:
        state = "shadow_partial"
        reason = f"Retained as a hidden hypothesis: partial evidence for {policy.get('label')}."
    else:
        state = "shadow_signal"
        reason = f"Retained as a hidden hypothesis: no decisive family-specific evidence yet for {policy.get('label')}."
    if not source_ok:
        reason += f" Independent-source requirement is not yet met ({len(sources)}/{policy.get('min_independent_sources', 1)})."

    result = {
        "state": state,
        "admitted": complete,
        "policy": policy.get("label"),
        "required_satisfied": satisfied,
        "required_missing": missing,
        "independent_sources": len(sources),
        "decisive_signals": sorted(decisive),
        "blocking_contradictions": blocking,
        "confirmation_required": [sorted(group) for group in policy.get("confirmation_required", [])],
        "validation_level": str(policy.get("validation_level") or "offline"),
        "reason": reason,
        "family_reasoning_version": FAMILY_REASONING_VERSION,
        "family_reasoning_rule_version": FAMILY_REASONING_RULE_VERSION,
        "evidence_scope": scope_diagnostics,
    }
    try:
        result["researcher_logic"] = researcher_logic_for_family(family)
    except KeyError:
        pass
    taxonomy = _taxonomy_attribution(
        family, admitted=complete, decisive_signals=decisive
    )
    if taxonomy is not None:
        result["taxonomy_attribution"] = taxonomy
    result["knowledge_references"] = knowledge_for_family(family)
    result["knowledge_context"] = _classification_context(
        family,
        support_items,
        contradict_items,
        admission_by_family={family: result},
    )
    return result


def _persist_classification_tags(
    db: Database,
    *,
    target: str,
    entity_type: str,
    entity_value: str,
    context: Mapping[str, Any],
) -> None:
    """Persist namespaced proximity/taxonomy tags without claiming a finding."""
    tags = [str(value) for value in context.get("tags", []) if str(value).strip()]
    rankings = context.get("family_rankings", [])
    if isinstance(rankings, list):
        for ranking in rankings[:3]:
            if not isinstance(ranking, Mapping):
                continue
            if int(ranking.get("score") or 0) <= 0:
                continue
            family = str(ranking.get("family") or "").strip().replace("_", "-")
            if family:
                tags.append(f"near-family:{family}")
    meta = context.get("meta_ranker", {})
    if isinstance(meta, Mapping):
        primary = meta.get("primary")
        if isinstance(primary, Mapping):
            family = str(primary.get("family") or "").strip().replace("_", "-")
            band = str(primary.get("proximity_band") or "").strip().replace("_", "-")
            priority = str(primary.get("hunt_priority") or "").strip().lower()
            if family:
                tags.append(f"proximity-family:{family}")
            if band:
                tags.append(f"proximity:{band}")
            if priority:
                tags.append(f"hunt-priority:{priority}")
    for tag in dict.fromkeys(tags):
        db.execute(
            "INSERT OR IGNORE INTO entity_tags(target,entity_type,entity_value,tag,created_at) VALUES(?,?,?,?,?)",
            (target, entity_type, entity_value, tag, utc_now()),
        )



def _candidate_auto_state(likelihood_score: Any, evidence_strength: Any) -> str:
    try:
        likelihood = int(likelihood_score or 0)
    except (TypeError, ValueError):
        likelihood = 0
    try:
        strength = int(evidence_strength or 0)
    except (TypeError, ValueError):
        strength = 0
    if likelihood >= 75 and strength >= 60:
        return "strong_candidate"
    if likelihood >= 55:
        return "plausible"
    if likelihood >= 35:
        return "possible"
    return "weak_signal"


def _reconcile_promoted_candidate(
    db: Database,
    *,
    candidate_id: str,
    assessment: Mapping[str, Any],
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]],
    missing: Iterable[str],
) -> dict[str, Any]:
    """Reconcile a historical promotion with the latest canonical admission.

    Automatic admission may be revoked by newly stored target contradictions.
    The candidate remains linked for audit/history, but an unreviewed automatic
    candidate becomes ``needs_revalidation``. Explicit analyst decisions are
    never overwritten by this automatic reconciliation path.
    """
    row = db.one(
        "SELECT candidate_state,analyst_decision,likelihood_score,evidence_strength,"
        "supporting_evidence_json,contradicting_evidence_json,missing_evidence_json "
        "FROM bug_candidates WHERE candidate_id=?",
        (candidate_id,),
    )
    if not row:
        return {
            "status": "candidate_missing",
            "candidate_id": candidate_id,
            "admitted": bool(assessment.get("admitted")),
        }

    current_state = str(row["candidate_state"] or "")
    analyst_decision = str(row["analyst_decision"] or "unreviewed")
    admitted = bool(assessment.get("admitted"))
    merged_support = _merge(
        [*_loads(row["supporting_evidence_json"], []), *[dict(item) for item in support]]
    )
    merged_contradict = _merge(
        [*_loads(row["contradicting_evidence_json"], []), *[dict(item) for item in contradict]]
    )
    merged_missing = list(
        dict.fromkeys(
            [
                *[str(item) for item in _loads(row["missing_evidence_json"], []) if str(item).strip()],
                *[str(item) for item in missing if str(item).strip()],
            ]
        )
    )

    next_state = current_state
    status = "admission_valid" if admitted else "needs_revalidation"
    if admitted:
        if current_state == "needs_revalidation" and analyst_decision in {"unreviewed", "needs_more_evidence"}:
            next_state = _candidate_auto_state(row["likelihood_score"], row["evidence_strength"])
            status = "admission_restored"
    elif analyst_decision == "confirmed_by_analyst":
        next_state = "confirmed_by_analyst"
        status = "analyst_confirmation_preserved"
    elif analyst_decision in {"rejected", "duplicate", "out_of_scope"}:
        status = "analyst_terminal_decision_preserved"
    else:
        next_state = "needs_revalidation"

    if not admitted:
        reason = str(assessment.get("reason") or "").strip()
        if reason:
            marker = f"Canonical admission requires revalidation: {reason}"
            if marker not in merged_missing:
                merged_missing.append(marker)

    db.execute(
        "UPDATE bug_candidates SET candidate_state=?,supporting_evidence_json=?,"
        "contradicting_evidence_json=?,missing_evidence_json=?,updated_at=? WHERE candidate_id=?",
        (
            next_state,
            json_dumps(merged_support),
            json_dumps(merged_contradict),
            json_dumps(merged_missing),
            utc_now(),
            candidate_id,
        ),
    )
    return {
        "status": status,
        "candidate_id": candidate_id,
        "admitted": admitted,
        "candidate_state_before": current_state,
        "candidate_state_after": next_state,
        "analyst_decision": analyst_decision,
        "analyst_decision_preserved": True,
    }

def record_hypothesis(
    db: Database,
    *,
    analysis_id: str,
    source_run_id: str,
    target: str,
    alert_id: int | None,
    asset: str,
    endpoint: str,
    source_ref: str,
    family: str,
    variant: str,
    support: list[dict[str, Any]],
    contradict: list[dict[str, Any]],
    missing: list[str],
    rule_ids: list[str],
    summary: str,
) -> dict[str, Any]:
    fingerprint = hypothesis_fingerprint(target, family, variant, endpoint)
    existing = db.one(
        "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND hypothesis_fingerprint=?",
        (analysis_id, fingerprint),
    )
    first_seen = utc_now()
    seen_count = 1
    promoted_candidate_id = ""
    if existing:
        support = _merge([*_loads(existing["supporting_evidence_json"], []), *support])
        contradict = _merge([*_loads(existing["contradicting_evidence_json"], []), *contradict])
        missing = list(dict.fromkeys([*_loads(existing["missing_evidence_json"], []), *missing]))
        rule_ids = list(dict.fromkeys([*_loads(existing["rule_ids_json"], []), *rule_ids]))
        first_seen = str(existing["first_seen_at"] or first_seen)
        seen_count = int(existing["seen_count"] or 0) + 1
        promoted_candidate_id = str(existing["promoted_candidate_id"] or "")
        alert_id = existing["alert_id"] if existing["alert_id"] is not None else alert_id
        source_ref = str(existing["source_ref"] or source_ref)

    # Persist only evidence that is unscoped legacy data or explicitly belongs
    # to this family. Newly stored evidence is namespaced so later correlation or
    # replay cannot silently rebind it to another vulnerability family.
    persisted_support_scope = scope_family_evidence(
        family, support, annotate_unscoped=True, channel="hypothesis_persistence"
    )
    persisted_contradict_scope = scope_family_evidence(
        family, contradict, annotate_unscoped=True, channel="hypothesis_persistence"
    )
    support = list(persisted_support_scope["accepted"])
    contradict = list(persisted_contradict_scope["accepted"])

    # Admission is fixed first from target evidence only.
    assessment = assess_admission(family, support, contradict)
    assessment.setdefault("evidence_scope", {})["quarantined_at_persistence"] = (
        int(persisted_support_scope["rejected_count"])
        + int(persisted_contradict_scope["rejected_count"])
    )

    historical_scores = _historical_family_scores(db, target)
    correlation_context = build_correlation_context(
        db,
        analysis_id=analysis_id,
        target=target,
        endpoint=endpoint,
        alert_id=alert_id,
        source_ref=source_ref,
    )
    correlation_scores = correlation_context.get("family_scores", {})

    # Rebuild retrieval/ranking with endpoint, summary, historical and
    # cross-surface context only after admission. These remain non-evidentiary.
    assessment["knowledge_context"] = _classification_context(
        family,
        support,
        contradict,
        endpoint=endpoint,
        summary=summary,
        historical_scores=historical_scores,
        correlation_scores=correlation_scores,
        admission_by_family={family: assessment},
    )
    assessment["correlation_context"] = correlation_context
    assessment["knowledge_engine_version"] = KNOWLEDGE_ENGINE_VERSION
    assessment["knowledge_rule_version"] = KNOWLEDGE_RULE_VERSION
    assessment["meta_ranker_version"] = META_RANKER_VERSION
    assessment["meta_ranker_rule_version"] = META_RANKER_RULE_VERSION
    assessment["correlation_engine_version"] = CORRELATION_ENGINE_VERSION
    assessment["correlation_rule_version"] = CORRELATION_RULE_VERSION
    assessment["family_reasoning_version"] = FAMILY_REASONING_VERSION
    assessment["family_reasoning_rule_version"] = FAMILY_REASONING_RULE_VERSION

    if promoted_candidate_id:
        assessment["promotion_reconciliation"] = _reconcile_promoted_candidate(
            db,
            candidate_id=promoted_candidate_id,
            assessment=assessment,
            support=support,
            contradict=contradict,
            missing=missing,
        )
    state = (
        "promoted"
        if promoted_candidate_id and bool(assessment.get("admitted"))
        else assessment["state"]
    )
    hypothesis_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recon-monitor:hypothesis:{analysis_id}:{fingerprint}"))
    now = utc_now()
    db.execute(
        """INSERT OR REPLACE INTO analysis_hypotheses(
        hypothesis_id,hypothesis_fingerprint,analysis_id,source_run_id,alert_id,target,asset,endpoint,source_ref,
        bug_family,bug_variant,state,summary,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,
        decisive_signals_json,admission_json,knowledge_references_json,rule_ids_json,rule_version,seen_count,
        first_seen_at,last_seen_at,promoted_candidate_id,created_at,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            hypothesis_id, fingerprint, analysis_id, source_run_id, alert_id, target, asset, endpoint, source_ref,
            family, variant, state, summary, json_dumps(support), json_dumps(contradict), json_dumps(missing),
            json_dumps(assessment["decisive_signals"]), json_dumps(assessment), json_dumps(assessment["knowledge_references"]),
            json_dumps(rule_ids), ADMISSION_RULE_VERSION, seen_count, first_seen, now, promoted_candidate_id, first_seen, now,
        ),
    )
    _persist_classification_tags(
        db,
        target=target,
        entity_type="analysis_hypothesis",
        entity_value=hypothesis_id,
        context=assessment.get("knowledge_context", {}),
    )
    return {
        "hypothesis_id": hypothesis_id,
        "hypothesis_fingerprint": fingerprint,
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": rule_ids,
        "assessment": assessment,
        "seen_count": seen_count,
    }


def mark_promoted(db: Database, analysis_id: str, hypothesis_fingerprint_value: str, candidate_id: str) -> None:
    row = db.one(
        "SELECT target,admission_json FROM analysis_hypotheses WHERE analysis_id=? AND hypothesis_fingerprint=?",
        (analysis_id, hypothesis_fingerprint_value),
    )
    db.execute(
        "UPDATE analysis_hypotheses SET state='promoted',promoted_candidate_id=?,updated_at=? WHERE analysis_id=? AND hypothesis_fingerprint=?",
        (candidate_id, utc_now(), analysis_id, hypothesis_fingerprint_value),
    )
    if row:
        admission = _loads(row["admission_json"], {})
        context = admission.get("knowledge_context", {}) if isinstance(admission, Mapping) else {}
        if isinstance(context, Mapping):
            _persist_classification_tags(
                db,
                target=str(row["target"]),
                entity_type="candidate",
                entity_value=candidate_id,
                context=context,
            )


def hypothesis_summary(db: Database, analysis_id: str) -> dict[str, Any]:
    rows = db.all(
        "SELECT state,COUNT(*) count FROM analysis_hypotheses WHERE analysis_id=? GROUP BY state ORDER BY state",
        (analysis_id,),
    )
    counts = {str(row["state"]): int(row["count"]) for row in rows}
    return {
        "analysis_id": analysis_id,
        "total": sum(counts.values()),
        "promoted": counts.get("promoted", 0),
        "hidden": sum(value for key, value in counts.items() if key != "promoted"),
        "states": counts,
        "engine_version": ADMISSION_ENGINE_VERSION,
        "rule_version": ADMISSION_RULE_VERSION,
        "family_reasoning_version": FAMILY_REASONING_VERSION,
        "family_reasoning_rule_version": FAMILY_REASONING_RULE_VERSION,
        "knowledge_engine_version": KNOWLEDGE_ENGINE_VERSION,
        "knowledge_rule_version": KNOWLEDGE_RULE_VERSION,
        "meta_ranker_version": META_RANKER_VERSION,
        "meta_ranker_rule_version": META_RANKER_RULE_VERSION,
        "correlation_engine_version": CORRELATION_ENGINE_VERSION,
        "correlation_rule_version": CORRELATION_RULE_VERSION,
    }
