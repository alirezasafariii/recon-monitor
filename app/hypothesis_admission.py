from __future__ import annotations

import json
import re
import uuid
from typing import Any, Iterable, Mapping

from core import Database, json_dumps, sha256_text, utc_now
from vulnerability_knowledge import (
    KNOWLEDGE_ENGINE_VERSION,
    KNOWLEDGE_RULE_VERSION,
    knowledge_context,
    knowledge_for_family,
)

ADMISSION_ENGINE_VERSION = "1.1.0"
ADMISSION_RULE_VERSION = "2026.08.10.1"

# Admission is intentionally stricter than hypothesis generation. Signals that
# fail admission remain persisted in analysis_hypotheses so recall is preserved.
# External knowledge is NEVER consulted while calculating `complete` below.
FAMILY_ADMISSION_POLICIES: dict[str, dict[str, Any]] = {
    "broken_object_authorization": {
        "required": [
            {"object_identifier", "graphql_identifier"},
            {"object_operation", "graphql_operation"},
            {
                "cross_identity_object_access",
                "cross_tenant_object_access",
                "ownership_mismatch",
                "parent_child_scope_mismatch",
                "authorization_response_differential",
                "object_access_without_secondary_guard",
                "identity_object_relation_conflict",
                "unauthorized_object_response",
            },
        ],
        "min_independent_sources": 2,
        "label": "object reference plus object operation plus object-level authorization-boundary evidence",
        "blocking_contradictions": {
            "ownership_enforcement_observed",
            "cross_context_denied",
            "scope_binding_observed",
            "secondary_guard_enforced",
        },
        "override_signals": {
            "cross_identity_object_access",
            "cross_tenant_object_access",
            "ownership_mismatch",
            "parent_child_scope_mismatch",
            "authorization_response_differential",
            "object_access_without_secondary_guard",
            "identity_object_relation_conflict",
            "unauthorized_object_response",
        },
    },
    "file_upload": {
        "required": [
            {"file_input"},
            {"upload_operation", "import_operation"},
        ],
        "min_independent_sources": 2,
        "label": "actual file input plus an upload/import operation",
    },
    "path_traversal": {
        "required": [
            {"path_parameter", "filename_field", "storage_path"},
            {"file_operation", "download_operation", "import_operation", "archive_operation", "upload_operation"},
        ],
        "min_independent_sources": 2,
        "label": "user-influenced path/filename plus a file-system-relevant operation",
    },
}


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


def _classification_context(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]],
    *,
    endpoint: str = "",
    summary: str = "",
) -> dict[str, Any]:
    """Build non-evidentiary taxonomy/writeup context.

    This function is intentionally called only *after* admission state has been
    calculated.  Its output is persisted for explanation and tagging but never
    changes required groups, independent source counts, blocking contradictions,
    or the admitted boolean.
    """
    return knowledge_context(
        family,
        support,
        contradict,
        endpoint=endpoint,
        summary=summary,
    )


def assess_admission(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in (contradict or [])]
    types = {str(item.get("type") or "") for item in support_items}
    contradiction_types = {str(item.get("type") or "") for item in contradict_items}
    sources = {
        str(item.get("source_group") or item.get("source") or item.get("type") or "unknown")
        for item in support_items
    }
    policy = FAMILY_ADMISSION_POLICIES.get(family)

    if not policy:
        result = {
            "state": "admitted",
            "admitted": True,
            "policy": "existing-family-gate",
            "required_satisfied": [],
            "required_missing": [],
            "independent_sources": len(sources),
            "decisive_signals": sorted(types),
            "blocking_contradictions": [],
            "reason": "No additional family admission policy is defined; existing family-specific reasoning gates remain authoritative.",
        }
        # Classification context is attached only after the target-evidence
        # decision above has already been made.
        result["knowledge_references"] = knowledge_for_family(family)
        result["knowledge_context"] = _classification_context(family, support_items, contradict_items)
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
        reason = f"Retained as a hidden hypothesis because stored target evidence supports enforcement: {', '.join(blocking)}."
    elif satisfied:
        state = "shadow_partial"
        reason = f"Retained as a hidden hypothesis: partial evidence for {policy.get('label')}."
    else:
        state = "shadow_signal"
        reason = f"Retained as a hidden hypothesis: no decisive family-specific evidence yet for {policy.get('label')}."
    if not source_ok:
        reason += f" Independent-source requirement is not yet met ({len(sources)}/{policy.get('min_independent_sources', 1)})."

    # From here downward everything knowledge-related is explanatory only.
    result = {
        "state": state,
        "admitted": complete,
        "policy": policy.get("label"),
        "required_satisfied": satisfied,
        "required_missing": missing,
        "independent_sources": len(sources),
        "decisive_signals": sorted(decisive),
        "blocking_contradictions": blocking,
        "reason": reason,
    }
    result["knowledge_references"] = knowledge_for_family(family)
    result["knowledge_context"] = _classification_context(family, support_items, contradict_items)
    return result


def _persist_classification_tags(
    db: Database,
    *,
    target: str,
    entity_type: str,
    entity_value: str,
    context: Mapping[str, Any],
) -> None:
    """Persist namespaced `near:`/taxonomy tags without claiming a finding."""
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
    for tag in dict.fromkeys(tags):
        db.execute(
            "INSERT OR IGNORE INTO entity_tags(target,entity_type,entity_value,tag,created_at) VALUES(?,?,?,?,?)",
            (target, entity_type, entity_value, tag, utc_now()),
        )


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

    assessment = assess_admission(family, support, contradict)
    # Rebuild retrieval with endpoint/summary context. This remains non-evidentiary.
    assessment["knowledge_context"] = _classification_context(
        family,
        support,
        contradict,
        endpoint=endpoint,
        summary=summary,
    )
    assessment["knowledge_engine_version"] = KNOWLEDGE_ENGINE_VERSION
    assessment["knowledge_rule_version"] = KNOWLEDGE_RULE_VERSION

    state = "promoted" if promoted_candidate_id else assessment["state"]
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
        "knowledge_engine_version": KNOWLEDGE_ENGINE_VERSION,
        "knowledge_rule_version": KNOWLEDGE_RULE_VERSION,
    }
