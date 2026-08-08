from __future__ import annotations

import json
import re
import uuid
from typing import Any, Iterable, Mapping

from core import Database, json_dumps, sha256_text, utc_now

ADMISSION_ENGINE_VERSION = "1.1.0"
ADMISSION_RULE_VERSION = "2026.08.8.5"

# External knowledge informs detection criteria only. It is never counted as target evidence.
KNOWLEDGE_REFERENCES: dict[str, list[dict[str, str]]] = {
    "broken_object_authorization": [
        {
            "source": "OWASP API Security Top 10",
            "ref": "API1:2023 Broken Object Level Authorization",
            "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            "principle": "An object identifier is only the attack surface; object-level authorization must verify that the logged-in identity may perform the requested action on the requested object.",
        },
        {
            "source": "OWASP WSTG",
            "ref": "WSTG-APIT-02 / WSTG-ATHZ-04",
            "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization",
            "principle": "BOLA evidence requires an object reference plus an authorization-boundary comparison; IDs alone do not establish unauthorized access.",
        },
        {
            "source": "MITRE CWE",
            "ref": "CWE-639",
            "url": "https://cwe.mitre.org/data/definitions/639.html",
            "principle": "The weakness requires a user-controlled key to select a record while the authorization decision fails to enforce the caller's entitlement to that record.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "GHSL-2026-029 / Spree",
            "url": "https://securitylab.github.com/advisories/GHSL-2026-029_Spree/",
            "principle": "A real IDOR may involve a valid object key being accepted without a secondary ownership or access guard that should bind the request to the object.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "GHSL-2026-049 / Zammad",
            "url": "https://securitylab.github.com/advisories/GHSL-2026-049_Zammad/",
            "principle": "Fetching an object by ID becomes security-relevant when the resulting operation bypasses the role or group boundary that should authorize access to that object.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "GHSL-2026-044 / Wekan",
            "url": "https://securitylab.github.com/advisories/GHSL-2026-044_Wekan/",
            "principle": "Authorizing a parent object is insufficient when a separately supplied child object identifier is not verified to belong to that parent.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "GHSL-2025-130 / Sentry",
            "url": "https://securitylab.github.com/advisories/GHSL-2025-130_Sentry/",
            "principle": "A tenant or organization context must be bound to the referenced object; a valid scope on one tenant does not authorize an object belonging to another tenant.",
        },
    ],
    "file_upload": [
        {
            "source": "OWASP",
            "ref": "Unrestricted File Upload",
            "url": "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "principle": "Upload risk depends on actual file handling, including file metadata, content, storage, and processing behavior.",
        },
        {
            "source": "MITRE CWE",
            "ref": "CWE-434",
            "url": "https://cwe.mitre.org/data/definitions/434.html",
            "principle": "The weakness concerns a product accepting an uploaded file of a dangerous type without sufficient restriction.",
        },
        {
            "source": "PortSwigger Web Security Academy",
            "ref": "File upload vulnerabilities",
            "url": "https://portswigger.net/web-security/file-upload",
            "principle": "A file-upload surface requires an actual upload capability; generic Content-Type metadata alone is not evidence of an upload function.",
        },
    ],
    "path_traversal": [
        {
            "source": "OWASP",
            "ref": "Path Traversal",
            "url": "https://owasp.org/www-community/attacks/Path_Traversal",
            "principle": "Path traversal requires attacker-influenced path data to affect access to a file or directory outside the intended location.",
        },
        {
            "source": "MITRE CWE",
            "ref": "CWE-22",
            "url": "https://cwe.mitre.org/data/definitions/22.html",
            "principle": "External input must participate in construction of a pathname whose restriction to an intended directory is not properly enforced.",
        },
        {
            "source": "GitHub Security Lab",
            "ref": "CVE-2024-36116 / archive path traversal",
            "url": "https://github.blog/security/vulnerability-research/attacks-on-maven-proxy-repositories/",
            "principle": "Real path-traversal findings connect attacker-controlled archive or filename data to a filesystem write/read operation, rather than relying on path words alone.",
        },
    ],
}

# Admission is intentionally stricter than hypothesis generation. Signals that fail
# admission remain persisted in analysis_hypotheses so recall is preserved.
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


def knowledge_for_family(family: str) -> list[dict[str, str]]:
    return [dict(item) for item in KNOWLEDGE_REFERENCES.get(family, [])]


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
        return {
            "state": "admitted",
            "admitted": True,
            "policy": "existing-family-gate",
            "required_satisfied": [],
            "required_missing": [],
            "independent_sources": len(sources),
            "decisive_signals": sorted(types),
            "blocking_contradictions": [],
            "reason": "No additional family admission policy is defined; existing family-specific reasoning gates remain authoritative.",
            "knowledge_references": knowledge_for_family(family),
        }

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

    return {
        "state": state,
        "admitted": complete,
        "policy": policy.get("label"),
        "required_satisfied": satisfied,
        "required_missing": missing,
        "independent_sources": len(sources),
        "decisive_signals": sorted(decisive),
        "blocking_contradictions": blocking,
        "reason": reason,
        "knowledge_references": knowledge_for_family(family),
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

    assessment = assess_admission(family, support, contradict)
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
    db.execute(
        "UPDATE analysis_hypotheses SET state='promoted',promoted_candidate_id=?,updated_at=? WHERE analysis_id=? AND hypothesis_fingerprint=?",
        (candidate_id, utc_now(), analysis_id, hypothesis_fingerprint_value),
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
    }
