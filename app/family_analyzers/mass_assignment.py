from __future__ import annotations

"""Dedicated Mass Assignment / Object Property Authorization analyzer.

The analyzer separates a writable sensitive-property surface from evidence that
the server actually accepts or persists a property the caller is not authorized
to modify. CWE/WSTG/OWASP and public write-up patterns guide reasoning only and
never become target evidence or satisfy admission/confirmation.
"""

import json
import re
from typing import Any, Iterable, Mapping

from core import Database, parse_int
from family_reasoning import FAMILY_REASONING, confirmation_gaps
from family_specs.registry import get_detection_spec

from .base import FamilyAnalyzer, FamilyAnalyzerContext


MASS_ASSIGNMENT_FAMILY_ANALYZER_VERSION = "1.0.0"
MASS_ASSIGNMENT_FAMILY_ANALYZER_RULE_VERSION = "2026.08.10.1"

WRITE_METHODS = {"POST", "PUT", "PATCH"}
SUCCESS_STATUSES = set(range(200, 300))
DENY_STATUSES = {400, 401, 403, 405, 409, 422}

PRIVILEGED_FIELDS = {
    "role", "roles", "isadmin", "is_admin", "admin", "permissions", "permission",
    "privilege", "privileges", "ownerid", "owner_id", "tenantid", "tenant_id",
    "accounttype", "account_type", "status", "verified", "isverified", "is_verified",
    "isstaff", "is_staff", "staff", "groups", "group", "plan", "tier", "credits",
    "balance", "approval", "approved", "moderator", "superuser",
}

MASS_ASSIGNMENT_SPEC = get_detection_spec("mass_assignment")

# Compatibility exports; canonical definitions live in family_specs.
MASS_ASSIGNMENT_TAXONOMY = MASS_ASSIGNMENT_SPEC.taxonomy()
MASS_ASSIGNMENT_METHOD = tuple(step.as_dict() for step in MASS_ASSIGNMENT_SPEC.standard.methodology)
MASS_ASSIGNMENT_FALSE_POSITIVE_CHECKS = tuple(MASS_ASSIGNMENT_SPEC.standard.false_positive_checks)
MASS_ASSIGNMENT_WRITEUP_PATTERNS = tuple(
    {
        "id": item.id,
        "source": item.source,
        "ref": item.ref,
        "url": item.url,
        "relation": item.relation,
        "principle": item.lesson,
        "signals": list(item.signal_hints),
        "counts_as_target_evidence": False,
    }
    for item in MASS_ASSIGNMENT_SPEC.standard.writeups
)

def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def _is_privileged_field(value: Any) -> bool:
    normalized = _normalize(value)
    return bool(normalized) and any(normalized == _normalize(marker) for marker in PRIVILEGED_FIELDS)


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "accepted", "allowed", "applied", "persisted", "changed"}:
        return True
    if text in {"false", "0", "no", "rejected", "denied", "ignored", "blocked"}:
        return False
    return None


def _status(item: Mapping[str, Any]) -> int:
    value = item.get("status_code")
    response = item.get("response")
    if value is None and isinstance(response, Mapping):
        value = response.get("status_code")
    return parse_int(value, 0)


def _scalar(item: Mapping[str, Any], keys: Iterable[str]) -> Any:
    normalized = {_normalize(key): value for key, value in item.items()}
    for key in keys:
        value = normalized.get(_normalize(key))
        if value is not None and str(value).strip() != "":
            return value
    return None


def _field_list(value: Any) -> list[str]:
    decoded = _loads(value, value)
    if isinstance(decoded, Mapping):
        return [str(key) for key, enabled in decoded.items() if _bool(enabled) is not False]
    if isinstance(decoded, (list, tuple, set)):
        return [str(item) for item in decoded if str(item).strip()]
    if isinstance(decoded, str):
        return [part.strip() for part in re.split(r"[,\s]+", decoded) if part.strip()]
    return []


def _observations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in ("property_observations", "field_observations", "property_results", "field_results"):
        raw = details.get(key)
        decoded = _loads(raw, raw)
        if isinstance(decoded, Mapping):
            result: list[dict[str, Any]] = []
            for field, value in decoded.items():
                if isinstance(value, Mapping):
                    item = dict(value)
                    item.setdefault("field", str(field))
                else:
                    item = {"field": str(field), "result": value}
                result.append(item)
            return result
        if isinstance(decoded, list):
            return [dict(item) for item in decoded if isinstance(item, Mapping)]
    return []


def _add_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    identity = (
        str(item.get("type") or ""),
        str(item.get("source_group") or item.get("source") or ""),
        str(item.get("text") or ""),
    )
    for existing in items:
        other = (
            str(existing.get("type") or ""),
            str(existing.get("source_group") or existing.get("source") or ""),
            str(existing.get("text") or ""),
        )
        if other == identity:
            return
    items.append(item)


def _structural_evidence(method: str, body_fields: list[str]) -> list[dict[str, Any]]:
    support: list[dict[str, Any]] = []
    privileged = [field for field in body_fields if _is_privileged_field(field)]
    if privileged:
        _add_unique(support, {
            "type": "privileged_property",
            "source": "schema",
            "source_group": "property_schema",
            "weight": 24,
            "text": f"Client-visible write schema includes policy-sensitive properties: {', '.join(privileged[:8])}.",
        })
        _add_unique(support, {
            "type": "privileged_fields",
            "source": "schema",
            "source_group": "property_schema",
            "weight": 16,
            "text": "The request contract exposes one or more security-sensitive object properties.",
        })
    if method.upper() in WRITE_METHODS:
        _add_unique(support, {
            "type": "write_method",
            "source": "method",
            "source_group": "write_operation",
            "weight": 14,
            "text": f"The client-visible object operation uses write method {method.upper()}.",
        })
        if body_fields:
            _add_unique(support, {
                "type": "body_schema",
                "source": "endpoint_schema",
                "source_group": "request_contract",
                "weight": 10,
                "text": "A structured request-body schema is available for the write operation.",
            })
    return support


def _behavioral_evidence(details: Mapping[str, Any], body_fields: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False
    privileged_body = [field for field in body_fields if _is_privileged_field(field)]

    accepted = set(_field_list(details.get("accepted_fields") or details.get("accepted_properties")))
    persisted = set(_field_list(details.get("persisted_fields") or details.get("mutated_fields") or details.get("changed_fields")))
    rejected = set(_field_list(details.get("rejected_fields") or details.get("blocked_fields")))
    ignored = set(_field_list(details.get("ignored_fields") or details.get("dropped_fields")))
    allowlist = set(_field_list(details.get("writable_fields") or details.get("allowed_fields") or details.get("server_allowlist")))

    for field in privileged_body:
        if any(_normalize(field) == _normalize(value) for value in accepted):
            _add_unique(support, {
                "type": "protected_property_accepted",
                "source": "stored_property_result",
                "source_group": "property_behavior",
                "weight": 30,
                "text": f"Stored target evidence records that protected property {field!r} was accepted by the write operation.",
            })
            direct = True
        if any(_normalize(field) == _normalize(value) for value in persisted):
            _add_unique(support, {
                "type": "protected_property_mutated",
                "source": "stored_property_result",
                "source_group": "property_persistence",
                "weight": 36,
                "text": f"Stored before/after or read-back evidence records that protected property {field!r} was persisted/mutated.",
            })
            direct = True
        if any(_normalize(field) == _normalize(value) for value in rejected):
            _add_unique(contradict, {
                "type": "protected_property_rejected",
                "source": "stored_property_result",
                "source_group": "property_behavior",
                "weight": -30,
                "text": f"Stored target evidence records that protected property {field!r} was rejected.",
            })
        if any(_normalize(field) == _normalize(value) for value in ignored):
            _add_unique(contradict, {
                "type": "sensitive_property_ignored",
                "source": "stored_property_result",
                "source_group": "property_behavior",
                "weight": -26,
                "text": f"Stored target evidence records that protected property {field!r} was ignored/dropped rather than applied.",
            })
        if allowlist and not any(_normalize(field) == _normalize(value) for value in allowlist):
            _add_unique(contradict, {
                "type": "server_allowlist_observed",
                "source": "stored_write_contract",
                "source_group": "property_policy",
                "weight": -24,
                "text": f"Stored server writable-field policy excludes protected property {field!r}.",
            })

    allowlist_enforced = _bool(details.get("server_allowlist_enforced") or details.get("field_allowlist_enforced") or details.get("serializer_allowlist_enforced"))
    if allowlist_enforced is True:
        _add_unique(contradict, {
            "type": "server_allowlist_observed",
            "source": "stored_write_contract",
            "source_group": "property_policy",
            "weight": -28,
            "text": "Stored target evidence explicitly records server-side writable-field allow-list enforcement.",
        })

    for index, observation in enumerate(_observations(details)):
        field = str(_scalar(observation, ("field", "property", "name", "key")) or "").strip()
        if not field or not _is_privileged_field(field):
            continue
        label = str(observation.get("context") or observation.get("name") or f"property-{index + 1}")
        expected_writable = _bool(_scalar(observation, ("expected_writable", "authorized_writable", "should_accept", "property_allowed")))
        accepted_flag = _bool(_scalar(observation, ("accepted", "property_accepted", "input_accepted")))
        persisted_flag = _bool(_scalar(observation, ("persisted", "mutated", "changed", "applied", "property_mutated")))
        ignored_flag = _bool(_scalar(observation, ("ignored", "dropped", "property_ignored")))
        rejected_flag = _bool(_scalar(observation, ("rejected", "blocked", "property_rejected")))
        status = _status(observation)
        before = _scalar(observation, ("before", "before_value", "old_value"))
        after = _scalar(observation, ("after", "after_value", "new_value"))
        changed_by_value = before is not None and after is not None and str(before) != str(after)
        success = status in SUCCESS_STATUSES if status else False
        denied = status in DENY_STATUSES if status else False

        if expected_writable is False and (accepted_flag is True or persisted_flag is True or changed_by_value or (success and accepted_flag is not False)):
            _add_unique(support, {
                "type": "property_authorization_differential",
                "source": "stored_property_context",
                "source_group": "property_policy",
                "weight": 34,
                "text": f"Stored context {label} records protected property {field!r} as not writable for the caller, yet the operation accepted or applied it.",
            })
            direct = True
        if accepted_flag is True:
            _add_unique(support, {
                "type": "protected_property_accepted",
                "source": "stored_property_context",
                "source_group": "property_behavior",
                "weight": 30,
                "text": f"Stored target evidence records protected property {field!r} as accepted.",
            })
            direct = True
        if persisted_flag is True or changed_by_value:
            _add_unique(support, {
                "type": "protected_property_mutated",
                "source": "stored_property_context",
                "source_group": "property_persistence",
                "weight": 38,
                "text": f"Stored target evidence records protected property {field!r} as persisted or changed.",
            })
            direct = True
        if expected_writable is False and (rejected_flag is True or denied):
            _add_unique(contradict, {
                "type": "protected_property_rejected",
                "source": "stored_property_context",
                "source_group": "property_behavior",
                "weight": -30,
                "text": f"Stored context {label} shows non-writable protected property {field!r} was rejected/denied.",
            })
        if ignored_flag is True:
            _add_unique(contradict, {
                "type": "sensitive_property_ignored",
                "source": "stored_property_context",
                "source_group": "property_behavior",
                "weight": -26,
                "text": f"Stored context {label} shows protected property {field!r} was ignored rather than persisted.",
            })

    return support, contradict, direct


def _matched_writeups(observed: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for doc in MASS_ASSIGNMENT_WRITEUP_PATTERNS:
        overlap = sorted(observed & {str(signal) for signal in doc.get("signals", [])})
        if not overlap:
            continue
        matches.append({
            "id": str(doc.get("id") or ""),
            "source": str(doc.get("source") or ""),
            "ref": str(doc.get("ref") or ""),
            "url": str(doc.get("url") or ""),
            "principle": str(doc.get("principle") or ""),
            "matched_signals": overlap,
            "non_evidentiary": True,
        })
    return matches


def _triggered_false_positive_checks(contradictions: set[str]) -> list[dict[str, str]]:
    mapping = {
        "protected_property_rejected": "The server rejected the protected property; verify that any apparent success came from a different property/context before treating it as a bypass.",
        "server_allowlist_observed": "A server-side writable-field allow-list is recorded; require direct evidence that the protected property bypassed that policy.",
        "sensitive_property_ignored": "The sensitive property was ignored/dropped; do not confuse syntactic acceptance or response echo with persistence.",
    }
    return [
        {"signal": signal, "check": mapping[signal]}
        for signal in sorted(contradictions)
        if signal in mapping
    ]


class MassAssignmentFamilyAnalyzer(FamilyAnalyzer):
    family = "mass_assignment"
    analyzer_version = MASS_ASSIGNMENT_FAMILY_ANALYZER_VERSION

    def analyze(
        self,
        context: FamilyAnalyzerContext,
        *,
        body_fields: list[str],
        **_: Any,
    ) -> dict[str, Any] | None:
        method = str(context.method or "UNKNOWN").upper()
        structural = _structural_evidence(method, body_fields)
        behavioral, contradictions, direct = _behavioral_evidence(context.details, body_fields)
        support = [*structural, *behavioral]
        observed = {str(item.get("type") or "") for item in support}

        if not ({"privileged_property", "privileged_fields"} & observed):
            return None
        if method not in WRITE_METHODS and not ({"protected_property_accepted", "protected_property_mutated", "property_authorization_differential"} & observed):
            return None

        contradiction_types = {str(item.get("type") or "") for item in contradictions}
        confirmation_missing = confirmation_gaps(self.family, observed)
        policy = FAMILY_REASONING[self.family]
        writeups = _matched_writeups(observed)

        if "protected_property_mutated" in observed:
            variant = "protected_property_mutation"
            summary = "Stored target evidence indicates a policy-sensitive object property was persisted or changed through a client-controlled write operation."
            base = 46
        elif "property_authorization_differential" in observed:
            variant = "property_authorization_differential"
            summary = "Stored target evidence indicates a property outside the caller's writable policy was accepted or applied."
            base = 42
        elif "protected_property_accepted" in observed:
            variant = "protected_property_acceptance"
            summary = "Stored target evidence indicates a protected property was accepted, but persistence/authorization context should be confirmed."
            base = 38
        else:
            variant = "privileged_properties"
            summary = "A client-visible write contract exposes policy-sensitive properties; server-side writable-field authorization remains unproven."
            base = 24

        if contradictions and not direct:
            base = max(10, base - min(12, len(contradictions) * 4))

        missing = list(policy.get("next_evidence", ()))
        if confirmation_missing:
            missing = list(dict.fromkeys([*missing, *[f"Confirmation evidence: {' / '.join(group)}" for group in confirmation_missing]]))

        return {
            "family": self.family,
            "variant": variant,
            "base": base,
            "support": support,
            "contradict": contradictions,
            "missing": missing,
            "rule_ids": [
                "mass-assignment-property-surface",
                "mass-assignment-writable-contract",
                "mass-assignment-property-authorization",
                "mass-assignment-behavioral-decision",
            ],
            "summary": summary,
            "direct": bool(direct),
            "family_analyzer": {
                **self.metadata(),
                "rule_version": MASS_ASSIGNMENT_FAMILY_ANALYZER_RULE_VERSION,
                "taxonomy": dict(MASS_ASSIGNMENT_TAXONOMY),
                "methodology": [dict(step) for step in MASS_ASSIGNMENT_METHOD],
                "writeup_patterns": writeups,
                "false_positive_checks": list(MASS_ASSIGNMENT_FALSE_POSITIVE_CHECKS),
                "triggered_false_positive_checks": _triggered_false_positive_checks(contradiction_types),
                "promotion_required": [sorted(group) for group in policy["promotion_required"]],
                "confirmation_required": [sorted(group) for group in policy["confirmation_required"]],
                "confirmation_missing": confirmation_missing,
                "confirmation_ready_from_stored_target_evidence": not confirmation_missing,
                "next_evidence": list(policy.get("next_evidence", ())),
                "validation_level": str(policy.get("validation_level") or "controlled"),
                "knowledge_sources_matched": len(writeups),
                "knowledge_does_not_change_target_evidence": True,
                "confounders": ["broken_object_authorization", "broken_function_authorization", "business_logic"],
            },
        }


def analyze_mass_assignment_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str,
    body_fields: list[str],
    details: Mapping[str, Any],
    business_context: str = "general",
) -> dict[str, Any] | None:
    context = FamilyAnalyzerContext(
        db=db,
        analysis_id=analysis_id,
        target=target,
        endpoint=endpoint,
        method=method,
        details=details,
        business_context=business_context,
    )
    return MassAssignmentFamilyAnalyzer().analyze(context, body_fields=body_fields)


__all__ = [
    "MASS_ASSIGNMENT_FAMILY_ANALYZER_VERSION",
    "MASS_ASSIGNMENT_FAMILY_ANALYZER_RULE_VERSION",
    "MASS_ASSIGNMENT_TAXONOMY",
    "MASS_ASSIGNMENT_METHOD",
    "MassAssignmentFamilyAnalyzer",
    "analyze_mass_assignment_signal",
]
