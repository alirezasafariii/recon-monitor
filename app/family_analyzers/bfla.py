from __future__ import annotations

"""Dedicated Broken Function Level Authorization family analyzer.

The analyzer executes against stored target observations. OWASP, WSTG, CWE and
curated write-up lessons come from the canonical family specification and never
become supporting evidence or satisfy admission/confirmation by themselves.
"""

import json
import re
from typing import Any, Iterable, Mapping

from core import Database, parse_int
from family_reasoning import confirmation_gaps
from family_specs.registry import get_detection_spec

from .base import FamilyAnalyzer, FamilyAnalyzerContext


BFLA_FAMILY_ANALYZER_VERSION = "1.1.0"
BFLA_FAMILY_ANALYZER_RULE_VERSION = "2026.08.15.3"
BFLA_SPEC = get_detection_spec("broken_function_authorization")

SUCCESS_STATUSES = set(range(200, 300))
DENY_STATUSES = {401, 403, 404}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

PRIVILEGED_ROUTE_MARKERS = (
    "/admin", "admin/", "/backoffice", "backoffice/", "/staff", "staff/",
    "/management", "management/", "/manage/", "/moderator", "/superuser",
    "/permissions", "/roles", "/privileges", "/impersonate", "/reprocess",
)
PRIVILEGED_ACTION_MARKERS = (
    "grant", "revoke", "approve", "suspend", "disable", "ban", "delete",
    "purge", "impersonate", "invite", "permission", "privilege", "role",
    "reprocess", "rotate", "configure", "administration",
)
PRIVILEGED_FIELDS = {
    "role", "roles", "isadmin", "admin", "permissions", "permission",
    "privilege", "privileges", "isstaff", "staff", "accounttype",
}
ROLE_KEYS = (
    "role", "user_role", "actor_role", "current_role", "request_role",
    "identity_role", "member_role", "account_role",
)
REQUIRED_ROLE_KEYS = (
    "required_role", "minimum_role", "expected_role", "authorized_role",
    "function_role", "required_group",
)
PERMISSION_KEYS = (
    "permission", "scope", "granted_permission", "granted_scope",
    "actor_permission", "current_permission",
)
REQUIRED_PERMISSION_KEYS = (
    "required_permission", "minimum_permission", "expected_permission",
    "required_scope", "function_permission",
)
EXPECTED_ACCESS_KEYS = (
    "expected_access", "authorization_expected", "should_allow",
    "should_be_allowed", "expected_authorized",
)

# Compatibility exports; canonical definitions live in family_specs.
BFLA_TAXONOMY = BFLA_SPEC.taxonomy()
BFLA_METHOD = tuple(step.as_dict() for step in BFLA_SPEC.standard.methodology)
BFLA_FALSE_POSITIVE_CHECKS = tuple(BFLA_SPEC.standard.false_positive_checks)
BFLA_WRITEUP_PATTERNS = tuple(
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
    for item in BFLA_SPEC.standard.writeups
)


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _flatten_scalars(value: Any, *, depth: int = 0) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    if depth > 5:
        return result
    if isinstance(value, Mapping):
        for key, child in list(value.items())[:500]:
            normalized = _normalize_key(str(key))
            if isinstance(child, (Mapping, list)):
                nested = _flatten_scalars(child, depth=depth + 1)
                for nested_key, values in nested.items():
                    result.setdefault(nested_key, []).extend(values)
            elif child is not None:
                result.setdefault(normalized, []).append(str(child).strip())
    elif isinstance(value, list):
        for child in value[:100]:
            nested = _flatten_scalars(child, depth=depth + 1)
            for nested_key, values in nested.items():
                result.setdefault(nested_key, []).extend(values)
    return result


def _first(flat: Mapping[str, list[str]], keys: Iterable[str]) -> str:
    for key in keys:
        for value in flat.get(_normalize_key(key), []):
            if str(value).strip():
                return str(value).strip()
    return ""


def _bool_value(value: str) -> bool | None:
    normalized = str(value or "").strip().lower()
    if normalized in {"true", "1", "yes", "allow", "allowed", "authorized"}:
        return True
    if normalized in {"false", "0", "no", "deny", "denied", "unauthorized", "forbidden"}:
        return False
    return None


def _status(mapping: Mapping[str, Any]) -> int:
    value = mapping.get("status_code")
    response = mapping.get("response")
    if value is None and isinstance(response, Mapping):
        value = response.get("status_code")
    return parse_int(value, 0)


def _different(left: str, right: str) -> bool:
    return bool(left and right and left.strip().lower() != right.strip().lower())


def _contexts(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = details.get("context_observations") or details.get("observations") or details.get("contexts")
    decoded = _loads(raw, raw)
    if isinstance(decoded, Mapping):
        items: list[dict[str, Any]] = []
        for label, value in decoded.items():
            if isinstance(value, Mapping):
                item = dict(value)
                item.setdefault("context", str(label))
                items.append(item)
        return items
    if isinstance(decoded, list):
        return [dict(item) for item in decoded if isinstance(item, Mapping)]
    return []


def _add_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    key = (
        str(item.get("type") or ""),
        str(item.get("source_group") or item.get("source") or ""),
        str(item.get("text") or ""),
    )
    if any(
        (
            str(existing.get("type") or ""),
            str(existing.get("source_group") or existing.get("source") or ""),
            str(existing.get("text") or ""),
        ) == key
        for existing in items
    ):
        return
    items.append(item)


def _role_context_evidence(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False
    observations = _contexts(details) or [dict(details)]

    for index, observation in enumerate(observations):
        flat = _flatten_scalars(observation)
        status = _status(observation)
        success = status in SUCCESS_STATUSES
        denied = status in DENY_STATUSES
        label = str(observation.get("context") or observation.get("name") or f"context-{index + 1}")
        expected = _bool_value(_first(flat, EXPECTED_ACCESS_KEYS))
        role = _first(flat, ROLE_KEYS)
        required_role = _first(flat, REQUIRED_ROLE_KEYS)
        permission = _first(flat, PERMISSION_KEYS)
        required_permission = _first(flat, REQUIRED_PERMISSION_KEYS)
        role_enforced = _bool_value(_first(flat, ("role_enforcement", "role_enforcement_observed", "role_check_enforced")))
        permission_enforced = _bool_value(_first(flat, ("permission_enforced", "permission_check_enforced", "authorization_enforced")))
        privileged_effect = _bool_value(_first(flat, ("privileged_effect", "sensitive_effect", "operation_performed", "state_change_observed")))

        if expected is False and success:
            _add_unique(support, {
                "type": "unauthorized_function_success",
                "source": "stored_context",
                "source_group": "role_function_boundary",
                "weight": 34,
                "text": f"Stored context {label} was explicitly expected to be denied but the function returned success ({status}).",
            })
            direct = True
            if privileged_effect is True:
                _add_unique(support, {
                    "type": "privileged_effect_observed",
                    "source": "stored_context",
                    "source_group": "function_effect",
                    "weight": 24,
                    "text": "Stored target evidence records that the successful lower-privilege request produced the privileged function effect.",
                })
        elif expected is False and denied:
            _add_unique(contradict, {
                "type": "lower_privilege_denied",
                "source": "stored_context",
                "source_group": "role_function_boundary",
                "weight": -28,
                "text": f"Stored lower-privilege context {label} was denied with HTTP {status}.",
            })

        if _different(role, required_role) and success:
            _add_unique(support, {
                "type": "role_authorization_differential",
                "source": "role_context",
                "source_group": "role_function_boundary",
                "weight": 30,
                "text": f"Stored target evidence shows role {role!r} successfully invoked a function requiring role {required_role!r}.",
            })
            direct = True

        if _different(permission, required_permission) and success:
            _add_unique(support, {
                "type": "permission_scope_mismatch",
                "source": "permission_context",
                "source_group": "permission_function_boundary",
                "weight": 30,
                "text": f"Stored target evidence shows permission/scope {permission!r} successfully invoked a function requiring {required_permission!r}.",
            })
            _add_unique(support, {
                "type": "role_authorization_differential",
                "source": "permission_context",
                "source_group": "permission_function_boundary",
                "weight": 22,
                "text": "The observed permission/scope is weaker or different from the function's recorded authorization requirement while the operation succeeds.",
            })
            direct = True

        if role_enforced is True:
            _add_unique(contradict, {
                "type": "role_enforcement_observed",
                "source": "role_context",
                "source_group": "role_function_boundary",
                "weight": -24,
                "text": "Stored target evidence explicitly records server-side role enforcement for this function.",
            })
        if permission_enforced is True:
            _add_unique(contradict, {
                "type": "permission_check_enforced",
                "source": "permission_context",
                "source_group": "permission_function_boundary",
                "weight": -24,
                "text": "Stored target evidence explicitly records server-side permission enforcement for this function.",
            })

    return support, contradict, direct


def _matched_writeups(observed: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in BFLA_SPEC.standard.writeups:
        overlap = sorted(observed & set(item.signal_hints))
        if not overlap:
            continue
        matches.append({
            "id": item.id,
            "source": item.source,
            "ref": item.ref,
            "url": item.url,
            "relation": item.relation,
            "principle": item.lesson,
            "matched_signals": overlap,
            "non_evidentiary": True,
            "counts_as_target_evidence": False,
        })
    return matches


def _triggered_false_positive_checks(contradictions: set[str]) -> list[dict[str, str]]:
    mapping = {
        "lower_privilege_denied": "A stored lower-privilege context is denied; require a separate concrete success that actually crosses the intended role boundary.",
        "role_enforcement_observed": "Server-side role enforcement is recorded; determine whether any decisive success bypasses a different handler or method rather than this enforced path.",
        "permission_check_enforced": "Server-side permission enforcement is recorded; do not infer BFLA from UI visibility or route naming alone.",
        "auth_hint": "Authentication hints only establish authentication context, not function-level authorization failure.",
    }
    return [{"signal": signal, "check": mapping[signal]} for signal in sorted(contradictions) if signal in mapping]


class BflaFamilyAnalyzer(FamilyAnalyzer):
    family = "broken_function_authorization"
    analyzer_version = BFLA_FAMILY_ANALYZER_VERSION

    def analyze(
        self,
        context: FamilyAnalyzerContext,
        *,
        body_fields: list[str] | None = None,
        auth_hints: list[str] | None = None,
        semantic_text: str = "",
        **_: Any,
    ) -> dict[str, Any] | None:
        body_fields = [str(value) for value in (body_fields or [])]
        auth_hints = [str(value) for value in (auth_hints or [])]
        method = str(context.method or "UNKNOWN").upper()
        haystack = " ".join([context.endpoint, semantic_text, json.dumps(context.details, sort_keys=True, default=str)]).lower()

        route_markers = [marker for marker in PRIVILEGED_ROUTE_MARKERS if marker in haystack]
        action_markers = [marker for marker in PRIVILEGED_ACTION_MARKERS if marker in haystack]
        privileged_fields = sorted(
            field for field in body_fields
            if _normalize_key(field).replace("_", "") in PRIVILEGED_FIELDS
        )
        classification_text = json.dumps(
            context.details.get("endpoint_classification") or context.details.get("diff_summary") or {},
            sort_keys=True,
            default=str,
        ).lower()
        classified_privileged = any(
            token in classification_text
            for token in ("admin", "privileged", "authorization", "permission", "role")
        )

        function_signal = bool(route_markers or classified_privileged or privileged_fields)
        if not function_signal and context.business_context == "administration" and action_markers:
            function_signal = True
        if not function_signal:
            return None

        support: list[dict[str, Any]] = []
        contradict: list[dict[str, Any]] = []
        _add_unique(support, {
            "type": "privileged_function",
            "source": "semantic",
            "source_group": "function_surface",
            "weight": 20,
            "text": "A function surface associated with administrative, role, permission or other privileged behavior is visible in collected target data.",
        })
        if classified_privileged:
            _add_unique(support, {
                "type": "privileged_classification",
                "source": "classification",
                "source_group": "function_classification",
                "weight": 14,
                "text": "Independent endpoint classification identifies administrative, privileged or authorization-sensitive semantics.",
            })
        if method in STATE_CHANGING_METHODS:
            _add_unique(support, {
                "type": "state_change",
                "source": "method",
                "source_group": "function_operation",
                "weight": 12,
                "text": f"The privileged function uses state-changing HTTP method {method}.",
            })
        else:
            _add_unique(support, {
                "type": "privileged_read_operation",
                "source": "method",
                "source_group": "function_operation",
                "weight": 8,
                "text": f"The privileged function is exposed through read-like method {method}; read-only administrative functions still require role authorization.",
            })
        if privileged_fields:
            _add_unique(support, {
                "type": "role_property",
                "source": "schema",
                "source_group": "request_contract",
                "weight": 12,
                "text": f"The client-visible request contract contains role/permission-sensitive fields: {', '.join(privileged_fields[:6])}.",
            })
        if action_markers:
            _add_unique(support, {
                "type": "privileged_operation_semantic",
                "source": "semantic",
                "source_group": "function_operation",
                "weight": 8,
                "text": f"Privilege-sensitive operation semantics were observed: {', '.join(action_markers[:6])}.",
            })
        if auth_hints:
            _add_unique(contradict, {
                "type": "auth_hint",
                "source": "client",
                "source_group": "authentication_context",
                "weight": -4,
                "text": "Authentication hints are present, but authentication alone does not establish server-side role enforcement.",
            })

        context_support, context_contradict, direct = _role_context_evidence(context.details)
        for item in context_support:
            _add_unique(support, item)
        for item in context_contradict:
            _add_unique(contradict, item)

        observed = {str(item.get("type") or "") for item in support}
        contradiction_types = {str(item.get("type") or "") for item in contradict}
        if "permission_scope_mismatch" in observed:
            variant = "permission_scope_mismatch"
        elif "role_authorization_differential" in observed or "unauthorized_function_success" in observed:
            variant = "vertical_role_bypass"
        elif method in STATE_CHANGING_METHODS:
            variant = "privileged_state_change"
        else:
            variant = "privileged_read"

        if direct:
            summary = "Stored target evidence indicates that a role or permission context expected to be denied can invoke a privileged function. The condition remains a Potential Finding until analyst confirmation of the intended role matrix and actual function effect."
            base = 30
        else:
            summary = "A privileged function surface is present, but stored target evidence does not yet establish that a lower-privilege role can invoke it. The signal is retained as a hidden role-differential hypothesis."
            base = 16

        confirmation_missing = confirmation_gaps(self.family, observed)
        matched_writeups = _matched_writeups(observed)

        return {
            "variant": variant,
            "base": base,
            "support": support,
            "contradict": contradict,
            "missing": list(BFLA_SPEC.next_evidence),
            "rule_ids": [
                "bfla-privileged-function",
                "bfla-role-function-matrix",
                "bfla-vertical-differential",
                "bfla-method-scope-differential",
            ],
            "summary": summary,
            "direct": direct,
            "family_analyzer": {
                **self.metadata(),
                "rule_version": BFLA_FAMILY_ANALYZER_RULE_VERSION,
                "family_spec_version": BFLA_SPEC.version,
                "family_spec_strategy": BFLA_SPEC.strategy,
                "taxonomy": BFLA_SPEC.taxonomy(),
                "methodology": [step.as_dict() for step in BFLA_SPEC.standard.methodology],
                "writeup_patterns": matched_writeups,
                "false_positive_checks": list(BFLA_SPEC.standard.false_positive_checks),
                "triggered_false_positive_checks": _triggered_false_positive_checks(contradiction_types),
                "promotion_required": [sorted(group) for group in BFLA_SPEC.promotion_required],
                "promotion_ready_from_stored_target_evidence": direct,
                "confirmation_required": [sorted(group) for group in BFLA_SPEC.confirmation_required],
                "confirmation_missing": confirmation_missing,
                "confirmation_ready_from_stored_target_evidence": not confirmation_missing,
                "next_evidence": list(BFLA_SPEC.next_evidence),
                "validation_level": BFLA_SPEC.validation_level,
                "knowledge_sources_matched": len(matched_writeups),
                "knowledge_does_not_change_target_evidence": True,
            },
        }


def analyze_bfla_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str,
    body_fields: list[str] | None,
    auth_hints: list[str] | None,
    details: Mapping[str, Any],
    business_context: str = "general",
    semantic_text: str = "",
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
    return BflaFamilyAnalyzer().analyze(
        context,
        body_fields=body_fields or [],
        auth_hints=auth_hints or [],
        semantic_text=semantic_text,
    )


__all__ = [
    "BFLA_FAMILY_ANALYZER_VERSION",
    "BFLA_FAMILY_ANALYZER_RULE_VERSION",
    "BFLA_SPEC",
    "BFLA_METHOD",
    "BFLA_TAXONOMY",
    "BFLA_FALSE_POSITIVE_CHECKS",
    "BFLA_WRITEUP_PATTERNS",
    "BflaFamilyAnalyzer",
    "analyze_bfla_signal",
]
