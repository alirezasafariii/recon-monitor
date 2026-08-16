from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

from core import Database, parse_int

BOLA_ENGINE_VERSION = "2.0.0"
BOLA_RULE_VERSION = "2026.08.8.5"

SUCCESS_STATUSES = set(range(200, 300))
DENY_STATUSES = {401, 403, 404}

IDENTITY_KEYS = (
    "identity_id", "request_user_id", "current_user_id", "actor_id", "authenticated_user_id", "user_id",
)
OWNER_KEYS = (
    "object_owner_id", "resource_owner_id", "record_owner_id", "owner_id",
)
REQUEST_TENANT_KEYS = (
    "request_tenant_id", "identity_tenant_id", "request_org_id", "identity_org_id", "active_org_id", "active_tenant_id",
)
OBJECT_TENANT_KEYS = (
    "object_tenant_id", "resource_tenant_id", "record_tenant_id", "object_org_id", "resource_org_id", "record_org_id",
)
REQUEST_PARENT_KEYS = (
    "request_parent_id", "parent_id", "board_id", "project_id", "account_id", "organization_id",
)
OBJECT_PARENT_KEYS = (
    "object_parent_id", "resource_parent_id", "record_parent_id", "child_parent_id", "custom_field_board_id", "object_board_id",
)
EXPECTED_ACCESS_KEYS = (
    "expected_access", "authorization_expected", "should_allow", "should_be_allowed",
)
GUARD_REQUIRED_KEYS = (
    "secondary_guard_required", "ownership_guard_required", "token_required", "object_token_required", "guard_required",
)
GUARD_PRESENT_KEYS = (
    "secondary_guard_present", "ownership_guard_present", "token_present", "object_token_present", "guard_present",
)


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _status(mapping: Mapping[str, Any]) -> int:
    value = mapping.get("status_code")
    if value is None and isinstance(mapping.get("response"), Mapping):
        value = mapping["response"].get("status_code")
    if value is None and isinstance(mapping.get("new"), Mapping):
        value = mapping["new"].get("status_code")
    return parse_int(value, 0)


def _normalize_key(value: str) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _flatten_scalars(value: Any, *, prefix: str = "", depth: int = 0) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    if depth > 5:
        return result
    if isinstance(value, Mapping):
        for key, child in list(value.items())[:500]:
            normalized = _normalize_key(str(key))
            path = f"{prefix}.{normalized}" if prefix else normalized
            if isinstance(child, (Mapping, list)):
                nested = _flatten_scalars(child, prefix=path, depth=depth + 1)
                for nkey, values in nested.items():
                    result.setdefault(nkey, []).extend(values)
            elif child is not None:
                text = str(child).strip()
                result.setdefault(normalized, []).append(text)
                result.setdefault(path, []).append(text)
    elif isinstance(value, list):
        for child in value[:100]:
            nested = _flatten_scalars(child, prefix=prefix, depth=depth + 1)
            for nkey, values in nested.items():
                result.setdefault(nkey, []).extend(values)
    return result


def _first(flat: Mapping[str, list[str]], keys: Iterable[str]) -> str:
    for key in keys:
        values = flat.get(_normalize_key(key), [])
        for value in values:
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


def _different(left: str, right: str) -> bool:
    return bool(left and right and left.strip().lower() != right.strip().lower())


def _context_observations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = details.get("context_observations") or details.get("observations") or details.get("contexts")
    decoded = _loads(raw, raw)
    if isinstance(decoded, Mapping):
        items = []
        for name, value in decoded.items():
            if isinstance(value, Mapping):
                item = dict(value)
                item.setdefault("context", str(name))
                items.append(item)
        return items
    if isinstance(decoded, list):
        return [dict(item) for item in decoded if isinstance(item, Mapping)]
    return []


def _add_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    key = (str(item.get("type") or ""), str(item.get("source_group") or item.get("source") or ""), str(item.get("text") or ""))
    if any((str(existing.get("type") or ""), str(existing.get("source_group") or existing.get("source") or ""), str(existing.get("text") or "")) == key for existing in items):
        return
    items.append(item)


def _authorization_context_evidence(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False

    contexts = _context_observations(details)
    if not contexts:
        contexts = [dict(details)]

    for index, context in enumerate(contexts):
        flat = _flatten_scalars(context)
        status = _status(context)
        success = status in SUCCESS_STATUSES
        denied = status in DENY_STATUSES
        label = str(context.get("context") or context.get("name") or f"context-{index + 1}")

        expected = _bool_value(_first(flat, EXPECTED_ACCESS_KEYS))
        identity = _first(flat, IDENTITY_KEYS)
        owner = _first(flat, OWNER_KEYS)
        request_tenant = _first(flat, REQUEST_TENANT_KEYS)
        object_tenant = _first(flat, OBJECT_TENANT_KEYS)
        request_parent = _first(flat, REQUEST_PARENT_KEYS)
        object_parent = _first(flat, OBJECT_PARENT_KEYS)
        guard_required = _bool_value(_first(flat, GUARD_REQUIRED_KEYS))
        guard_present = _bool_value(_first(flat, GUARD_PRESENT_KEYS))
        ownership_enforced = _bool_value(_first(flat, ("ownership_enforced", "owner_check_enforced", "object_authorization_enforced")))
        scope_binding = _bool_value(_first(flat, ("scope_binding_enforced", "tenant_binding_enforced", "parent_child_binding_enforced")))
        visibility = _first(flat, ("object_visibility", "resource_visibility", "visibility")).lower()

        if expected is False and success:
            _add_unique(support, {
                "type": "unauthorized_object_response", "source": "stored_context", "source_group": "authorization_context",
                "weight": 32, "text": f"Stored context {label} was marked as not authorized but recorded a successful object response ({status}).",
            })
            _add_unique(support, {
                "type": "authorization_response_differential", "source": "stored_context", "source_group": "authorization_context",
                "weight": 24, "text": "Stored authorization expectations and observed response behavior conflict for this object operation.",
            })
            direct = True
        elif expected is False and denied:
            _add_unique(contradict, {
                "type": "cross_context_denied", "source": "stored_context", "source_group": "authorization_context",
                "weight": -24, "text": f"Stored unauthorized context {label} was denied with HTTP {status}.",
            })

        if _different(identity, owner) and success:
            _add_unique(support, {
                "type": "cross_identity_object_access", "source": "ownership_context", "source_group": "identity_object_binding",
                "weight": 30, "text": "Stored target evidence associates the requesting identity with a different object owner while the object operation succeeded.",
            })
            _add_unique(support, {
                "type": "ownership_mismatch", "source": "ownership_context", "source_group": "identity_object_binding",
                "weight": 24, "text": "Request identity and object-owner identifiers differ in stored target evidence.",
            })
            direct = True

        if _different(request_tenant, object_tenant) and success:
            _add_unique(support, {
                "type": "cross_tenant_object_access", "source": "tenant_context", "source_group": "tenant_object_binding",
                "weight": 32, "text": "Stored target evidence links the request context and referenced object to different tenant or organization identifiers while the operation succeeded.",
            })
            _add_unique(support, {
                "type": "identity_object_relation_conflict", "source": "tenant_context", "source_group": "tenant_object_binding",
                "weight": 22, "text": "Tenant/object relation evidence conflicts with the active request scope.",
            })
            direct = True

        if _different(request_parent, object_parent) and success:
            _add_unique(support, {
                "type": "parent_child_scope_mismatch", "source": "relationship_context", "source_group": "parent_child_binding",
                "weight": 30, "text": "Stored target evidence shows the supplied parent scope differs from the referenced child's recorded parent while the operation succeeded.",
            })
            direct = True

        if guard_required is True and guard_present is False and success:
            _add_unique(support, {
                "type": "object_access_without_secondary_guard", "source": "guard_context", "source_group": "object_guard",
                "weight": 30, "text": "Stored target evidence marks a secondary object-access guard as required and absent while the object operation succeeded.",
            })
            direct = True
        elif guard_required is True and guard_present is False and denied:
            _add_unique(contradict, {
                "type": "secondary_guard_enforced", "source": "guard_context", "source_group": "object_guard",
                "weight": -24, "text": "Stored target evidence shows the request without the required secondary guard was denied.",
            })

        if ownership_enforced is True:
            _add_unique(contradict, {
                "type": "ownership_enforcement_observed", "source": "ownership_context", "source_group": "identity_object_binding",
                "weight": -22, "text": "Stored target evidence explicitly records object ownership enforcement.",
            })
        if scope_binding is True:
            _add_unique(contradict, {
                "type": "scope_binding_observed", "source": "relationship_context", "source_group": "parent_child_binding",
                "weight": -22, "text": "Stored target evidence explicitly records tenant/parent-to-object scope binding.",
            })
        if visibility in {"public", "shared", "global"}:
            _add_unique(contradict, {
                "type": "public_or_shared_object", "source": "object_context", "source_group": "object_visibility",
                "weight": -10, "text": f"Stored target metadata describes the object as {visibility}; cross-identity access may therefore be intended.",
            })

    return support, contradict, direct


def analyze_bola_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str,
    object_ids: list[str],
    structural_fields: list[str],
    details: Mapping[str, Any],
    business_context: str = "general",
) -> dict[str, Any] | None:
    method = str(method or "UNKNOWN").upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
        return None

    structural_normalized = {_normalize_key(value) for value in structural_fields}
    typed_ids = [value for value in object_ids if _normalize_key(value) != "id"]
    generic_id_structural = "id" in structural_normalized
    ids = typed_ids or (["id"] if generic_id_structural else [])
    if not ids:
        return None

    support: list[dict[str, Any]] = [
        {
            "type": "object_identifier", "source": "endpoint_schema", "source_group": "object_reference",
            "weight": 10, "text": f"Structured object reference observed: {', '.join(ids[:6])}",
        },
        {
            "type": "object_operation", "source": "endpoint", "source_group": "object_operation",
            "weight": 6, "text": f"Client-visible {method} operation acts on the referenced object surface.",
        },
    ]
    contradict: list[dict[str, Any]] = []
    missing = [
        "Expected identity-to-object ownership or sharing policy",
        "Server-side authorization decision for this identity, object and operation",
        "Behavior for explicitly authorized comparison identities/objects when permitted by target policy",
    ]
    rule_ids = ["bola-object-reference", "bola-object-operation", "bola-authorization-boundary"]

    context_support, context_contradict, direct = _authorization_context_evidence(details)
    support.extend(context_support)
    contradict.extend(context_contradict)

    boundary = db.one(
        "SELECT boundary,confidence,evidence_json FROM authentication_boundaries WHERE analysis_id=? AND target=? AND endpoint=?",
        (analysis_id, target, endpoint),
    )
    if boundary:
        value = str(boundary["boundary"] or "unknown")
        if value in {"authentication_required", "session_required", "bearer_required", "api_key_required", "mixed", "role_gated_hint"}:
            _add_unique(support, {
                "type": "authenticated_object_surface", "source": "authentication_boundary", "source_group": "authentication_boundary",
                "weight": 4, "text": f"Stored observations place this object operation behind a {value.replace('_', ' ')} boundary.",
            })
        elif value == "public":
            _add_unique(contradict, {
                "type": "public_boundary_observed", "source": "authentication_boundary", "source_group": "authentication_boundary",
                "weight": -5, "text": "Stored observations currently classify the endpoint as public; object privacy remains unknown.",
            })

    shape = db.one(
        "SELECT sensitive_keys_json,confidence,status_code FROM response_shape_fingerprints WHERE analysis_id=? AND target=? AND endpoint=? ORDER BY confidence DESC LIMIT 1",
        (analysis_id, target, endpoint),
    )
    if shape:
        sensitive = _loads(shape["sensitive_keys_json"], [])
        if sensitive:
            _add_unique(support, {
                "type": "sensitive_object_response", "source": "response_shape", "source_group": "response_shape",
                "weight": 7, "text": f"Stored response shape contains sensitive-looking object fields: {', '.join(map(str, sensitive[:6]))}.",
            })

    relations = db.all(
        "SELECT parent_parameter,child_parameter,relation,confidence FROM parameter_relationships WHERE analysis_id=? AND target=? AND endpoint=? ORDER BY confidence DESC LIMIT 20",
        (analysis_id, target, endpoint),
    )
    if relations:
        relation_text = ", ".join(f"{row['parent_parameter']} {row['relation']} {row['child_parameter']}" for row in relations[:4])
        _add_unique(support, {
            "type": "object_relationship", "source": "parameter_relationships", "source_group": "object_relationship",
            "weight": 5, "text": f"Stored endpoint contract contains parent/child object relationships: {relation_text}.",
        })
        missing.append("Verification that each referenced child object belongs to the authorized parent/tenant scope")

    stored_contexts = db.all(
        "SELECT context,auth_state,status_code,shape_hash,confidence FROM behavioral_observations WHERE analysis_id=? AND target=? AND endpoint=? ORDER BY confidence DESC LIMIT 20",
        (analysis_id, target, endpoint),
    )
    if len(stored_contexts) >= 2:
        denied = [row for row in stored_contexts if parse_int(row["status_code"], 0) in DENY_STATUSES]
        successful = [row for row in stored_contexts if parse_int(row["status_code"], 0) in SUCCESS_STATUSES]
        if denied and successful:
            _add_unique(contradict, {
                "type": "cross_context_denied", "source": "behavioral_observation", "source_group": "authorization_context",
                "weight": -14, "text": "Stored contexts show at least one denied and one successful response; this may indicate object-level enforcement rather than a bypass.",
            })
        elif len(successful) >= 2:
            _add_unique(support, {
                "type": "multi_context_success", "source": "behavioral_observation", "source_group": "authorization_context",
                "weight": 3, "text": "Multiple stored contexts received successful responses, but object ownership for those contexts is not established.",
            })

    if business_context in {"payment", "identity", "customer_data", "administration", "partner_portal"}:
        _add_unique(support, {
            "type": "business_context", "source": "context", "source_group": "business_context",
            "weight": 4, "text": f"The object operation is associated with {business_context.replace('_', ' ')} context.",
        })

    decisive = {
        "cross_identity_object_access", "cross_tenant_object_access", "ownership_mismatch", "parent_child_scope_mismatch",
        "authorization_response_differential", "object_access_without_secondary_guard", "identity_object_relation_conflict",
        "unauthorized_object_response",
    }
    observed_types = {str(item.get("type") or "") for item in support}
    variant = "authorization_boundary"
    if "cross_tenant_object_access" in observed_types:
        variant = "cross_tenant_object"
    elif "parent_child_scope_mismatch" in observed_types:
        variant = "parent_child_scope"
    elif "object_access_without_secondary_guard" in observed_types:
        variant = "secondary_guard_gap"
    elif "cross_identity_object_access" in observed_types or "ownership_mismatch" in observed_types:
        variant = "cross_owner_object"
    elif "unauthorized_object_response" in observed_types or "authorization_response_differential" in observed_types:
        variant = "authorization_differential"

    if observed_types & decisive:
        summary = "Stored target evidence suggests a mismatch between the requesting identity/scope and the referenced object for this operation. The condition remains an unverified potential BOLA until analyst validation."
        base = 24
    else:
        summary = "A client-controlled object reference and object operation are present, but stored evidence does not yet establish an object-level authorization failure. The signal is retained for future correlation."
        base = 8

    status = _status(details)
    if status in DENY_STATUSES:
        _add_unique(contradict, {
            "type": "anonymous_or_current_context_denied", "source": "http", "source_group": "http_boundary",
            "weight": -8, "text": f"The currently stored request context returned HTTP {status}; this does not test cross-object authorization.",
        })

    return {
        "variant": variant,
        "base": base,
        "support": support,
        "contradict": contradict,
        "missing": list(dict.fromkeys(missing)),
        "rule_ids": rule_ids,
        "summary": summary,
        "direct": direct,
        "engine_version": BOLA_ENGINE_VERSION,
        "rule_version": BOLA_RULE_VERSION,
    }
