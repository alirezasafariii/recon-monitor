from __future__ import annotations

"""Compatibility/integration surface for Candidate Engine family analyzers.

The historical Candidate Engine implementation is preserved byte-for-byte in
``bug_candidates_core.py``. This wrapper enriches BFLA, Mass Assignment and
Authentication/Session hypotheses with dedicated family analyzers before the
existing admission and promotion flow runs. Other families remain delegated
unchanged until migrated.
"""

import importlib
from typing import Any, Mapping

from family_analyzers.authentication_session import analyze_authentication_session_signal
from family_analyzers.bfla import analyze_bfla_signal
from family_analyzers.mass_assignment import analyze_mass_assignment_signal

_base = importlib.import_module("bug_candidates_core")

for _name, _value in vars(_base).items():
    if not _name.startswith("__"):
        globals()[_name] = _value


CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = "1.2.0"
_ORIGINAL_RECORD_HYPOTHESIS = _base.record_hypothesis
_ORIGINAL_EVIDENCE_STRENGTH = _base._evidence_strength

_FAMILY_DIRECT_TYPES = {
    "broken_function_authorization": {
        "unauthorized_function_success",
        "role_authorization_differential",
        "permission_scope_mismatch",
        "privileged_effect_observed",
    },
    "mass_assignment": {
        "protected_property_accepted",
        "protected_property_mutated",
        "property_authorization_differential",
    },
    "authentication_session": {
        "session_reuse_after_logout",
        "token_not_rotated",
        "recovery_bypass",
        "authentication_state_violation",
    },
}

_base.FAMILY_EVIDENCE_SCHEMAS["broken_function_authorization"] = {
    "required_any": (
        ("privileged_function", "privileged_classification"),
        (
            "state_change",
            "role_property",
            "privileged_read_operation",
            "privileged_operation_semantic",
            "unauthorized_function_success",
            "role_authorization_differential",
            "permission_scope_mismatch",
        ),
    ),
    "label": "privileged function plus role/permission-sensitive operation context",
}
_base.FAMILY_EVIDENCE_SCHEMAS["mass_assignment"] = {
    "required_any": (
        ("privileged_property", "privileged_fields"),
        (
            "write_method",
            "body_schema",
            "object_update",
            "protected_property_accepted",
            "protected_property_mutated",
            "property_authorization_differential",
        ),
    ),
    "label": "policy-sensitive property plus writable object/property operation context",
}
_base.FAMILY_EVIDENCE_SCHEMAS["authentication_session"] = {
    "required_any": (
        ("authentication_surface",),
        (
            "client_operation",
            "state_change",
            "auth_boundary",
            "session_reuse_after_logout",
            "token_not_rotated",
            "recovery_bypass",
            "authentication_state_violation",
        ),
    ),
    "label": "authentication/session surface plus concrete lifecycle or boundary operation context",
}
FAMILY_EVIDENCE_SCHEMAS = _base.FAMILY_EVIDENCE_SCHEMAS


def _analysis_alert_context(
    db: Any,
    *,
    analysis_id: str,
    alert_id: int | None,
) -> dict[str, Any]:
    if alert_id is None:
        return {}
    row = db.one(
        """SELECT r.endpoint_schema_json,r.business_context,a.details_json,a.item,a.category
        FROM analysis_results r
        JOIN alerts a ON a.id=r.alert_id
        WHERE r.analysis_id=? AND r.alert_id=?
        LIMIT 1""",
        (analysis_id, int(alert_id)),
    )
    if not row:
        return {}
    schema = _base._loads(row["endpoint_schema_json"], {})
    details = _base._loads(row["details_json"], {})
    return {
        "schema": schema if isinstance(schema, Mapping) else {},
        "details": details if isinstance(details, Mapping) else {},
        "business_context": str(row["business_context"] or "general"),
        "item": str(row["item"] or ""),
        "category": str(row["category"] or ""),
    }


def _stored_family_context(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    alert_id: int | None,
    endpoint: str,
) -> dict[str, Any] | None:
    stored = _analysis_alert_context(db, analysis_id=analysis_id, alert_id=alert_id)
    if not stored:
        return None
    schema = stored["schema"]
    details = stored["details"]
    method = str(schema.get("method") or details.get("method") or "UNKNOWN").upper()
    resolved_endpoint = str(schema.get("endpoint") or endpoint or stored["item"])
    body_fields = [str(value) for value in _base._list(schema.get("body_fields"))]
    query_fields = [str(value) for value in _base._list(schema.get("query_parameters"))]
    path_fields = [str(value) for value in _base._list(schema.get("path_parameters"))]
    auth_hints = [str(value) for value in _base._list(schema.get("authentication_hints"))]
    semantic_text = " ".join(
        [
            resolved_endpoint,
            stored["item"],
            stored["category"],
            stored["business_context"],
            _base.json_dumps(details),
            " ".join(body_fields + query_fields + path_fields),
        ]
    )
    return {
        "target": target,
        "endpoint": resolved_endpoint,
        "method": method,
        "body_fields": body_fields,
        "query_fields": query_fields,
        "path_fields": path_fields,
        "auth_hints": auth_hints,
        "details": details,
        "business_context": stored["business_context"],
        "semantic_text": semantic_text,
    }


def _dedicated_family_result(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    alert_id: int | None,
    endpoint: str,
    family: str,
) -> dict[str, Any] | None:
    stored = _stored_family_context(
        db,
        analysis_id=analysis_id,
        target=target,
        alert_id=alert_id,
        endpoint=endpoint,
    )
    if not stored:
        return None

    if family == "broken_function_authorization":
        return analyze_bfla_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=stored["endpoint"],
            method=stored["method"],
            body_fields=stored["body_fields"],
            auth_hints=stored["auth_hints"],
            details=stored["details"],
            business_context=stored["business_context"],
            semantic_text=stored["semantic_text"],
        )

    if family == "mass_assignment":
        return analyze_mass_assignment_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=stored["endpoint"],
            method=stored["method"],
            body_fields=stored["body_fields"],
            details=stored["details"],
            business_context=stored["business_context"],
        )

    if family == "authentication_session":
        return analyze_authentication_session_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=stored["endpoint"],
            method=stored["method"],
            body_fields=stored["body_fields"],
            query_fields=stored["query_fields"],
            auth_hints=stored["auth_hints"],
            details=stored["details"],
            business_context=stored["business_context"],
            semantic_text=stored["semantic_text"],
        )

    return None


def _record_hypothesis_with_family_analyzers(
    db: Any,
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
    family_meta: dict[str, Any] | None = None
    if family in {
        "broken_function_authorization",
        "mass_assignment",
        "authentication_session",
    }:
        dedicated = _dedicated_family_result(
            db,
            analysis_id=analysis_id,
            target=target,
            alert_id=alert_id,
            endpoint=endpoint,
            family=family,
        )
        if dedicated:
            variant = str(dedicated.get("variant") or variant)
            support = [dict(item) for item in dedicated.get("support", []) if isinstance(item, Mapping)]
            contradict = [dict(item) for item in dedicated.get("contradict", []) if isinstance(item, Mapping)]
            missing = [str(item) for item in dedicated.get("missing", []) if str(item)]
            rule_ids = list(dict.fromkeys([
                *[str(item) for item in rule_ids if str(item)],
                *[str(item) for item in dedicated.get("rule_ids", []) if str(item)],
            ]))
            summary = str(dedicated.get("summary") or summary)
            raw_meta = dedicated.get("family_analyzer")
            if isinstance(raw_meta, Mapping):
                family_meta = dict(raw_meta)

    result = _ORIGINAL_RECORD_HYPOTHESIS(
        db,
        analysis_id=analysis_id,
        source_run_id=source_run_id,
        target=target,
        alert_id=alert_id,
        asset=asset,
        endpoint=endpoint,
        source_ref=source_ref,
        family=family,
        variant=variant,
        support=support,
        contradict=contradict,
        missing=missing,
        rule_ids=rule_ids,
        summary=summary,
    )

    if family_meta:
        assessment = dict(result.get("assessment") or {})
        assessment["family_analyzer"] = family_meta
        assessment["candidate_family_analyzer_integration_version"] = CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION
        result["assessment"] = assessment
        db.execute(
            "UPDATE analysis_hypotheses SET admission_json=? WHERE hypothesis_id=?",
            (_base.json_dumps(assessment), str(result.get("hypothesis_id") or "")),
        )
    return result


def _evidence_strength_with_family_directness(
    analysis_confidence: int,
    support: list[dict[str, Any]],
    contradict: list[dict[str, Any]],
    *,
    direct: bool = False,
) -> int:
    if not direct:
        observed = {str(item.get("type") or "") for item in support}
        direct = any(bool(observed & signals) for signals in _FAMILY_DIRECT_TYPES.values())
    return _ORIGINAL_EVIDENCE_STRENGTH(
        analysis_confidence,
        support,
        contradict,
        direct=direct,
    )


_base.record_hypothesis = _record_hypothesis_with_family_analyzers
_base._evidence_strength = _evidence_strength_with_family_directness
record_hypothesis = _record_hypothesis_with_family_analyzers
_evidence_strength = _evidence_strength_with_family_directness

for _name, _value in vars(_base).items():
    if not _name.startswith("__"):
        globals()[_name] = _value
record_hypothesis = _record_hypothesis_with_family_analyzers
_evidence_strength = _evidence_strength_with_family_directness

__all__ = [name for name in globals() if not name.startswith("__")]
