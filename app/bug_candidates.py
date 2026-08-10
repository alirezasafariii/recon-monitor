from __future__ import annotations

"""Compatibility/integration surface for Candidate Engine family analyzers.

The historical Candidate Engine implementation is preserved byte-for-byte in
``bug_candidates_core.py``. This wrapper enriches only BFLA hypotheses with the
dedicated family analyzer before the existing admission/promotion flow runs.
All other behavior is delegated unchanged to the core module.
"""

import importlib
from typing import Any, Mapping

from family_analyzers.bfla import analyze_bfla_signal

_base = importlib.import_module("bug_candidates_core")

# Re-export the complete historical module contract, including private helpers
# used by regression tests and internal callers.
for _name, _value in vars(_base).items():
    if not _name.startswith("__"):
        globals()[_name] = _value


CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = "1.0.0"
_ORIGINAL_RECORD_HYPOTHESIS = _base.record_hypothesis
_ORIGINAL_EVIDENCE_STRENGTH = _base._evidence_strength

_BFLA_DIRECT_TYPES = {
    "unauthorized_function_success",
    "role_authorization_differential",
    "permission_scope_mismatch",
    "privileged_effect_observed",
}

# Keep the legacy candidate score gate aligned with evidence emitted by the
# dedicated BFLA analyzer. Admission remains authoritative and is evaluated
# separately in hypothesis_admission.
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


def _dedicated_bfla_result(
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
    return analyze_bfla_signal(
        db,
        analysis_id=analysis_id,
        target=target,
        endpoint=resolved_endpoint,
        method=method,
        body_fields=body_fields,
        auth_hints=auth_hints,
        details=details,
        business_context=stored["business_context"],
        semantic_text=semantic_text,
    )


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
    if family == "broken_function_authorization":
        dedicated = _dedicated_bfla_result(
            db,
            analysis_id=analysis_id,
            target=target,
            alert_id=alert_id,
            endpoint=endpoint,
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
    if not direct and any(str(item.get("type") or "") in _BFLA_DIRECT_TYPES for item in support):
        direct = True
    return _ORIGINAL_EVIDENCE_STRENGTH(
        analysis_confidence,
        support,
        contradict,
        direct=direct,
    )


# Patch only the dependency references used by functions defined in the core
# module. No Candidate Engine route, persistence schema or public API changes.
_base.record_hypothesis = _record_hypothesis_with_family_analyzers
_base._evidence_strength = _evidence_strength_with_family_directness
record_hypothesis = _record_hypothesis_with_family_analyzers
_evidence_strength = _evidence_strength_with_family_directness

# Refresh exported references after patching the core globals.
for _name, _value in vars(_base).items():
    if not _name.startswith("__"):
        globals()[_name] = _value
record_hypothesis = _record_hypothesis_with_family_analyzers
_evidence_strength = _evidence_strength_with_family_directness

__all__ = [name for name in globals() if not name.startswith("__")]
