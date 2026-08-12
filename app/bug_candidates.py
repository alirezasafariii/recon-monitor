from __future__ import annotations

"""Compatibility/integration surface for Candidate Engine family analyzers.

The historical Candidate Engine implementation is preserved in
``bug_candidates_core.py``. This wrapper enriches specialized family hypotheses
with dedicated analyzers before the existing admission and promotion flow.
DOM-XSS, postMessage Trust and Open Redirect additionally migrate their static
JavaScript paths away from direct candidate insertion: static proximity is
retained as a hidden hypothesis and promotion requires independent stored
runtime condition evidence. SSRF and File Upload / Import use the same
hypothesis-first admission model for alert/endpoint surfaces and require
independent stored target behavior before promotion.
"""

import importlib
from typing import Any, Callable, Mapping

from family_analyzers.account_enumeration import analyze_account_enumeration_signal
from family_analyzers.authentication_session import analyze_authentication_session_signal
from family_analyzers.bfla import analyze_bfla_signal
from family_analyzers.business_logic import analyze_business_logic_signal
from family_analyzers.cors_misconfiguration import analyze_cors_misconfiguration_signal
from family_analyzers.dom_xss import analyze_dom_xss_signal, is_dangerous_dom_sink
from family_analyzers.file_upload import analyze_file_upload_signal
from family_analyzers.graphql_authorization import analyze_graphql_authorization_signal
from family_analyzers.graphql_data_exposure import analyze_graphql_data_exposure_signal
from family_analyzers.information_disclosure import analyze_information_disclosure_signal
from family_analyzers.mass_assignment import analyze_mass_assignment_signal
from family_analyzers.open_redirect import analyze_open_redirect_signal, is_navigation_sink
from family_analyzers.path_traversal import analyze_path_traversal_signal
from family_analyzers.postmessage_trust import analyze_postmessage_trust_signal, is_postmessage_source
from family_analyzers.race_condition import analyze_race_condition_signal
from family_analyzers.secret_exposure import analyze_secret_exposure_signal
from family_analyzers.sensitive_caching import analyze_sensitive_caching_signal
from family_analyzers.source_map_exposure import analyze_source_map_exposure_signal
from family_analyzers.ssrf import analyze_ssrf_signal
from family_analyzers.websocket_authorization import analyze_websocket_authorization_signal

_base = importlib.import_module("bug_candidates_core")

for _name, _value in vars(_base).items():
    if not _name.startswith("__"):
        globals()[_name] = _value


CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = "2.0.0"
_ORIGINAL_RECORD_HYPOTHESIS = _base.record_hypothesis
_ORIGINAL_EVIDENCE_STRENGTH = _base._evidence_strength
_ORIGINAL_STATIC_CANDIDATES = _base._static_candidates

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
    "account_enumeration": {
        "identity_response_differential",
        "identity_timing_differential",
    },
    "dom_xss": {
        "runtime_dom_sink_reached",
        "unsanitized_dom_flow",
    },
    "postmessage_trust": {
        "untrusted_message_accepted",
    },
    "open_redirect": {
        "external_destination_accepted",
    },
    "ssrf": {
        "server_fetch_observed",
        "controlled_callback_observed",
        "destination_policy_bypass_observed",
        "restricted_destination_accepted",
    },
    "file_upload": {
        "unsafe_file_accepted",
        "file_policy_differential",
        "content_type_bypass_observed",
        "executable_upload_observed",
    },
    "path_traversal": {
        "path_escape_observed",
        "path_boundary_differential",
        "canonicalization_bypass_observed",
        "out_of_root_file_access_observed",
        "out_of_root_file_write_observed",
    },
    "information_disclosure": {
        "sensitive_response_observed",
        "private_field_publicly_observed",
        "error_detail_exposure_observed",
    },
    "source_map_exposure": {
        "source_map_publicly_reachable",
        "sensitive_source_content_observed",
    },
    "secret_exposure": {
        "credential_material_confirmed",
        "live_secret_context",
    },
    "graphql_authorization": {"graphql_unauthorized_object_response", "graphql_authorization_differential"},
    "graphql_data_exposure": {"sensitive_graphql_response_observed", "field_authorization_differential"},
    "business_logic": {"workflow_invariant_violation", "invalid_transition_accepted", "server_value_override_observed"},
    "race_condition": {"duplicate_operation_observed", "non_atomic_transition_observed"},
    "websocket_authorization": {"unauthorized_subscription_observed", "channel_authorization_differential"},
    "cors_misconfiguration": {"untrusted_origin_allowed", "credentialed_cross_origin_read"},
    "sensitive_caching": {"shared_cache_sensitive_response", "cross_user_cache_observed"},

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
_base.FAMILY_EVIDENCE_SCHEMAS["account_enumeration"] = {
    "required_any": (
        ("identity_lookup",),
        (
            "authentication_surface",
            "client_operation",
            "identity_response_differential",
            "identity_timing_differential",
        ),
    ),
    "label": "identity lookup surface plus authentication/client comparison context",
}
_base.FAMILY_EVIDENCE_SCHEMAS["dom_xss"] = {
    "required_any": (
        ("dataflow_source",),
        ("dataflow_sink",),
    ),
    "label": "user-influenced browser source plus dangerous DOM/execution sink",
}
_base.FAMILY_EVIDENCE_SCHEMAS["postmessage_trust"] = {
    "required_any": (
        ("postmessage_source", "dataflow_source"),
        ("message_handler", "sensitive_sink", "dataflow_sink"),
    ),
    "label": "Web Messaging source/handler plus sensitive message consumer context",
}
_base.FAMILY_EVIDENCE_SCHEMAS["open_redirect"] = {
    "required_any": (
        ("redirect_parameter", "dataflow_source"),
        ("navigation_context", "dataflow_sink"),
    ),
    "label": "user-influenced redirect destination plus concrete navigation sink",
}
_base.FAMILY_EVIDENCE_SCHEMAS["ssrf"] = {
    "required_any": (
        ("remote_destination", "url_parameter"),
        (
            "server_feature",
            "server_fetch_semantic",
            "server_request_function",
            "server_fetch_observed",
            "controlled_callback_observed",
        ),
    ),
    "label": "user-influenced remote destination plus server-fetch semantics or stored server-side outbound observation",
}
_base.FAMILY_EVIDENCE_SCHEMAS["file_upload"] = {
    "required_any": (
        ("file_input",),
        (
            "upload_operation",
            "import_operation",
            "unsafe_file_accepted",
            "file_policy_differential",
            "content_type_bypass_observed",
            "executable_upload_observed",
        ),
    ),
    "label": "concrete file input plus upload/import operation or stored file-policy differential",
}
_base.FAMILY_EVIDENCE_SCHEMAS["path_traversal"] = {
    "required_any": (
        ("path_parameter", "filename_field", "storage_path"),
        ("file_operation", "download_operation", "import_operation", "archive_operation", "upload_operation", "path_escape_observed", "path_boundary_differential", "canonicalization_bypass_observed", "out_of_root_file_access_observed", "out_of_root_file_write_observed"),
    ),
    "label": "user-influenced path/filename plus file operation or stored filesystem-boundary differential",
}
_base.FAMILY_EVIDENCE_SCHEMAS["information_disclosure"] = {
    "required_any": (
        ("sensitive_marker",),
        ("stored_evidence", "sensitive_response_observed", "private_field_publicly_observed"),
    ),
    "label": "sensitive/debug/internal marker plus stored response context or direct visibility-boundary exposure",
}
_base.FAMILY_EVIDENCE_SCHEMAS["source_map_exposure"] = {
    "required_any": (
        ("source_map", "source_map_publicly_reachable"),
        ("internal_sources", "sensitive_source_content_observed"),
    ),
    "label": "source-map surface/public reachability plus internal source structure or sensitive source-content evidence",
}
_base.FAMILY_EVIDENCE_SCHEMAS["secret_exposure"] = {
    "required_any": (
        ("secret_pattern",),
        ("context", "credential_material_confirmed", "live_secret_context"),
    ),
    "label": "redacted secret-pattern evidence plus concrete exposure context or confirmed credential material",
}
FAMILY_EVIDENCE_SCHEMAS = _base.FAMILY_EVIDENCE_SCHEMAS

_DEDICATED_ALERT_FAMILIES = {
    "broken_function_authorization",
    "mass_assignment",
    "authentication_session",
    "account_enumeration",
    "dom_xss",
    "postmessage_trust",
    "open_redirect",
    "ssrf",
    "file_upload",
    "path_traversal",
    "information_disclosure",
    "business_logic",
    "race_condition",
    "cors_misconfiguration",
    "sensitive_caching",

}

_INCOMPLETE_STATIC_GROUPS = {
    "dom_xss": "dom_xss_incomplete_correlated_flow",
    "postmessage_trust": "postmessage_incomplete_correlated_flow",
    "open_redirect": "open_redirect_incomplete_correlated_flow",
}


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

    if family == "account_enumeration":
        return analyze_account_enumeration_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=stored["endpoint"],
            method=stored["method"],
            body_fields=stored["body_fields"],
            query_fields=stored["query_fields"],
            details=stored["details"],
            business_context=stored["business_context"],
            semantic_text=stored["semantic_text"],
        )

    details = stored["details"]
    if family == "dom_xss":
        return analyze_dom_xss_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=stored["endpoint"],
            method=stored["method"],
            source_kind=str(details.get("source_kind") or details.get("dom_source") or ""),
            sink_kind=str(details.get("sink_kind") or details.get("dom_sink") or ""),
            snippet=stored["semantic_text"],
            confidence=_base.parse_int(details.get("confidence"), 0),
            details=details,
            business_context=stored["business_context"],
        )

    if family == "postmessage_trust":
        return analyze_postmessage_trust_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=stored["endpoint"],
            method=stored["method"],
            source_kind=str(details.get("source_kind") or details.get("message_source") or "postMessage"),
            sink_kind=str(details.get("sink_kind") or details.get("message_sink") or ""),
            snippet=stored["semantic_text"],
            confidence=_base.parse_int(details.get("confidence"), 0),
            details=details,
            business_context=stored["business_context"],
        )

    if family == "open_redirect":
        return analyze_open_redirect_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=stored["endpoint"],
            method=stored["method"],
            source_kind=str(
                details.get("source_kind")
                or details.get("redirect_source")
                or details.get("redirect_parameter")
                or "redirect_parameter"
            ),
            sink_kind=str(details.get("sink_kind") or details.get("navigation_sink") or "navigation"),
            snippet=stored["semantic_text"],
            confidence=_base.parse_int(details.get("confidence"), 0),
            details=details,
            business_context=stored["business_context"],
        )

    if family == "ssrf":
        return analyze_ssrf_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=stored["endpoint"],
            method=stored["method"],
            body_fields=stored["body_fields"],
            query_fields=stored["query_fields"],
            details=details,
            business_context=stored["business_context"],
            semantic_text=stored["semantic_text"],
        )

    if family == "file_upload":
        return analyze_file_upload_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=stored["endpoint"],
            method=stored["method"],
            body_fields=stored["body_fields"],
            query_fields=stored["query_fields"],
            details=details,
            business_context=stored["business_context"],
            semantic_text=stored["semantic_text"],
        )

    if family == "path_traversal":
        return analyze_path_traversal_signal(
            db, analysis_id=analysis_id, target=target, endpoint=stored["endpoint"], method=stored["method"],
            body_fields=stored["body_fields"], query_fields=stored["query_fields"], path_fields=stored["path_fields"],
            details=details, business_context=stored["business_context"], semantic_text=stored["semantic_text"],
        )

    if family == "information_disclosure":
        return analyze_information_disclosure_signal(
            db, analysis_id=analysis_id, target=target, endpoint=stored["endpoint"], method=stored["method"],
            body_fields=stored["body_fields"], query_fields=stored["query_fields"], path_fields=stored["path_fields"],
            details=details, business_context=stored["business_context"], semantic_text=stored["semantic_text"],
        )


    if family == "business_logic":
        return analyze_business_logic_signal(
  db, analysis_id=analysis_id, target=target, endpoint=stored["endpoint"], method=stored["method"],
  body_fields=stored["body_fields"], query_fields=stored["query_fields"], path_fields=stored["path_fields"],
  details=details, business_context=stored["business_context"], semantic_text=stored["semantic_text"],
        )
    if family == "race_condition":
        return analyze_race_condition_signal(
  db, analysis_id=analysis_id, target=target, endpoint=stored["endpoint"], method=stored["method"],
  body_fields=stored["body_fields"], query_fields=stored["query_fields"], path_fields=stored["path_fields"],
  details=details, business_context=stored["business_context"], semantic_text=stored["semantic_text"],
        )
    if family == "cors_misconfiguration":
        return analyze_cors_misconfiguration_signal(
  db, analysis_id=analysis_id, target=target, endpoint=stored["endpoint"], details=details,
  business_context=stored["business_context"], semantic_text=stored["semantic_text"],
        )
    if family == "sensitive_caching":
        return analyze_sensitive_caching_signal(
  db, analysis_id=analysis_id, target=target, endpoint=stored["endpoint"], details=details,
  business_context=stored["business_context"], semantic_text=stored["semantic_text"],
        )

    return None


def _collapse_incomplete_sources(
    support: list[dict[str, Any]],
    family_meta: Mapping[str, Any] | None,
    *,
    family: str,
) -> list[dict[str, Any]]:
    if not family_meta or bool(family_meta.get("confirmation_ready_from_stored_target_evidence")):
        return support
    group = _INCOMPLETE_STATIC_GROUPS.get(family)
    if not group:
        return support
    collapsed: list[dict[str, Any]] = []
    for raw in support:
        item = dict(raw)
        item["source_group"] = group
        collapsed.append(item)
    return collapsed


def _persist_family_meta(db: Any, result: dict[str, Any], family_meta: Mapping[str, Any]) -> dict[str, Any]:
    assessment = dict(result.get("assessment") or {})
    assessment["family_analyzer"] = dict(family_meta)
    assessment["candidate_family_analyzer_integration_version"] = CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION
    result["assessment"] = assessment
    db.execute(
        "UPDATE analysis_hypotheses SET admission_json=? WHERE hypothesis_id=?",
        (_base.json_dumps(assessment), str(result.get("hypothesis_id") or "")),
    )
    return result


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
    if family in _DEDICATED_ALERT_FAMILIES:
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
            support = _collapse_incomplete_sources(support, family_meta, family=family)

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
        result = _persist_family_meta(db, result, family_meta)
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


def _semantic_runtime_details(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    js_url: str,
    unit_types: tuple[str, ...],
    result_key: str,
) -> dict[str, Any]:
    placeholders = ",".join("?" for _ in unit_types)
    rows = db.all(
        f"""SELECT unit_type,unit_key,value_json,confidence
        FROM semantic_js_units
        WHERE analysis_id=? AND target=? AND js_url=?
          AND unit_type IN ({placeholders})
        ORDER BY confidence DESC,unit_type,unit_key""",
        (analysis_id, target, js_url, *unit_types),
    )
    observations: list[dict[str, Any]] = []
    for row in rows:
        value = _base._loads(row["value_json"], {})
        item = dict(value) if isinstance(value, Mapping) else {}
        item.setdefault("unit_type", str(row["unit_type"] or ""))
        item.setdefault("unit_key", str(row["unit_key"] or ""))
        item.setdefault("confidence", _base.parse_int(row["confidence"], 0))
        observations.append(item)
    return {result_key: observations} if observations else {}


def _dom_runtime_details(db: Any, *, analysis_id: str, target: str, js_url: str) -> dict[str, Any]:
    return _semantic_runtime_details(
        db,
        analysis_id=analysis_id,
        target=target,
        js_url=js_url,
        unit_types=("dom_runtime_observation", "dom_xss_runtime", "runtime_dom_flow", "dom_sanitization"),
        result_key="dom_runtime_observations",
    )


def _postmessage_runtime_details(db: Any, *, analysis_id: str, target: str, js_url: str) -> dict[str, Any]:
    return _semantic_runtime_details(
        db,
        analysis_id=analysis_id,
        target=target,
        js_url=js_url,
        unit_types=(
            "postmessage_runtime_observation",
            "web_message_runtime",
            "message_runtime_observation",
            "postmessage_trust_observation",
        ),
        result_key="postmessage_runtime_observations",
    )


def _open_redirect_runtime_details(db: Any, *, analysis_id: str, target: str, js_url: str) -> dict[str, Any]:
    return _semantic_runtime_details(
        db,
        analysis_id=analysis_id,
        target=target,
        js_url=js_url,
        unit_types=(
            "redirect_runtime_observation",
            "open_redirect_runtime",
            "navigation_runtime_observation",
            "client_redirect_observation",
        ),
        result_key="redirect_runtime_observations",
    )


def _record_migrated_static_hypothesis(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    row: Mapping[str, Any],
    family: str,
    analyzer: Callable[..., dict[str, Any] | None],
    runtime_details: dict[str, Any],
    fallback_variant: str,
    fallback_candidate_variant: str,
    fallback_summary: str,
) -> bool:
    target = str(row["target"])
    js_url = str(row["js_url"])
    source = str(row["source_kind"])
    sink = str(row["sink_kind"])
    confidence = _base.parse_int(row["confidence"], 0)
    dedicated = analyzer(
        db,
        analysis_id=analysis_id,
        target=target,
        js_url=js_url,
        endpoint=js_url,
        method="GET",
        source_kind=source,
        sink_kind=sink,
        snippet=str(row["snippet"] or ""),
        confidence=confidence,
        details=runtime_details,
        business_context="general",
    )
    if not dedicated:
        return False

    family_meta = dict(dedicated.get("family_analyzer") or {})
    support = [dict(item) for item in dedicated.get("support", []) if isinstance(item, Mapping)]
    support = _collapse_incomplete_sources(support, family_meta, family=family)
    contradict = [dict(item) for item in dedicated.get("contradict", []) if isinstance(item, Mapping)]
    source_ref = f"js-dataflow:{js_url}:{source}:{sink}"
    hypothesis = _ORIGINAL_RECORD_HYPOTHESIS(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=None,
        asset="",
        endpoint=js_url,
        source_ref=source_ref,
        family=family,
        variant=str(dedicated.get("variant") or fallback_variant),
        support=support,
        contradict=contradict,
        missing=[str(item) for item in dedicated.get("missing", []) if str(item)],
        rule_ids=[str(item) for item in dedicated.get("rule_ids", []) if str(item)],
        summary=str(dedicated.get("summary") or fallback_summary),
    )
    if family_meta:
        hypothesis = _persist_family_meta(db, hypothesis, family_meta)

    if not bool(hypothesis.get("assessment", {}).get("admitted")):
        return False
    if not bool(family_meta.get("confirmation_ready_from_stored_target_evidence")):
        return False

    support = hypothesis["support"]
    contradict = hypothesis["contradict"]
    missing = hypothesis["missing"]
    rules = hypothesis["rule_ids"]
    likelihood = _base._clamp(
        30
        + confidence * 0.30
        + sum(_base.parse_int(item.get("weight"), 0) for item in support)
        + sum(_base.parse_int(item.get("weight"), 0) for item in contradict)
    )
    strength = _evidence_strength_with_family_directness(
        confidence,
        support,
        contradict,
        direct=bool(dedicated.get("direct")),
    )
    candidate_id = _base._insert_candidate(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=None,
        asset="",
        endpoint=js_url,
        source_ref=source_ref,
        family=family,
        variant=str(dedicated.get("variant") or fallback_candidate_variant),
        likelihood=likelihood,
        evidence_strength=strength,
        impact_potential=_base._impact(_base.BUG_FAMILIES[family]["impact"], "general"),
        support=support,
        contradict=contradict,
        missing=missing,
        rule_ids=rules,
        summary=str(dedicated.get("summary") or fallback_summary),
    )
    _base.mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)
    return True


def _record_dom_static_hypothesis(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    row: Mapping[str, Any],
) -> bool:
    target = str(row["target"])
    js_url = str(row["js_url"])
    return _record_migrated_static_hypothesis(
        db,
        analysis_id=analysis_id,
        run_id=run_id,
        row=row,
        family="dom_xss",
        analyzer=analyze_dom_xss_signal,
        runtime_details=_dom_runtime_details(db, analysis_id=analysis_id, target=target, js_url=js_url),
        fallback_variant="static_dom_flow",
        fallback_candidate_variant="runtime_unsanitized_dom_flow",
        fallback_summary="DOM-XSS client-side flow hypothesis.",
    )


def _record_postmessage_static_hypothesis(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    row: Mapping[str, Any],
) -> bool:
    target = str(row["target"])
    js_url = str(row["js_url"])
    return _record_migrated_static_hypothesis(
        db,
        analysis_id=analysis_id,
        run_id=run_id,
        row=row,
        family="postmessage_trust",
        analyzer=analyze_postmessage_trust_signal,
        runtime_details=_postmessage_runtime_details(db, analysis_id=analysis_id, target=target, js_url=js_url),
        fallback_variant="static_message_handler",
        fallback_candidate_variant="untrusted_sender_to_sensitive_consumer",
        fallback_summary="postMessage trust hypothesis.",
    )


def _record_open_redirect_static_hypothesis(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    row: Mapping[str, Any],
) -> bool:
    target = str(row["target"])
    js_url = str(row["js_url"])
    return _record_migrated_static_hypothesis(
        db,
        analysis_id=analysis_id,
        run_id=run_id,
        row=row,
        family="open_redirect",
        analyzer=analyze_open_redirect_signal,
        runtime_details=_open_redirect_runtime_details(db, analysis_id=analysis_id, target=target, js_url=js_url),
        fallback_variant="static_source_to_navigation_sink",
        fallback_candidate_variant="user_controlled_external_destination",
        fallback_summary="Open Redirect navigation hypothesis.",
    )



def _record_source_map_static_hypothesis(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    row: Mapping[str, Any],
) -> bool:
    target = str(row["target"] or "")
    js_url = str(row["js_url"] or "")
    source_map_url = str(row["source_map_url"] or "")
    source_count = _base.parse_int(row["source_count"], 0)
    internal_count = _base.parse_int(row["internal_source_count"], 0)
    details = {
        "source_map_url": source_map_url,
        "js_url": js_url,
        "source_count": source_count,
        "internal_source_count": internal_count,
        "collector_download_succeeded": source_count > 0,
    }
    dedicated = analyze_source_map_exposure_signal(
        db,
        analysis_id=analysis_id,
        target=target,
        source_map_url=source_map_url,
        js_url=js_url,
        source_count=source_count,
        internal_source_count=internal_count,
        details=details,
        business_context="general",
    )
    if not dedicated:
        return False
    family_meta = dict(dedicated.get("family_analyzer") or {})
    support = [dict(item) for item in dedicated.get("support", []) if isinstance(item, Mapping)]
    contradict = [dict(item) for item in dedicated.get("contradict", []) if isinstance(item, Mapping)]
    source_ref = f"source-map:{js_url}"
    hypothesis = _ORIGINAL_RECORD_HYPOTHESIS(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=None,
        asset="",
        endpoint=source_map_url,
        source_ref=source_ref,
        family="source_map_exposure",
        variant=str(dedicated.get("variant") or "source_map_reference_only"),
        support=support,
        contradict=contradict,
        missing=[str(item) for item in dedicated.get("missing", []) if str(item)],
        rule_ids=[str(item) for item in dedicated.get("rule_ids", []) if str(item)],
        summary=str(dedicated.get("summary") or "Source-map exposure hypothesis."),
    )
    if family_meta:
        hypothesis = _persist_family_meta(db, hypothesis, family_meta)
    if not bool(hypothesis.get("assessment", {}).get("admitted")):
        return False
    if not bool(family_meta.get("confirmation_ready_from_stored_target_evidence")):
        return False
    support = hypothesis["support"]
    contradict = hypothesis["contradict"]
    candidate_id = _base._insert_candidate(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=None,
        asset="",
        endpoint=source_map_url,
        source_ref=source_ref,
        family="source_map_exposure",
        variant=str(dedicated.get("variant") or "public_internal_source_map"),
        likelihood=_base._clamp(48 + min(24, internal_count * 3) + (12 if source_count else 0)),
        evidence_strength=_evidence_strength_with_family_directness(86, support, contradict, direct=bool(dedicated.get("direct"))),
        impact_potential=_base._impact(_base.BUG_FAMILIES["source_map_exposure"]["impact"], "general"),
        support=support,
        contradict=contradict,
        missing=hypothesis["missing"],
        rule_ids=hypothesis["rule_ids"],
        summary=str(dedicated.get("summary") or "A publicly reachable source map exposes internal source structure."),
    )
    _base.mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)
    return True

def _secret_marker_classes(db: Any, *, target: str, js_url: str) -> list[str]:
    rows = db.all(
        "SELECT value FROM js_indicators WHERE target=? AND js_url=? AND kind='sensitive_marker'",
        (target, js_url),
    )
    classes: set[str] = set()
    for row in rows:
        label = str(row["value"] or "").split(":count=", 1)[0].strip().lower()
        if label:
            classes.add(label)
    return sorted(classes)


def _record_secret_static_hypothesis(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    rows: list[Mapping[str, Any]],
) -> bool:
    if not rows:
        return False
    target = str(rows[0]["target"] or "")
    js_url = str(rows[0]["js_url"] or "")
    observations: list[dict[str, Any]] = []
    max_confidence = 0
    for row in rows:
        confidence = _base.parse_int(row["confidence"], 0)
        max_confidence = max(max_confidence, confidence)
        reasons = _base._loads(row["reasons_json"], [])
        observations.append({
            "secret_kind": str(row["secret_kind"] or ""),
            "value_fingerprint": str(row["value_fingerprint"] or ""),
            "confidence": confidence,
            "assessment": str(row["assessment"] or "candidate"),
            "reasons": reasons if isinstance(reasons, list) else [],
        })
    dedicated = analyze_secret_exposure_signal(
        db,
        analysis_id=analysis_id,
        target=target,
        js_url=js_url,
        observations=observations,
        marker_classes=_secret_marker_classes(db, target=target, js_url=js_url),
        details={},
        business_context="general",
    )
    if not dedicated:
        return False
    family_meta = dict(dedicated.get("family_analyzer") or {})
    support = [dict(item) for item in dedicated.get("support", []) if isinstance(item, Mapping)]
    contradict = [dict(item) for item in dedicated.get("contradict", []) if isinstance(item, Mapping)]
    source_ref = f"secret:{js_url}"
    hypothesis = _ORIGINAL_RECORD_HYPOTHESIS(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=None,
        asset="",
        endpoint=js_url,
        source_ref=source_ref,
        family="secret_exposure",
        variant=str(dedicated.get("variant") or "secret_pattern_surface"),
        support=support,
        contradict=contradict,
        missing=[str(item) for item in dedicated.get("missing", []) if str(item)],
        rule_ids=[str(item) for item in dedicated.get("rule_ids", []) if str(item)],
        summary=str(dedicated.get("summary") or "Credential/token exposure hypothesis."),
    )
    if family_meta:
        hypothesis = _persist_family_meta(db, hypothesis, family_meta)
    if not bool(hypothesis.get("assessment", {}).get("admitted")):
        return False

    support = hypothesis["support"]
    contradict = hypothesis["contradict"]
    direct = bool(dedicated.get("direct"))
    likelihood = _base._clamp(
        34 + max_confidence * 0.45 + (18 if direct else 0)
        + sum(_base.parse_int(item.get("weight"), 0) for item in contradict)
    )
    candidate_id = _base._insert_candidate(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=None,
        asset="",
        endpoint=js_url,
        source_ref=source_ref,
        family="secret_exposure",
        variant=str(dedicated.get("variant") or "credential_material_candidate"),
        likelihood=likelihood,
        evidence_strength=_evidence_strength_with_family_directness(
            max_confidence, support, contradict, direct=direct
        ),
        impact_potential=_base._impact(_base.BUG_FAMILIES["secret_exposure"]["impact"], "general"),
        support=support,
        contradict=contradict,
        missing=hypothesis["missing"],
        rule_ids=hypothesis["rule_ids"],
        summary=str(dedicated.get("summary") or "Redacted credential/token material is exposed in client-delivered JavaScript."),
    )
    _base.mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)
    return True


def _graphql_runtime_details(db: Any, *, analysis_id: str, target: str, js_url: str) -> dict[str, Any]:
    return _semantic_runtime_details(
        db,
        analysis_id=analysis_id,
        target=target,
        js_url=js_url,
        unit_types=(
            "graphql_authorization_observation",
            "graphql_data_exposure_observation",
            "graphql_field_observation",
            "graphql_runtime_observation",
        ),
        result_key="graphql_runtime_observations",
    )


def _websocket_runtime_details(db: Any, *, analysis_id: str, target: str, js_url: str) -> dict[str, Any]:
    return _semantic_runtime_details(
        db,
        analysis_id=analysis_id,
        target=target,
        js_url=js_url,
        unit_types=(
            "websocket_authorization_observation",
            "websocket_runtime_observation",
            "subscription_observation",
            "channel_authorization_observation",
        ),
        result_key="websocket_runtime_observations",
    )


def _promote_static_family_result(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    target: str,
    endpoint: str,
    source_ref: str,
    family: str,
    dedicated: Mapping[str, Any],
    confidence: int,
) -> bool:
    family_meta = dict(dedicated.get("family_analyzer") or {})
    support = [dict(item) for item in dedicated.get("support", []) if isinstance(item, Mapping)]
    contradict = [dict(item) for item in dedicated.get("contradict", []) if isinstance(item, Mapping)]
    hypothesis = _ORIGINAL_RECORD_HYPOTHESIS(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=None,
        asset="",
        endpoint=endpoint,
        source_ref=source_ref,
        family=family,
        variant=str(dedicated.get("variant") or "stored_surface"),
        support=support,
        contradict=contradict,
        missing=[str(item) for item in dedicated.get("missing", []) if str(item)],
        rule_ids=[str(item) for item in dedicated.get("rule_ids", []) if str(item)],
        summary=str(dedicated.get("summary") or f"{family} hypothesis."),
    )
    if family_meta:
        hypothesis = _persist_family_meta(db, hypothesis, family_meta)
    if not bool(hypothesis.get("assessment", {}).get("admitted")):
        return False
    support = hypothesis["support"]
    contradict = hypothesis["contradict"]
    direct = bool(dedicated.get("direct"))
    candidate_id = _base._insert_candidate(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=None,
        asset="",
        endpoint=endpoint,
        source_ref=source_ref,
        family=family,
        variant=str(dedicated.get("variant") or "stored_surface"),
        likelihood=_base._clamp(
            30
            + confidence * 0.32
            + (12 if direct else 0)
            + sum(_base.parse_int(item.get("weight"), 0) for item in contradict)
        ),
        evidence_strength=_evidence_strength_with_family_directness(
            confidence, support, contradict, direct=direct
        ),
        impact_potential=_base._impact(_base.BUG_FAMILIES[family]["impact"], "general"),
        support=support,
        contradict=contradict,
        missing=hypothesis["missing"],
        rule_ids=hypothesis["rule_ids"],
        summary=str(dedicated.get("summary") or f"{family} hypothesis."),
    )
    _base.mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)
    return True


def _record_graphql_static_hypotheses(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    row: Mapping[str, Any],
) -> int:
    target = str(row["target"] or "")
    js_url = str(row["js_url"] or "")
    operation_name = str(row["operation_name"] or "")
    operation_type = str(row["operation_type"] or "query")
    confidence = _base.parse_int(row["confidence"], 0)
    raw_identifiers = _base._loads(row["identifiers_json"], [])
    raw_sensitive = _base._loads(row["sensitive_fields_json"], [])
    identifiers = [str(value) for value in raw_identifiers] if isinstance(raw_identifiers, list) else []
    sensitive = [str(value) for value in raw_sensitive] if isinstance(raw_sensitive, list) else []
    runtime = _graphql_runtime_details(
        db, analysis_id=analysis_id, target=target, js_url=js_url
    )
    promoted = 0
    if identifiers:
        dedicated = analyze_graphql_authorization_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint="/graphql",
            js_url=js_url,
            operation_name=operation_name,
            operation_type=operation_type,
            identifiers=identifiers,
            details=runtime,
            business_context="general",
        )
        if dedicated and _promote_static_family_result(
            db,
            analysis_id=analysis_id,
            run_id=run_id,
            target=target,
            endpoint="/graphql",
            source_ref=f"graphql:{js_url}:{operation_name}",
            family="graphql_authorization",
            dedicated=dedicated,
            confidence=confidence,
        ):
            promoted += 1
    if sensitive:
        dedicated = analyze_graphql_data_exposure_signal(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint="/graphql",
            js_url=js_url,
            operation_name=operation_name,
            operation_type=operation_type,
            sensitive_fields=sensitive,
            details=runtime,
            business_context="general",
        )
        if dedicated and _promote_static_family_result(
            db,
            analysis_id=analysis_id,
            run_id=run_id,
            target=target,
            endpoint="/graphql",
            source_ref=f"graphql-data:{js_url}:{operation_name}",
            family="graphql_data_exposure",
            dedicated=dedicated,
            confidence=confidence,
        ):
            promoted += 1
    return promoted


def _record_websocket_static_hypothesis(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    row: Mapping[str, Any],
) -> bool:
    target = str(row["target"] or "")
    js_url = str(row["js_url"] or "")
    source = str(row["source_kind"] or "")
    sink = str(row["sink_kind"] or "")
    confidence = _base.parse_int(row["confidence"], 0)
    dedicated = analyze_websocket_authorization_signal(
        db,
        analysis_id=analysis_id,
        target=target,
        endpoint=js_url,
        js_url=js_url,
        source_kind=source,
        sink_kind=sink,
        operation="websocket construction or messaging",
        details=_websocket_runtime_details(
            db, analysis_id=analysis_id, target=target, js_url=js_url
        ),
        semantic_text=str(row["snippet"] or ""),
        business_context="general",
    )
    if not dedicated:
        return False
    return _promote_static_family_result(
        db,
        analysis_id=analysis_id,
        run_id=run_id,
        target=target,
        endpoint=js_url,
        source_ref=f"js-dataflow:{js_url}:{source}:{sink}",
        family="websocket_authorization",
        dedicated=dedicated,
        confidence=confidence,
    )


class _MigratedStaticFilteredDatabase:
    """Delegate DB access while hiding migrated client-side rows from legacy insertion."""

    def __init__(self, db: Any):
        self._db = db

    def all(self, query: str, params: tuple[Any, ...] = ()) -> list[Any]:
        rows = self._db.all(query, params)
        lowered = str(query).lower()
        if "from source_map_intelligence" in lowered:
            return []
        if "from secret_intelligence" in lowered:
            return []
        if "from graphql_intelligence" in lowered:
            return []
        if "from js_dataflows" not in lowered:
            return rows
        filtered: list[Any] = []
        for row in rows:
            source = str(row["source_kind"] or "")
            sink = str(row["sink_kind"] or "")
            if is_postmessage_source(source):
                continue
            if is_dangerous_dom_sink(sink):
                continue
            if is_navigation_sink(sink):
                continue
            if sink.strip().lower() == "websocket":
                continue
            filtered.append(row)
        return filtered

    def __getattr__(self, name: str) -> Any:
        return getattr(self._db, name)


def _static_candidates_with_family_analyzers(db: Any, analysis_id: str, run_id: str, target: str | None) -> int:
    params: list[Any] = [analysis_id]
    target_clause = ""
    if target:
        target_clause = " AND target=?"
        params.append(target)
    secret_rows = db.all(f"SELECT * FROM secret_intelligence WHERE analysis_id=?{target_clause}", tuple(params))
    grouped_secrets: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in secret_rows:
        grouped_secrets.setdefault((str(row["target"] or ""), str(row["js_url"] or "")), []).append(row)
    migrated_count = 0
    for grouped_rows in grouped_secrets.values():
        if _record_secret_static_hypothesis(db, analysis_id=analysis_id, run_id=run_id, rows=grouped_rows):
            migrated_count += 1

    graphql_rows = db.all(f"SELECT * FROM graphql_intelligence WHERE analysis_id=?{target_clause}", tuple(params))
    for row in graphql_rows:
        migrated_count += _record_graphql_static_hypotheses(db, analysis_id=analysis_id, run_id=run_id, row=row)

    source_map_rows = db.all(f"SELECT * FROM source_map_intelligence WHERE analysis_id=?{target_clause}", tuple(params))
    for row in source_map_rows:
        if _record_source_map_static_hypothesis(db, analysis_id=analysis_id, run_id=run_id, row=row):
            migrated_count += 1

    rows = db.all(f"SELECT * FROM js_dataflows WHERE analysis_id=?{target_clause}", tuple(params))
    for row in rows:
        source = str(row["source_kind"] or "")
        sink = str(row["sink_kind"] or "")
        if is_postmessage_source(source):
            if _record_postmessage_static_hypothesis(db, analysis_id=analysis_id, run_id=run_id, row=row):
                migrated_count += 1
            continue
        if is_dangerous_dom_sink(sink):
            if _record_dom_static_hypothesis(db, analysis_id=analysis_id, run_id=run_id, row=row):
                migrated_count += 1
            continue
        if is_navigation_sink(sink):
            if _record_open_redirect_static_hypothesis(db, analysis_id=analysis_id, run_id=run_id, row=row):
                migrated_count += 1
            continue
        if sink.strip().lower() == "websocket":
            if _record_websocket_static_hypothesis(db, analysis_id=analysis_id, run_id=run_id, row=row):
                migrated_count += 1
            continue

    legacy_count = _ORIGINAL_STATIC_CANDIDATES(
        _MigratedStaticFilteredDatabase(db),
        analysis_id,
        run_id,
        target,
    )
    return migrated_count + legacy_count


_base.record_hypothesis = _record_hypothesis_with_family_analyzers
_base._evidence_strength = _evidence_strength_with_family_directness
_base._static_candidates = _static_candidates_with_family_analyzers
record_hypothesis = _record_hypothesis_with_family_analyzers
_evidence_strength = _evidence_strength_with_family_directness
_static_candidates = _static_candidates_with_family_analyzers

for _name, _value in vars(_base).items():
    if not _name.startswith("__"):
        globals()[_name] = _value
record_hypothesis = _record_hypothesis_with_family_analyzers
_evidence_strength = _evidence_strength_with_family_directness
_static_candidates = _static_candidates_with_family_analyzers

__all__ = [name for name in globals() if not name.startswith("__")]
