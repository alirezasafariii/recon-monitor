from __future__ import annotations

"""Offline bridge from stored Recon/Analysis intelligence to family-analyzer context.

The bridge is intentionally conservative. It may add *surface/context* signals
that are already supported by stored Recon Monitor observations, but it never
creates decisive bypass/exploitation evidence, never performs network I/O, and
never turns taxonomy/write-up knowledge into target evidence.

This closes an integration gap between Semantic/Behavioral Intelligence tables
and the dedicated vulnerability-family analyzers. Decisive and unsafe evidence
must still come from explicit stored target observations handled by each family
analyzer and Family Reasoning.
"""

import json
import re
import urllib.parse
from collections import OrderedDict
from typing import Any, Mapping

FAMILY_SIGNAL_BRIDGE_VERSION = "1.0.0"
FAMILY_SIGNAL_BRIDGE_RULE_VERSION = "2026.08.14.1"

_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SENSITIVE_ROUTE_MARKERS = {
    "account", "admin", "billing", "checkout", "customer", "invoice", "order",
    "payment", "profile", "settings", "staff", "tenant", "user", "wallet",
}
_CLOUD_MARKERS = (
    "amazonaws.com", "s3.", ".s3", "storage.googleapis.com", "storage.cloud.google.com",
    ".blob.core.windows.net", "azureedge.net", "cloudfront.net", "gcs",
)
_BACKUP_SUFFIXES = (
    ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".zip", ".tar", ".tar.gz",
    ".tgz", ".sql", ".dump", "~",
)

# Signals in this set are deliberately prohibited from bridge synthesis. The
# bridge is a discovery/context adapter, not a confirmation engine.
_FORBIDDEN_DECISIVE_SUFFIXES = (
    "_bypass_observed",
    "_accepted_observed",
    "_execution_observed",
    "_influence_observed",
    "_differential",
    "_violation",
    "_confirmed",
)

_TARGET_UNIT_CACHE_MAX = 512
_ENDPOINT_CONTEXT_CACHE_MAX = 4096
_TARGET_UNIT_CACHE: "OrderedDict[tuple[int, str, str], tuple[dict[str, Any], ...]]" = OrderedDict()
_ENDPOINT_CONTEXT_CACHE: "OrderedDict[tuple[int, str, str, str], dict[str, Any]]" = OrderedDict()


def clear_family_signal_bridge_cache() -> None:
    """Clear bounded process-local enrichment caches.

    Analysis IDs are unique, so normal runs do not require explicit invalidation.
    The hook exists for tests, long-lived maintenance processes, and replay tools.
    """

    _TARGET_UNIT_CACHE.clear()
    _ENDPOINT_CONTEXT_CACHE.clear()


def _cache_put(cache: OrderedDict, key: tuple[Any, ...], value: Any, maximum: int) -> Any:
    cache[key] = value
    cache.move_to_end(key)
    while len(cache) > maximum:
        cache.popitem(last=False)
    return value


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _safe_all(db: Any, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    if db is None:
        return []
    try:
        return [dict(row) for row in db.all(sql, params)]
    except Exception:
        # Compatibility with older/minimal test databases is fail-open only for
        # enrichment: missing advisory tables must never break core analysis.
        return []


def _safe_one(db: Any, sql: str, params: tuple[Any, ...]) -> dict[str, Any]:
    rows = _safe_all(db, sql, params)
    return rows[0] if rows else {}


def _target_semantic_units(db: Any, analysis_id: str, target: str) -> tuple[dict[str, Any], ...]:
    key = (id(db), analysis_id, target)
    cached = _TARGET_UNIT_CACHE.get(key)
    if cached is not None:
        _TARGET_UNIT_CACHE.move_to_end(key)
        return cached
    rows = tuple(
        _safe_all(
            db,
            "SELECT js_url,unit_type,unit_key,value_json,confidence FROM semantic_js_units "
            "WHERE analysis_id=? AND target=? ORDER BY confidence DESC LIMIT 2000",
            (analysis_id, target),
        )
    )
    return _cache_put(_TARGET_UNIT_CACHE, key, rows, _TARGET_UNIT_CACHE_MAX)


def _endpoint_context_snapshot(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
) -> dict[str, Any]:
    key = (id(db), analysis_id, target, endpoint)
    cached = _ENDPOINT_CONTEXT_CACHE.get(key)
    if cached is not None:
        _ENDPOINT_CONTEXT_CACHE.move_to_end(key)
        return cached

    contract = _safe_one(
        db,
        "SELECT * FROM endpoint_contracts WHERE analysis_id=? AND target=? AND endpoint=? "
        "ORDER BY confidence DESC LIMIT 1",
        (analysis_id, target, endpoint),
    )
    auth = _safe_one(
        db,
        "SELECT * FROM authentication_boundaries WHERE analysis_id=? AND target=? AND endpoint=? "
        "ORDER BY confidence DESC LIMIT 1",
        (analysis_id, target, endpoint),
    )
    shape = _safe_one(
        db,
        "SELECT * FROM response_shape_fingerprints WHERE analysis_id=? AND target=? AND endpoint=? "
        "ORDER BY confidence DESC LIMIT 1",
        (analysis_id, target, endpoint),
    )
    protocols = (
        _safe_all(
            db,
            "SELECT protocol,kind,entity,confidence,severity,summary,evidence_json FROM protocol_findings "
            "WHERE analysis_id=? AND target=? AND entity=? ORDER BY confidence DESC LIMIT 50",
            (analysis_id, target, endpoint),
        )
        if endpoint
        else []
    )
    technologies = (
        _safe_all(
            db,
            "SELECT url,technology,confidence,evidence_json FROM technology_observations "
            "WHERE target=? AND is_current=1 AND url=? ORDER BY confidence DESC LIMIT 100",
            (target, endpoint),
        )
        if endpoint
        else []
    )

    try:
        endpoint_path = urllib.parse.urlsplit(
            endpoint if "://" in endpoint else f"https://placeholder.invalid/{endpoint.lstrip('/')}"
        ).path
    except ValueError:
        endpoint_path = endpoint

    related_units: list[dict[str, Any]] = []
    for unit in _target_semantic_units(db, analysis_id, target):
        value = str(_loads(unit.get("value_json"), {}).get("value") or "")
        if endpoint and (
            endpoint in value
            or (endpoint_path and endpoint_path != "/" and endpoint_path in value)
        ):
            related_units.append(unit)

    snapshot = {
        "contract": contract,
        "auth": auth,
        "shape": shape,
        "protocols": protocols,
        "technologies": technologies,
        "endpoint_path": endpoint_path,
        "related_units": related_units,
    }
    return _cache_put(_ENDPOINT_CONTEXT_CACHE, key, snapshot, _ENDPOINT_CONTEXT_CACHE_MAX)


def _status_code(details: Mapping[str, Any]) -> int:
    candidates = [details.get("status_code")]
    for key in ("new", "current", "after", "response"):
        nested = details.get(key)
        if isinstance(nested, Mapping):
            candidates.append(nested.get("status_code"))
    for value in candidates:
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _content_type(details: Mapping[str, Any], contract: Mapping[str, Any] | None = None) -> str:
    values = [details.get("content_type")]
    for key in ("new", "current", "after", "response"):
        nested = details.get(key)
        if isinstance(nested, Mapping):
            values.append(nested.get("content_type"))
    if contract:
        values.append(contract.get("content_type"))
    return " ".join(str(value or "") for value in values).lower()


def _header_map(details: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    candidates: list[Any] = []
    for key in ("headers", "response_headers", "headers_json", "new_headers", "current_headers"):
        if details.get(key):
            candidates.append(details.get(key))
    for key in ("new", "current", "after", "response"):
        nested = details.get(key)
        if isinstance(nested, Mapping):
            for header_key in ("headers", "response_headers", "headers_json"):
                if nested.get(header_key):
                    candidates.append(nested.get(header_key))
    for raw in candidates:
        decoded = _loads(raw, raw)
        if isinstance(decoded, Mapping):
            for key, value in decoded.items():
                result[str(key).strip().lower()] = str(value).strip()
        elif isinstance(decoded, list):
            for item in decoded:
                if isinstance(item, str) and ":" in item:
                    key, value = item.split(":", 1)
                    result[key.strip().lower()] = value.strip()
    return result


def _field_blob(details: Mapping[str, Any], contract: Mapping[str, Any] | None = None) -> str:
    values: list[str] = []
    if contract:
        input_fields = _loads(contract.get("input_fields_json"), {})
        output_fields = _loads(contract.get("output_fields_json"), [])
        values.append(json.dumps(input_fields, sort_keys=True))
        values.append(json.dumps(output_fields, sort_keys=True))
    for key in ("body_fields", "query_parameters", "path_parameters", "input_fields", "output_fields"):
        raw = details.get(key)
        if raw:
            values.append(json.dumps(raw, sort_keys=True) if isinstance(raw, (dict, list)) else str(raw))
    return " ".join(values).lower()


def _add_signal(
    enriched: dict[str, Any],
    sources: dict[str, list[str]],
    signal: str,
    source: str,
) -> None:
    if not signal or any(signal.endswith(suffix) for suffix in _FORBIDDEN_DECISIVE_SUFFIXES):
        return
    # Never overwrite explicit target evidence supplied by an importer,
    # collector or controlled validation record.
    if signal not in enriched:
        enriched[signal] = True
    sources.setdefault(signal, [])
    if source not in sources[signal]:
        sources[signal].append(source)


def _query_duplicates(endpoint: str) -> bool:
    try:
        query = urllib.parse.urlsplit(endpoint).query
    except ValueError:
        return False
    if not query:
        return False
    names = [name for name, _ in urllib.parse.parse_qsl(query, keep_blank_values=True)]
    return len(names) != len(set(names))


def _external_api_units(units: list[dict[str, Any]], target: str) -> list[str]:
    target_host = (urllib.parse.urlsplit(target if "://" in target else f"https://{target}").hostname or target).lower()
    external: list[str] = []
    for unit in units:
        if str(unit.get("unit_type") or "") != "api_call":
            continue
        value = str(_loads(unit.get("value_json"), {}).get("value") or "")
        try:
            host = (urllib.parse.urlsplit(value).hostname or "").lower()
        except ValueError:
            host = ""
        if host and target_host and host != target_host and not host.endswith("." + target_host):
            external.append(value)
    return external


def augment_family_details(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str,
    details: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Merge existing analysis context into the family-analyzer details envelope.

    Only discovery/surface context is synthesized. Existing explicit evidence is
    preserved verbatim and no decisive family signal is manufactured.
    """

    enriched = dict(details or {})
    if not analysis_id or not target:
        return enriched

    method = str(method or enriched.get("method") or "UNKNOWN").upper()
    endpoint = str(endpoint or enriched.get("resolved_url") or enriched.get("url") or "")
    sources: dict[str, list[str]] = {}

    snapshot = _endpoint_context_snapshot(
        db,
        analysis_id=analysis_id,
        target=target,
        endpoint=endpoint,
    )
    contract = snapshot["contract"]
    auth = snapshot["auth"]
    shape = snapshot["shape"]
    protocols = snapshot["protocols"]
    technologies = snapshot["technologies"]
    endpoint_path = str(snapshot["endpoint_path"] or "")
    related_units = snapshot["related_units"]

    text = " ".join(
        [
            endpoint,
            endpoint_path,
            str(enriched.get("title") or ""),
            str(enriched.get("category") or ""),
            str(enriched.get("change_class") or ""),
            _field_blob(enriched, contract),
            " ".join(str(_loads(unit.get("value_json"), {}).get("value") or "") for unit in related_units[:200]),
            " ".join(str(row.get("summary") or "") for row in protocols),
        ]
    ).lower()
    content_type = _content_type(enriched, contract)
    headers = _header_map(enriched)
    status = _status_code(enriched)
    auth_boundary = str(auth.get("boundary") or contract.get("auth_boundary") or "").lower()

    # Phase-one discovery context.
    if any(token in text for token in ("batch", "bulk", "upload", "export", "report", "search", "render", "resize", "convert", "generate", "send")):
        _add_signal(enriched, sources, "resource_consuming_operation", "semantic_surface")
    if any(token in text for token in ("debug", "/admin", "management", "actuator", "swagger", "openapi", "server-status", "directory")):
        _add_signal(enriched, sources, "configuration_surface", "deployment_surface")
    if re.search(r"/(?:api/)?v\d+(?:/|$)", text) or any(token in text for token in ("/swagger", "/openapi", "/graphql", "/actuator")):
        _add_signal(enriched, sources, "api_inventory_surface", "versioned_or_documented_api_surface")
    external_calls = _external_api_units(related_units, target)
    if external_calls:
        _add_signal(enriched, sources, "third_party_api_integration", "semantic_js_external_api_call")
        _add_signal(enriched, sources, "upstream_data_trust_boundary", "semantic_js_external_api_call")

    # Phase-two surface context. These signals intentionally describe where to
    # look, not whether a vulnerability exists.
    try:
        query_pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(endpoint).query, keep_blank_values=True)
    except ValueError:
        query_pairs = []
    if query_pairs or any(token in text for token in ("search", "query", "message", "error", "return", "callback")):
        _add_signal(enriched, sources, "reflected_input_surface", "request_or_route_input_surface")
    if method in _STATE_CHANGING_METHODS and any(token in text for token in ("comment", "profile", "bio", "description", "message", "review", "post", "content")):
        _add_signal(enriched, sources, "persistent_user_content_surface", "state_changing_content_surface")
    if method in {"PUT", "PATCH", "DELETE"} or "allowed_methods" in text or "allow:" in text:
        _add_signal(enriched, sources, "method_authorization_surface", "http_method_surface")
    if _query_duplicates(endpoint):
        _add_signal(enriched, sources, "duplicate_parameter_surface", "duplicate_query_parameter")
    if any(token in text for token in ("filter", "where", "order", "sort", "query", "find", "search")):
        _add_signal(enriched, sources, "orm_query_surface", "query_semantics")
    if "xml" in content_type or any(token in text for token in ("xml", "soap", "saml", "doctype", "dtd")):
        _add_signal(enriched, sources, "xml_parser_surface", "xml_content_or_route")
        _add_signal(enriched, sources, "xml_external_entity_surface", "xml_content_or_route")
    if any(token in text for token in (".shtml", " ssi ", "server side include")):
        _add_signal(enriched, sources, "ssi_processing_surface", "ssi_semantics")
    if "xml" in text and any(token in text for token in ("xpath", "node", "filter", "search")):
        _add_signal(enriched, sources, "xpath_query_surface", "xml_query_semantics")
    if any(token in text for token in ("smtp", "imap", "/mail", "recipient", "subject", "folder")):
        _add_signal(enriched, sources, "mail_protocol_command_surface", "mail_semantics")
    if any(token in text for token in ("eval", "expression", "dynamic code", "execute code")):
        _add_signal(enriched, sources, "dynamic_code_execution_surface", "dynamic_code_semantics")
    if any(token in text for token in ("include", "template", "view", "page", "module")) and any(token in text for token in ("file", "path", "template", "view")):
        _add_signal(enriched, sources, "dynamic_file_include_surface", "file_include_semantics")
    if any(token in text for token in ("printf", "sprintf", "format_string", "log format", "logger.format")):
        _add_signal(enriched, sources, "format_string_surface", "formatting_semantics")
    if any(token in text for token in ("redirect", "location", "filename", "download", "header", "cookie")):
        _add_signal(enriched, sources, "response_header_input_surface", "response_header_semantics")
    if any(token in text for token in ("proxy", "gateway", "load balancer", "content-length", "transfer-encoding")) or any(
        any(marker in str(row.get("technology") or "").lower() for marker in ("nginx", "haproxy", "envoy", "traefik", "cloudflare", "fastly"))
        for row in technologies
    ):
        _add_signal(enriched, sources, "multi_hop_http_parser_surface", "proxy_or_gateway_surface")
    if any(token in text for token in ("x-forwarded-host", "host_header", "reset_url", "absolute url", "absolute_url")):
        _add_signal(enriched, sources, "host_derived_security_surface", "host_semantics")
    if any(token in text for token in ("csv", "excel", "spreadsheet", "export", "report")):
        _add_signal(enriched, sources, "spreadsheet_export_surface", "export_semantics")
    if any(token in text for token in ("__proto__", "prototype", "object.assign", "merge(", "deepmerge", "lodash.merge")):
        _add_signal(enriched, sources, "object_merge_surface", "object_merge_semantics")
    if any(token in text for token in ("serialize", "deserialize", "pickle", "object stream", "binary formatter")):
        _add_signal(enriched, sources, "serialized_object_input_surface", "serialization_semantics")
    if method in _STATE_CHANGING_METHODS and auth_boundary in {"session_required", "mixed"}:
        _add_signal(enriched, sources, "cookie_authenticated_state_change_surface", "session_bound_state_change")
    if any(marker in text for marker in _SENSITIVE_ROUTE_MARKERS) and ("html" in content_type or not content_type):
        _add_signal(enriched, sources, "sensitive_ui_frame_surface", "sensitive_ui_semantics")
    if "html" in content_type or any(token in text for token in ("preview", "content", "description", "message", "html")):
        _add_signal(enriched, sources, "html_rendering_surface", "html_rendering_semantics")
    if any(token in text for token in ("style", "theme", "css", "color", "font")):
        _add_signal(enriched, sources, "style_injection_surface", "style_semantics")
    if any(token in text for token in ("src", "href", "resource", "asset", "image", "script", "stylesheet")):
        _add_signal(enriched, sources, "client_resource_url_surface", "client_resource_semantics")
    if any(token in text for token in ("jsonp", "callback=")) and shape:
        _add_signal(enriched, sources, "script_readable_sensitive_response_surface", "script_readable_response_semantics")
    if "target=_blank" in text or 'target="_blank"' in text or "window.open" in text:
        _add_signal(enriched, sources, "new_tab_external_link_surface", "new_tab_semantics")
    if any(token in text for token in ("angular", "vue", "mustache", "handlebars", "client template", "template expression")):
        _add_signal(enriched, sources, "client_template_expression_surface", "client_template_semantics")
    if any(str(unit.get("unit_type") or "") == "storage_key" for unit in related_units):
        _add_signal(enriched, sources, "browser_storage_surface", "semantic_js_storage_key")
    if headers or ("html" in content_type and status in {200, 201, 202, 203, 204}):
        _add_signal(enriched, sources, "browser_security_header_surface", "stored_http_header_surface")
    if endpoint.startswith("http://") or any(
        key in enriched for key in ("tls_issuer", "tls_expiry", "tls_sans", "tls_serial", "certificate")
    ):
        _add_signal(enriched, sources, "transport_security_surface", "stored_transport_metadata")
    rrtype = str(enriched.get("rrtype") or "").upper()
    if rrtype == "CNAME":
        _add_signal(enriched, sources, "dangling_dns_dependency_surface", "stored_cname_observation")
    if any(marker in text for marker in _CLOUD_MARKERS):
        _add_signal(enriched, sources, "cloud_storage_surface", "cloud_storage_semantics")
    if endpoint.lower().endswith(_BACKUP_SUFFIXES) or any(token in endpoint.lower() for token in ("/backup/", "/backups/", ".bak?", ".old?")):
        _add_signal(enriched, sources, "backup_or_unreferenced_file_surface", "backup_path_semantics")
    if any(token in endpoint.lower() for token in ("/admin", "/manage", "/management", "/console", "/dashboard", "/internal")):
        _add_signal(enriched, sources, "administrative_interface_surface", "administrative_route")
    if any(token in text for token in ("proxy", "rewrite", "normalize", "semicolon", "path suffix")):
        _add_signal(enriched, sources, "path_normalization_boundary_surface", "routing_semantics")
    if any(token in text for token in ("jwt", "bearer", "authorization", "token", "jws")):
        _add_signal(enriched, sources, "jwt_authentication_surface", "token_auth_semantics")
    if any(token in text for token in ("oauth", "openid", "oidc", "authorize", "callback", "redirect_uri", "pkce", "code_challenge")):
        _add_signal(enriched, sources, "oauth_oidc_flow_surface", "oauth_semantics")
    if any(token in text for token in ("audit", "security event", "monitor", "logging", "/logs", "/log")):
        _add_signal(enriched, sources, "security_relevant_event_surface", "security_event_semantics")
    if status >= 500 or any(token in text for token in ("exception", "timeout", "fallback", "fail-open")):
        _add_signal(enriched, sources, "security_control_error_path_surface", "error_path_semantics")
    if any(token in text for token in ("md5", "sha1", "des", "rc4", "ecb", "cipher", "crypto", "hash")):
        _add_signal(enriched, sources, "cryptographic_operation_surface", "cryptographic_semantics")
    if any(token in text for token in ("update", "artifact", "package", "plugin", "firmware", "manifest", "signature")):
        _add_signal(enriched, sources, "trusted_update_or_data_pipeline_surface", "update_pipeline_semantics")
    versioned_technologies = [
        str(row.get("technology") or "")
        for row in technologies
        if re.search(r"\d+(?:\.\d+)+", str(row.get("technology") or ""))
    ]
    if versioned_technologies:
        _add_signal(enriched, sources, "third_party_component_surface", "versioned_technology_observation")
    if any(str(row.get("protocol") or "") == "cache" for row in protocols) or any(
        key in headers for key in ("cache-control", "age", "via", "x-cache", "cf-cache-status")
    ):
        _add_signal(enriched, sources, "shared_cache_key_surface", "cache_response_context")

    # Preserve useful advisory records for later explainability. They are not
    # interpreted as evidence by admission unless a family analyzer explicitly
    # maps an allowed context signal above.
    enriched["_family_signal_bridge"] = {
        "version": FAMILY_SIGNAL_BRIDGE_VERSION,
        "rule_version": FAMILY_SIGNAL_BRIDGE_RULE_VERSION,
        "context_only": True,
        "network_requests": False,
        "decisive_signals_synthesized": False,
        "sources": sources,
        "related_semantic_unit_count": len(related_units),
        "protocol_finding_count": len(protocols),
        "technology_observation_count": len(technologies),
        "external_api_call_count": len(external_calls),
    }
    return enriched


__all__ = [
    "FAMILY_SIGNAL_BRIDGE_VERSION",
    "FAMILY_SIGNAL_BRIDGE_RULE_VERSION",
    "augment_family_details",
    "clear_family_signal_bridge_cache",
]
