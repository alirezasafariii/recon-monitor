from __future__ import annotations

"""Derive passive family evidence from already-stored Recon observations.

This module is deliberately narrower than the family signal bridge. The bridge
creates discovery/context hints; this extractor may derive a small allow-listed
set of passive target-evidence signals only when the stored Recon record already
contains the concrete observation needed for that signal.

Safety properties:
- no network, subprocess, filesystem, or collector execution;
- no payload generation and no target mutation;
- no taxonomy/write-up material is treated as target evidence;
- route names alone never become vulnerability evidence;
- direct/confirmation signals are never synthesized.
"""

import urllib.parse
from typing import Any, Mapping

PASSIVE_EVIDENCE_EXTRACTOR_VERSION = "1.1.0"
PASSIVE_EVIDENCE_EXTRACTOR_RULE_VERSION = "2026.09.18.2"

_BACKUP_SUFFIXES = (
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".save",
    ".swp",
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".sql",
    ".dump",
    "~",
)
_BACKUP_PATH_MARKERS = ("/backup/", "/backups/")
_ADMIN_PATH_MARKERS = ("/admin", "/manage", "/management", "/console")
_ADMIN_TITLE_MARKERS = ("admin", "administration", "management", "console", "control panel")
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")
_SENSITIVE_UI_PATH_MARKERS = (
    "/account",
    "/admin",
    "/billing",
    "/checkout",
    "/customer",
    "/invoice",
    "/order",
    "/payment",
    "/profile",
    "/settings",
    "/staff",
    "/tenant",
    "/user",
    "/wallet",
)
_SECURE_REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
)
_HSTS_MIN_MAX_AGE_SECONDS = 15_552_000

_ALLOWED_DERIVED_SIGNALS = frozenset(
    {
        "backup_file_publicly_reachable_observed",
        "backup_files_not_publicly_reachable",
        "admin_interface_publicly_reachable_observed",
        "admin_authentication_enforced",
        "required_security_header_missing_or_invalid_observed",
        "required_security_headers_valid_observed",
        "frame_ancestors_protection_missing_observed",
        "x_frame_options_enforced",
        "csp_frame_ancestors_enforced",
        "hsts_policy_weak_or_missing_observed",
        "hsts_policy_valid_observed",
    }
)


def _truth(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "y", "on", "reachable"}:
        return True
    if text in {"0", "false", "no", "n", "off", "unreachable"}:
        return False
    return None


def _int_value(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _first_nested(details: Mapping[str, Any], key: str) -> Any:
    if details.get(key) not in (None, ""):
        return details.get(key)
    for parent in ("new", "current", "after", "response"):
        nested = details.get(parent)
        if isinstance(nested, Mapping) and nested.get(key) not in (None, ""):
            return nested.get(key)
    return None


def _status_code(details: Mapping[str, Any]) -> int:
    return _int_value(_first_nested(details, "status_code"))


def _content_type(details: Mapping[str, Any]) -> str:
    return str(_first_nested(details, "content_type") or "").strip().lower()


def _content_length(details: Mapping[str, Any]) -> int:
    return max(0, _int_value(_first_nested(details, "content_length")))


def _error(details: Mapping[str, Any]) -> str:
    return str(_first_nested(details, "error") or "").strip()


def _response_headers(details: Mapping[str, Any]) -> dict[str, str]:
    candidates: list[Any] = []
    for key in (
        "response_headers",
        "headers",
        "headers_json",
        "response_headers_json",
    ):
        value = details.get(key)
        if value:
            candidates.append(value)
    for parent in ("new", "current", "after", "response"):
        nested = details.get(parent)
        if not isinstance(nested, Mapping):
            continue
        for key in (
            "response_headers",
            "headers",
            "headers_json",
            "response_headers_json",
        ):
            value = nested.get(key)
            if value:
                candidates.append(value)

    result: dict[str, str] = {}
    for raw in candidates:
        decoded = raw
        if isinstance(raw, str):
            try:
                import json

                decoded = json.loads(raw)
            except (TypeError, ValueError):
                continue
        if not isinstance(decoded, Mapping):
            continue
        for key, value in decoded.items():
            name = str(key or "").strip().lower()
            if not name:
                continue
            if isinstance(value, (list, tuple, set)):
                text = ", ".join(str(item) for item in value if item is not None)
            elif isinstance(value, Mapping):
                continue
            else:
                text = str(value or "")
            text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
            if text:
                result[name] = text[:2048]
    return result


def _header_snapshot_observed(details: Mapping[str, Any]) -> bool:
    value = _first_nested(details, "response_headers_observed")
    return _truth(value) is True


def _successful_html_response(status: int, content_type: str) -> bool:
    return 200 <= status < 300 and any(marker in content_type for marker in _HTML_CONTENT_TYPES)


def _valid_x_content_type_options(headers: Mapping[str, str]) -> bool:
    return str(headers.get("x-content-type-options") or "").strip().lower() == "nosniff"


def _valid_referrer_policy(headers: Mapping[str, str]) -> bool:
    value = str(headers.get("referrer-policy") or "").strip().lower()
    if not value:
        return False
    # Browsers use the last recognized policy in a comma-separated list.
    tokens = [item.strip() for item in value.split(",") if item.strip()]
    return bool(tokens and tokens[-1] in _SECURE_REFERRER_POLICIES)


def _valid_x_frame_options(headers: Mapping[str, str]) -> bool:
    value = str(headers.get("x-frame-options") or "").strip().lower()
    return value in {"deny", "sameorigin"}


def _frame_ancestors_value(headers: Mapping[str, str]) -> str:
    csp = str(headers.get("content-security-policy") or "")
    for directive in csp.split(";"):
        name, _, value = directive.strip().partition(" ")
        if name.strip().lower() == "frame-ancestors":
            return value.strip().lower()
    return ""


def _valid_frame_ancestors(headers: Mapping[str, str]) -> bool:
    value = _frame_ancestors_value(headers)
    if not value:
        return False
    tokens = [token for token in value.split() if token]
    if not tokens:
        return False
    if "'none'" in tokens or "'self'" in tokens:
        return True
    # Explicit origins constrain framing. Broad wildcards and scheme-only
    # sources are not treated as protection by this conservative extractor.
    return any(
        "://" in token and "*" not in token
        for token in tokens
    )


def _hsts_max_age(headers: Mapping[str, str]) -> int | None:
    value = str(headers.get("strict-transport-security") or "").strip()
    if not value:
        return None
    for directive in value.split(";"):
        name, sep, raw = directive.strip().partition("=")
        if sep and name.strip().lower() == "max-age":
            try:
                return max(0, int(raw.strip().strip('"')))
            except (TypeError, ValueError):
                return -1
    return -1


def _path(endpoint: str) -> str:
    raw = str(endpoint or "").strip()
    try:
        value = urllib.parse.urlsplit(
            raw if "://" in raw else f"https://placeholder.invalid/{raw.lstrip('/')}"
        ).path
    except ValueError:
        value = raw
    return value.lower()


def _classification(details: Mapping[str, Any]) -> str:
    value = details.get("endpoint_classification")
    if isinstance(value, Mapping):
        return str(value.get("primary_category") or "").strip().lower()
    return str(details.get("category") or "").strip().lower()


def _set_signal(
    enriched: dict[str, Any],
    sources: dict[str, list[str]],
    signal: str,
    *source_roots: str,
) -> None:
    if signal not in _ALLOWED_DERIVED_SIGNALS:
        raise ValueError(f"Passive evidence signal is not allow-listed: {signal}")
    # Explicit imported/reviewed evidence always wins over this derived layer.
    if signal not in enriched:
        enriched[signal] = True
    bucket = sources.setdefault(signal, [])
    for source in source_roots:
        value = str(source or "").strip()
        if value and value not in bucket:
            bucket.append(value)


def _stored_response_observed(details: Mapping[str, Any], status: int) -> bool:
    if _error(details):
        return False
    reachable = _truth(_first_nested(details, "reachable"))
    if reachable is False:
        return False
    # A persisted HTTP status is itself a stored target observation. Explicit
    # reachability strengthens it but is not required for fingerprint-only rows.
    return bool(status and 100 <= status <= 599 and (reachable is not False))


def _backup_surface(path: str) -> bool:
    return path.endswith(_BACKUP_SUFFIXES) or any(marker in path for marker in _BACKUP_PATH_MARKERS)


def _derive_backup_evidence(
    enriched: dict[str, Any],
    sources: dict[str, list[str]],
    *,
    path: str,
    status: int,
    content_type: str,
    content_length: int,
) -> None:
    if not _backup_surface(path):
        return

    if status in {401, 403, 404, 410}:
        _set_signal(
            enriched,
            sources,
            "backup_files_not_publicly_reachable",
            "stored_http_status",
            "backup_path_semantics",
        )
        return

    # A route name is never enough. Require a successful stored response plus
    # file-like response metadata; HTML catch-all/login/error pages are rejected.
    if status not in {200, 206}:
        return
    if any(marker in content_type for marker in _HTML_CONTENT_TYPES):
        return
    if not content_type and content_length <= 0:
        return

    _set_signal(
        enriched,
        sources,
        "backup_file_publicly_reachable_observed",
        "stored_http_status",
        "stored_response_metadata",
        "backup_path_semantics",
    )


def _admin_surface(path: str, title: str, classification: str) -> bool:
    strong_path = any(marker in path for marker in _ADMIN_PATH_MARKERS)
    title_match = any(marker in title for marker in _ADMIN_TITLE_MARKERS)
    classified = classification in {"administration", "admin", "management"}
    # Generic /dashboard is intentionally not sufficient on its own.
    return strong_path or title_match or classified


def _derive_admin_evidence(
    enriched: dict[str, Any],
    sources: dict[str, list[str]],
    *,
    path: str,
    title: str,
    classification: str,
    status: int,
    content_type: str,
) -> None:
    if not _admin_surface(path, title, classification):
        return

    if status in {401, 403}:
        _set_signal(
            enriched,
            sources,
            "admin_authentication_enforced",
            "stored_http_status",
            "administrative_surface",
        )
        return

    # This first passive extractor intentionally covers browser-visible admin
    # interfaces only. API/admin authorization remains in the authorization
    # families and requires stronger evidence.
    if status < 200 or status >= 300:
        return
    if not any(marker in content_type for marker in _HTML_CONTENT_TYPES):
        return

    _set_signal(
        enriched,
        sources,
        "admin_interface_publicly_reachable_observed",
        "stored_http_status",
        "stored_content_type",
        "administrative_surface",
    )


def _derive_security_header_evidence(
    enriched: dict[str, Any],
    sources: dict[str, list[str]],
    *,
    status: int,
    content_type: str,
    headers: Mapping[str, str],
    headers_observed: bool,
) -> None:
    if not headers_observed or not _successful_html_response(status, content_type):
        return

    nosniff = _valid_x_content_type_options(headers)
    referrer = _valid_referrer_policy(headers)
    if nosniff and referrer:
        _set_signal(
            enriched,
            sources,
            "required_security_headers_valid_observed",
            "stored_response_headers",
            "stored_html_response",
        )
    elif not nosniff and not referrer:
        _set_signal(
            enriched,
            sources,
            "required_security_header_missing_or_invalid_observed",
            "stored_response_headers",
            "stored_html_response",
        )


def _derive_clickjacking_evidence(
    enriched: dict[str, Any],
    sources: dict[str, list[str]],
    *,
    path: str,
    title: str,
    classification: str,
    status: int,
    content_type: str,
    headers: Mapping[str, str],
    headers_observed: bool,
) -> None:
    if not headers_observed or not _successful_html_response(status, content_type):
        return

    sensitive_surface = _truth(enriched.get("sensitive_ui_frame_surface")) is True
    if not sensitive_surface:
        sensitive_surface = (
            any(marker in path for marker in _SENSITIVE_UI_PATH_MARKERS)
            or any(marker in title for marker in _ADMIN_TITLE_MARKERS)
            or classification in {
                "administration",
                "admin",
                "management",
                "account",
                "billing",
                "payment",
                "profile",
                "settings",
            }
        )
    if not sensitive_surface:
        return

    xfo = _valid_x_frame_options(headers)
    csp = _valid_frame_ancestors(headers)
    if xfo:
        _set_signal(
            enriched,
            sources,
            "x_frame_options_enforced",
            "stored_response_headers",
            "sensitive_ui_surface",
        )
    if csp:
        _set_signal(
            enriched,
            sources,
            "csp_frame_ancestors_enforced",
            "stored_response_headers",
            "sensitive_ui_surface",
        )
    if not xfo and not csp:
        _set_signal(
            enriched,
            sources,
            "frame_ancestors_protection_missing_observed",
            "stored_response_headers",
            "sensitive_ui_surface",
        )


def _derive_hsts_evidence(
    enriched: dict[str, Any],
    sources: dict[str, list[str]],
    *,
    endpoint: str,
    status: int,
    headers: Mapping[str, str],
    headers_observed: bool,
) -> None:
    if not headers_observed or status < 200 or status >= 400:
        return
    try:
        scheme = urllib.parse.urlsplit(str(endpoint or "")).scheme.lower()
    except ValueError:
        scheme = ""
    if scheme != "https":
        return

    max_age = _hsts_max_age(headers)
    if max_age is not None and max_age >= _HSTS_MIN_MAX_AGE_SECONDS:
        _set_signal(
            enriched,
            sources,
            "hsts_policy_valid_observed",
            "stored_response_headers",
            "https_transport_surface",
        )
    else:
        _set_signal(
            enriched,
            sources,
            "hsts_policy_weak_or_missing_observed",
            "stored_response_headers",
            "https_transport_surface",
        )


def extract_passive_family_evidence(
    *,
    endpoint: str,
    details: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return details enriched only with evidence derivable from stored Recon.

    The function is deterministic and side-effect free. It does not query the
    target or alter collector behavior.
    """

    enriched = dict(details or {})
    status = _status_code(enriched)
    path = _path(endpoint or str(enriched.get("resolved_url") or enriched.get("url") or ""))
    content_type = _content_type(enriched)
    content_length = _content_length(enriched)
    title = str(enriched.get("title") or "").strip().lower()
    classification = _classification(enriched)
    headers = _response_headers(enriched)
    headers_observed = _header_snapshot_observed(enriched)

    sources: dict[str, list[str]] = {}
    if _stored_response_observed(enriched, status):
        _derive_backup_evidence(
            enriched,
            sources,
            path=path,
            status=status,
            content_type=content_type,
            content_length=content_length,
        )
        _derive_admin_evidence(
            enriched,
            sources,
            path=path,
            title=title,
            classification=classification,
            status=status,
            content_type=content_type,
        )
        _derive_security_header_evidence(
            enriched,
            sources,
            status=status,
            content_type=content_type,
            headers=headers,
            headers_observed=headers_observed,
        )
        _derive_clickjacking_evidence(
            enriched,
            sources,
            path=path,
            title=title,
            classification=classification,
            status=status,
            content_type=content_type,
            headers=headers,
            headers_observed=headers_observed,
        )
        _derive_hsts_evidence(
            enriched,
            sources,
            endpoint=endpoint,
            status=status,
            headers=headers,
            headers_observed=headers_observed,
        )

    enriched["_passive_evidence_extractor"] = {
        "version": PASSIVE_EVIDENCE_EXTRACTOR_VERSION,
        "rule_version": PASSIVE_EVIDENCE_EXTRACTOR_RULE_VERSION,
        "derived_from_stored_recon_only": True,
        "network_requests": 0,
        "active_validation_performed": False,
        "collector_behavior_changed": False,
        "payload_generated": False,
        "confirmation_signals_synthesized": False,
        "response_header_snapshot_observed": headers_observed,
        "persisted_response_header_names": sorted(headers),
        "derived_signals": sorted(sources),
        "sources": sources,
    }
    return enriched


__all__ = [
    "PASSIVE_EVIDENCE_EXTRACTOR_VERSION",
    "PASSIVE_EVIDENCE_EXTRACTOR_RULE_VERSION",
    "extract_passive_family_evidence",
]
