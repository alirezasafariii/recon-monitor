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

PASSIVE_EVIDENCE_EXTRACTOR_VERSION = "1.0.0"
PASSIVE_EVIDENCE_EXTRACTOR_RULE_VERSION = "2026.09.18.1"

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

_ALLOWED_DERIVED_SIGNALS = frozenset(
    {
        "backup_file_publicly_reachable_observed",
        "backup_files_not_publicly_reachable",
        "admin_interface_publicly_reachable_observed",
        "admin_authentication_enforced",
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

    enriched["_passive_evidence_extractor"] = {
        "version": PASSIVE_EVIDENCE_EXTRACTOR_VERSION,
        "rule_version": PASSIVE_EVIDENCE_EXTRACTOR_RULE_VERSION,
        "derived_from_stored_recon_only": True,
        "network_requests": 0,
        "active_validation_performed": False,
        "collector_behavior_changed": False,
        "payload_generated": False,
        "confirmation_signals_synthesized": False,
        "derived_signals": sorted(sources),
        "sources": sources,
    }
    return enriched


__all__ = [
    "PASSIVE_EVIDENCE_EXTRACTOR_VERSION",
    "PASSIVE_EVIDENCE_EXTRACTOR_RULE_VERSION",
    "extract_passive_family_evidence",
]
