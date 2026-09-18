from __future__ import annotations

"""Deterministic offline matching from stored Recon technology versions.

The runtime matcher never fetches advisories and never contacts the target. A
separate catalog-sync command creates the local source-attributed snapshot.
Catalog misses remain unknown even when the local GitHub-reviewed snapshot is
complete because other advisory sources and unreachable vulnerable features may
exist outside this matcher.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

DEPENDENCY_ADVISORY_MATCHER_VERSION = "2.0.0"
DEPENDENCY_ADVISORY_MATCHER_RULE_VERSION = "2026.09.18.2"

_DEFAULT_CATALOG = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "dependency_advisory_catalog.json"
)
_ALLOWED_SOURCE_TYPES = {
    "github_reviewed_advisory",
    "maintainer_security_advisory",
}
_VERSIONED_TECH_RE = re.compile(
    r"^(?P<name>.+?)(?:\s*[:/@]\s*|\s+)"
    r"v?(?P<version>\d+(?:\.\d+){1,3})$",
    re.I,
)
_COMPARATOR_RE = re.compile(r"^(<=|>=|<|>|=)?\s*(\d+(?:\.\d+){1,3})$")


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _version_tuple(value: str) -> tuple[int, int, int, int] | None:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d+(?:\.\d+){1,3}", text):
        return None
    parts = [int(part) for part in text.split(".")]
    if any(part < 0 for part in parts):
        return None
    return tuple((parts + [0, 0, 0, 0])[:4])


def parse_versioned_technology(value: str) -> dict[str, str] | None:
    text = str(value or "").strip()
    match = _VERSIONED_TECH_RE.fullmatch(text)
    if not match:
        return None
    name = _normalize_name(match.group("name"))
    version = str(match.group("version"))
    if not name or _version_tuple(version) is None:
        return None
    return {
        "raw": text,
        "name": name,
        "version": version,
    }


def _compare(left: tuple[int, ...], operator: str, right: tuple[int, ...]) -> bool:
    if operator == "<":
        return left < right
    if operator == "<=":
        return left <= right
    if operator == ">":
        return left > right
    if operator == ">=":
        return left >= right
    return left == right


def range_expression_supported(expression: str) -> bool:
    clauses = [item.strip() for item in str(expression or "").split(",") if item.strip()]
    if not clauses:
        return False
    return all(_COMPARATOR_RE.fullmatch(clause) is not None for clause in clauses)


def version_matches_range(version: str, expression: str) -> bool:
    current = _version_tuple(version)
    if current is None or not range_expression_supported(expression):
        return False
    clauses = [item.strip() for item in str(expression or "").split(",") if item.strip()]
    for clause in clauses:
        match = _COMPARATOR_RE.fullmatch(clause)
        if match is None:
            return False
        boundary = _version_tuple(match.group(2))
        if boundary is None:
            return False
        if not _compare(current, match.group(1) or "=", boundary):
            return False
    return True


def advisories_sha256(advisories: Iterable[Mapping[str, Any]]) -> str:
    canonical = json.dumps(
        [dict(item) for item in advisories],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _advisory_aliases(advisory: Mapping[str, Any]) -> set[str]:
    result = {_normalize_name(str(advisory.get("product") or ""))}
    for alias in advisory.get("aliases", []) or []:
        normalized = _normalize_name(str(alias))
        if normalized:
            result.add(normalized)
    result.discard("")
    return result


def _valid_advisory(advisory: Mapping[str, Any]) -> bool:
    return (
        bool(str(advisory.get("id") or "").strip())
        and bool(_advisory_aliases(advisory))
        and str(advisory.get("source_type") or "") in _ALLOWED_SOURCE_TYPES
        and str(advisory.get("source_url") or "").startswith("https://")
        and bool(advisory.get("affected_ranges"))
        and not str(advisory.get("withdrawn_at") or "").strip()
    )


def validate_catalog_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    raw_advisories = payload.get("advisories")
    advisories = (
        [dict(item) for item in raw_advisories if isinstance(item, Mapping)]
        if isinstance(raw_advisories, list)
        else []
    )
    invalid = [
        str(item.get("id") or "")
        for item in advisories
        if not _valid_advisory(item)
    ]
    identities: set[tuple[str, str, str]] = set()
    duplicates: list[str] = []
    supported_range_count = 0
    unsupported_range_count = 0
    for item in advisories:
        identity = (
            str(item.get("id") or ""),
            str(item.get("ecosystem") or "").lower(),
            _normalize_name(str(item.get("product") or "")),
        )
        if identity in identities:
            duplicates.append("|".join(identity))
        identities.add(identity)
        for expression in item.get("affected_ranges", []) or []:
            if range_expression_supported(str(expression)):
                supported_range_count += 1
            else:
                unsupported_range_count += 1

    integrity = payload.get("integrity")
    declared_hash = (
        str(integrity.get("advisories_sha256") or "")
        if isinstance(integrity, Mapping)
        else ""
    )
    actual_hash = advisories_sha256(advisories)
    hash_valid = not declared_hash or declared_hash == actual_hash

    source = payload.get("source_snapshot")
    source_snapshot = dict(source) if isinstance(source, Mapping) else {}
    return {
        "valid": not invalid and not duplicates and hash_valid,
        "advisory_count": len(advisories),
        "invalid_advisories": invalid,
        "duplicate_identities": duplicates,
        "supported_range_count": supported_range_count,
        "unsupported_range_count": unsupported_range_count,
        "advisories_sha256": actual_hash,
        "declared_advisories_sha256": declared_hash,
        "integrity_valid": hash_valid,
        "source_sync_complete": bool(source_snapshot.get("sync_complete")),
        "source_scope": str(source_snapshot.get("scope") or ""),
        "source_page_count": int(source_snapshot.get("page_count") or 0),
        "source_advisory_count": int(source_snapshot.get("source_advisory_count") or 0),
    }


def _load_catalog(path: str | Path | None = None) -> dict[str, Any]:
    selected = Path(path) if path else _DEFAULT_CATALOG
    raw = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("Dependency advisory catalog must be a JSON object")
    catalog = dict(raw)
    validation = validate_catalog_payload(catalog)
    if not validation["valid"]:
        raise ValueError(
            "Dependency advisory catalog failed validation: "
            + json.dumps(validation, sort_keys=True)
        )
    return catalog


def catalog_status(path: str | Path | None = None) -> dict[str, Any]:
    selected = Path(path) if path else _DEFAULT_CATALOG
    catalog = _load_catalog(selected)
    validation = validate_catalog_payload(catalog)
    source = catalog.get("source_snapshot")
    source_snapshot = dict(source) if isinstance(source, Mapping) else {}
    ecosystems = sorted(
        {
            str(item.get("ecosystem") or "").lower()
            for item in catalog.get("advisories", []) or []
            if isinstance(item, Mapping) and str(item.get("ecosystem") or "")
        }
    )
    products = {
        (
            str(item.get("ecosystem") or "").lower(),
            _normalize_name(str(item.get("product") or "")),
        )
        for item in catalog.get("advisories", []) or []
        if isinstance(item, Mapping)
    }
    return {
        "matcher_version": DEPENDENCY_ADVISORY_MATCHER_VERSION,
        "rule_version": DEPENDENCY_ADVISORY_MATCHER_RULE_VERSION,
        "catalog_path": str(selected),
        "catalog_version": str(catalog.get("version") or ""),
        "generated_at": str(catalog.get("generated_at") or ""),
        "completeness": str(catalog.get("completeness") or ""),
        "runtime_role": str(catalog.get("runtime_role") or ""),
        "advisory_count": validation["advisory_count"],
        "product_count": len(products),
        "ecosystems": ecosystems,
        "supported_range_count": validation["supported_range_count"],
        "unsupported_range_count": validation["unsupported_range_count"],
        "integrity_valid": validation["integrity_valid"],
        "source_sync_complete": bool(source_snapshot.get("sync_complete")),
        "source_scope": str(source_snapshot.get("scope") or ""),
        "source_page_count": int(source_snapshot.get("page_count") or 0),
        "source_advisory_count": int(source_snapshot.get("source_advisory_count") or 0),
        "source_last_updated_at": str(source_snapshot.get("last_updated_at") or ""),
        "catalog_is_exhaustive": False,
        "absence_of_match_means_safe": False,
        "runtime_network_requests": 0,
    }


def match_versioned_technology(
    technology: str,
    *,
    catalog_path: str | Path | None = None,
) -> dict[str, Any]:
    parsed = parse_versioned_technology(technology)
    catalog = _load_catalog(catalog_path)
    source = catalog.get("source_snapshot")
    source_snapshot = dict(source) if isinstance(source, Mapping) else {}
    result = {
        "matcher_version": DEPENDENCY_ADVISORY_MATCHER_VERSION,
        "rule_version": DEPENDENCY_ADVISORY_MATCHER_RULE_VERSION,
        "catalog_version": str(catalog.get("version") or ""),
        "catalog_generated_at": str(catalog.get("generated_at") or ""),
        "catalog_completeness": str(catalog.get("completeness") or ""),
        "catalog_source_sync_complete": bool(source_snapshot.get("sync_complete")),
        "technology": parsed or {},
        "version_exact": bool(parsed),
        "matches": [],
        "catalog_is_exhaustive": False,
        "absence_of_match_means_safe": False,
        "network_requests": 0,
    }
    if not parsed:
        return result

    name = parsed["name"]
    version = parsed["version"]
    matches: list[dict[str, Any]] = []
    for raw in catalog.get("advisories", []) or []:
        if not isinstance(raw, Mapping) or not _valid_advisory(raw):
            continue
        if name not in _advisory_aliases(raw):
            continue
        matched_range = next(
            (
                str(expression)
                for expression in raw.get("affected_ranges", []) or []
                if version_matches_range(version, str(expression))
            ),
            "",
        )
        if not matched_range:
            continue
        matches.append(
            {
                "advisory_id": str(raw.get("id") or ""),
                "cve": str(raw.get("cve") or ""),
                "product": str(raw.get("product") or ""),
                "ecosystem": str(raw.get("ecosystem") or ""),
                "version": version,
                "matched_range": matched_range,
                "patched_versions": [
                    str(item)
                    for item in raw.get("patched_versions", []) or []
                    if str(item)
                ],
                "severity": str(raw.get("severity") or ""),
                "published_at": str(raw.get("published_at") or ""),
                "updated_at": str(raw.get("updated_at") or ""),
                "source_type": str(raw.get("source_type") or ""),
                "review_status": str(raw.get("review_status") or ""),
                "source_url": str(raw.get("source_url") or ""),
            }
        )
    result["matches"] = matches
    return result


def match_technologies(
    technologies: Iterable[Any],
    *,
    catalog_path: str | Path | None = None,
) -> dict[str, Any]:
    exact: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []
    seen_matches: set[tuple[str, str, str, str]] = set()
    for raw in technologies:
        technology = (
            str(raw.get("technology") or "")
            if isinstance(raw, Mapping)
            else str(raw or "")
        ).strip()
        if not technology:
            continue
        outcome = match_versioned_technology(
            technology,
            catalog_path=catalog_path,
        )
        parsed = outcome.get("technology")
        if isinstance(parsed, Mapping) and parsed:
            exact.append(dict(parsed))
        for match in outcome.get("matches", []) or []:
            if not isinstance(match, Mapping):
                continue
            identity = (
                str(match.get("advisory_id") or ""),
                str(match.get("ecosystem") or ""),
                str(match.get("product") or ""),
                str(match.get("version") or ""),
            )
            if identity in seen_matches:
                continue
            seen_matches.add(identity)
            matches.append(dict(match))

    catalog = _load_catalog(catalog_path)
    source = catalog.get("source_snapshot")
    source_snapshot = dict(source) if isinstance(source, Mapping) else {}
    return {
        "version": DEPENDENCY_ADVISORY_MATCHER_VERSION,
        "rule_version": DEPENDENCY_ADVISORY_MATCHER_RULE_VERSION,
        "catalog_version": str(catalog.get("version") or ""),
        "catalog_generated_at": str(catalog.get("generated_at") or ""),
        "catalog_completeness": str(catalog.get("completeness") or ""),
        "catalog_source_sync_complete": bool(source_snapshot.get("sync_complete")),
        "versioned_components": exact,
        "matches": matches,
        "match_count": len(matches),
        "catalog_is_exhaustive": False,
        "absence_of_match_means_safe": False,
        "network_requests": 0,
    }


__all__ = [
    "DEPENDENCY_ADVISORY_MATCHER_VERSION",
    "DEPENDENCY_ADVISORY_MATCHER_RULE_VERSION",
    "advisories_sha256",
    "catalog_status",
    "match_technologies",
    "match_versioned_technology",
    "parse_versioned_technology",
    "range_expression_supported",
    "validate_catalog_payload",
    "version_matches_range",
]
