from __future__ import annotations

"""Deterministic offline matching from stored Recon technology versions to a
small source-attributed runtime advisory catalog.

This module does not fetch advisories, contact targets, infer missing versions,
or treat an absent catalog match as proof that a component is safe.
"""

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

DEPENDENCY_ADVISORY_MATCHER_VERSION = "1.0.0"
DEPENDENCY_ADVISORY_MATCHER_RULE_VERSION = "2026.09.18.1"

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


def version_matches_range(version: str, expression: str) -> bool:
    current = _version_tuple(version)
    if current is None:
        return False
    clauses = [item.strip() for item in str(expression or "").split(",") if item.strip()]
    if not clauses:
        return False
    for clause in clauses:
        match = _COMPARATOR_RE.fullmatch(clause)
        if not match:
            return False
        boundary = _version_tuple(match.group(2))
        if boundary is None:
            return False
        if not _compare(current, match.group(1) or "=", boundary):
            return False
    return True


def _load_catalog(path: str | Path | None = None) -> dict[str, Any]:
    selected = Path(path) if path else _DEFAULT_CATALOG
    raw = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("Dependency advisory catalog must be a JSON object")
    return dict(raw)


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
    )


def match_versioned_technology(
    technology: str,
    *,
    catalog_path: str | Path | None = None,
) -> dict[str, Any]:
    parsed = parse_versioned_technology(technology)
    catalog = _load_catalog(catalog_path)
    result = {
        "matcher_version": DEPENDENCY_ADVISORY_MATCHER_VERSION,
        "rule_version": DEPENDENCY_ADVISORY_MATCHER_RULE_VERSION,
        "catalog_version": str(catalog.get("version") or ""),
        "catalog_generated_at": str(catalog.get("generated_at") or ""),
        "catalog_completeness": str(catalog.get("completeness") or ""),
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
                "version": version,
                "matched_range": matched_range,
                "patched_versions": [
                    str(item)
                    for item in raw.get("patched_versions", []) or []
                    if str(item)
                ],
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
    seen_matches: set[tuple[str, str, str]] = set()
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
                str(match.get("product") or ""),
                str(match.get("version") or ""),
            )
            if identity in seen_matches:
                continue
            seen_matches.add(identity)
            matches.append(dict(match))

    catalog = _load_catalog(catalog_path)
    return {
        "version": DEPENDENCY_ADVISORY_MATCHER_VERSION,
        "rule_version": DEPENDENCY_ADVISORY_MATCHER_RULE_VERSION,
        "catalog_version": str(catalog.get("version") or ""),
        "catalog_generated_at": str(catalog.get("generated_at") or ""),
        "catalog_completeness": str(catalog.get("completeness") or ""),
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
    "parse_versioned_technology",
    "version_matches_range",
    "match_versioned_technology",
    "match_technologies",
]
