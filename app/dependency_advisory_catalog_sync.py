from __future__ import annotations

"""Offline dependency-advisory catalog synchronization.

This command is intentionally separate from Recon/Analysis execution. It may
contact only GitHub's public Global Security Advisories API and writes a local
snapshot that runtime Analysis later consumes without network access.

The synchronized snapshot includes all non-withdrawn GitHub-reviewed advisory
package entries returned by a complete cursor traversal. Range syntax that the
runtime matcher cannot yet evaluate is preserved and counted, never discarded;
such entries remain cataloged but cannot produce a version match until their
range syntax is supported.
"""

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from dependency_advisory_matcher import (
    advisories_sha256,
    normalize_component_name,
    range_expression_supported,
    validate_catalog_payload,
)

DEPENDENCY_ADVISORY_CATALOG_SYNC_VERSION = "1.0.1"
DEPENDENCY_ADVISORY_CATALOG_SYNC_RULE_VERSION = "2026.09.18.2"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_REVIEWED_ADVISORY_API = "https://api.github.com/advisories"
CATALOG_SCHEMA_VERSION = "2.0.0"

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT_DIR / "data" / "dependency_advisory_catalog.json"
DEFAULT_ALIASES = ROOT_DIR / "data" / "dependency_advisory_aliases.json"
DEFAULT_MANIFEST = ROOT_DIR / "MANIFEST.sha256"

_GHSA_RE = re.compile(r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$", re.I)
_NEXT_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


def _text(value: Any) -> str:
    return str(value or "").strip()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _next_link(value: str) -> str:
    match = _NEXT_LINK_RE.search(str(value or ""))
    return str(match.group(1)) if match else ""


def _api_get_page(url: str, *, token: str = "") -> tuple[list[dict[str, Any]], str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-dependency-advisory-catalog-sync",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=45) as response:
        payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, list):
            raise ValueError("GitHub advisory API returned a non-list payload")
        rows = [dict(item) for item in payload if isinstance(item, Mapping)]
        return rows, _next_link(response.headers.get("Link", ""))


def load_alias_registry(path: str | Path | None = None) -> dict[str, list[str]]:
    selected = Path(path) if path else DEFAULT_ALIASES
    if not selected.exists():
        return {}
    raw = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("Dependency advisory alias registry must be an object")
    aliases = raw.get("aliases")
    if not isinstance(aliases, Mapping):
        return {}
    result: dict[str, list[str]] = {}
    for raw_key, raw_values in aliases.items():
        key = _text(raw_key).lower()
        if not key or not isinstance(raw_values, list):
            continue
        values = sorted({_text(item) for item in raw_values if _text(item)})
        if values:
            result[key] = values
    return result


def _package_aliases(
    ecosystem: str,
    product: str,
    alias_registry: Mapping[str, list[str]],
) -> list[str]:
    key = f"{ecosystem.lower()}:{product.lower()}"
    values = {product}
    values.update(alias_registry.get(key, []))
    return sorted(_text(item) for item in values if _text(item))


def _normalize_advisory_rows(
    row: Mapping[str, Any],
    *,
    alias_registry: Mapping[str, list[str]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    stats = {
        "withdrawn_excluded": 0,
        "malformed_excluded": 0,
        "vulnerability_rows_seen": 0,
    }
    if _text(row.get("withdrawn_at")):
        stats["withdrawn_excluded"] += 1
        return [], stats

    ghsa = _text(row.get("ghsa_id")).upper()
    if not _GHSA_RE.fullmatch(ghsa):
        stats["malformed_excluded"] += 1
        return [], stats

    source_url = _text(row.get("html_url"))
    if not source_url.startswith("https://github.com/advisories/"):
        source_url = f"https://github.com/advisories/{ghsa}"

    vulnerabilities = row.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        stats["malformed_excluded"] += 1
        return [], stats

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for raw_vulnerability in vulnerabilities:
        if not isinstance(raw_vulnerability, Mapping):
            continue
        stats["vulnerability_rows_seen"] += 1
        package = raw_vulnerability.get("package")
        if not isinstance(package, Mapping):
            stats["malformed_excluded"] += 1
            continue
        ecosystem = _text(package.get("ecosystem")).lower()
        product = _text(package.get("name"))
        affected_range = _text(raw_vulnerability.get("vulnerable_version_range"))
        if not ecosystem or not product or not affected_range:
            stats["malformed_excluded"] += 1
            continue

        canonical_product = normalize_component_name(product)
        if not canonical_product:
            stats["malformed_excluded"] += 1
            continue
        identity = (ecosystem, canonical_product)
        entry = grouped.setdefault(
            identity,
            {
                "id": ghsa,
                "cve": _text(row.get("cve_id")).upper(),
                "product": product,
                "ecosystem": ecosystem,
                "aliases": _package_aliases(
                    ecosystem,
                    product,
                    alias_registry,
                ),
                "source_type": "github_reviewed_advisory",
                "review_status": "reviewed",
                "source_url": source_url,
                "severity": _text(row.get("severity")).lower(),
                "published_at": _text(row.get("published_at")),
                "updated_at": _text(row.get("updated_at")),
                "reviewed_at": _text(row.get("reviewed_at")),
                "affected_ranges": [],
                "patched_versions": [],
                "withdrawn_at": "",
            },
        )
        entry["aliases"] = sorted({
            _text(item)
            for item in list(entry.get("aliases") or [])
            + _package_aliases(ecosystem, product, alias_registry)
            if _text(item)
        })
        if affected_range not in entry["affected_ranges"]:
            entry["affected_ranges"].append(affected_range)
        patched = raw_vulnerability.get("first_patched_version")
        patched_version = (
            _text(patched.get("identifier"))
            if isinstance(patched, Mapping)
            else ""
        )
        if patched_version and patched_version not in entry["patched_versions"]:
            entry["patched_versions"].append(patched_version)

    normalized: list[dict[str, Any]] = []
    for entry in grouped.values():
        entry["affected_ranges"] = sorted(entry["affected_ranges"])
        entry["patched_versions"] = sorted(entry["patched_versions"])
        entry["range_match_supported"] = any(
            range_expression_supported(expression)
            for expression in entry["affected_ranges"]
        )
        normalized.append(entry)
    return normalized, stats


def _catalog_identity(entry: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        _text(entry.get("id")).upper(),
        _text(entry.get("ecosystem")).lower(),
        normalize_component_name(_text(entry.get("product"))),
    )


def build_catalog_from_pages(
    *,
    fetch_page: Callable[[str], tuple[list[dict[str, Any]], str]],
    alias_registry: Mapping[str, list[str]] | None = None,
    max_pages: int = 0,
    now: str | None = None,
) -> dict[str, Any]:
    aliases = alias_registry or {}
    query = urllib.parse.urlencode(
        {
            "per_page": 100,
            "type": "reviewed",
            "sort": "updated",
            "direction": "asc",
        }
    )
    next_url = f"{GITHUB_REVIEWED_ADVISORY_API}?{query}"
    seen_urls: set[str] = set()
    entries: dict[tuple[str, str, str], dict[str, Any]] = {}
    page_count = 0
    source_advisory_count = 0
    withdrawn_excluded_count = 0
    malformed_excluded_count = 0
    vulnerability_rows_seen = 0
    last_updated_at = ""
    truncated = False

    while next_url:
        if next_url in seen_urls:
            raise ValueError("GitHub advisory pagination loop detected")
        if max_pages > 0 and page_count >= max_pages:
            truncated = True
            break
        seen_urls.add(next_url)
        rows, following = fetch_page(next_url)
        page_count += 1
        source_advisory_count += len(rows)

        for row in rows:
            updated_at = _text(row.get("updated_at"))
            if updated_at > last_updated_at:
                last_updated_at = updated_at
            normalized, stats = _normalize_advisory_rows(
                row,
                alias_registry=aliases,
            )
            withdrawn_excluded_count += stats["withdrawn_excluded"]
            malformed_excluded_count += stats["malformed_excluded"]
            vulnerability_rows_seen += stats["vulnerability_rows_seen"]
            for entry in normalized:
                identity = _catalog_identity(entry)
                existing = entries.get(identity)
                if existing is None:
                    entries[identity] = entry
                    continue
                for field in ("affected_ranges", "patched_versions", "aliases"):
                    values = {
                        _text(item)
                        for item in list(existing.get(field) or [])
                        + list(entry.get(field) or [])
                        if _text(item)
                    }
                    existing[field] = sorted(values)
                existing["range_match_supported"] = any(
                    range_expression_supported(expression)
                    for expression in existing["affected_ranges"]
                )
                if _text(entry.get("updated_at")) > _text(existing.get("updated_at")):
                    for field in (
                        "cve",
                        "severity",
                        "published_at",
                        "updated_at",
                        "reviewed_at",
                        "source_url",
                    ):
                        existing[field] = entry.get(field, existing.get(field))

        next_url = following

    advisories = sorted(
        entries.values(),
        key=lambda item: (
            _text(item.get("ecosystem")).lower(),
            _text(item.get("product")).lower(),
            _text(item.get("id")).upper(),
        ),
    )
    supported_entries = sum(
        1 for item in advisories if bool(item.get("range_match_supported"))
    )
    unsupported_entries = len(advisories) - supported_entries
    sync_complete = not truncated and not next_url
    generated_at = now or _utc_now()

    payload: dict[str, Any] = {
        "version": CATALOG_SCHEMA_VERSION,
        "generated_at": generated_at,
        "completeness": (
            "github_reviewed_full_snapshot"
            if sync_complete
            else "github_reviewed_partial_snapshot"
        ),
        "runtime_role": "positive_match_only",
        "source_snapshot": {
            "provider": "github_advisory_database",
            "scope": "github_reviewed_non_malware",
            "api_endpoint": GITHUB_REVIEWED_ADVISORY_API,
            "api_version": GITHUB_API_VERSION,
            "sync_complete": sync_complete,
            "page_count": page_count,
            "source_advisory_count": source_advisory_count,
            "vulnerability_rows_seen": vulnerability_rows_seen,
            "normalized_package_entry_count": len(advisories),
            "supported_match_entry_count": supported_entries,
            "unsupported_match_entry_count": unsupported_entries,
            "withdrawn_excluded_count": withdrawn_excluded_count,
            "malformed_excluded_count": malformed_excluded_count,
            "last_updated_at": last_updated_at,
            "runtime_network_dependency": False,
            "catalog_miss_means_safe": False,
        },
        "advisories": advisories,
    }
    payload["integrity"] = {
        "algorithm": "sha256",
        "advisories_sha256": advisories_sha256(advisories),
    }
    validation = validate_catalog_payload(payload)
    if not validation["valid"]:
        raise ValueError(
            "Generated dependency advisory catalog failed validation: "
            + json.dumps(validation, sort_keys=True)
        )
    return payload


def sync_catalog(
    *,
    token: str = "",
    alias_path: str | Path | None = None,
    max_pages: int = 0,
    fetch_page: Callable[[str], tuple[list[dict[str, Any]], str]] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    aliases = load_alias_registry(alias_path)
    if fetch_page is None:
        def live_fetch(url: str) -> tuple[list[dict[str, Any]], str]:
            return _api_get_page(url, token=token)
        selected_fetch = live_fetch
    else:
        selected_fetch = fetch_page
    return build_catalog_from_pages(
        fetch_page=selected_fetch,
        alias_registry=aliases,
        max_pages=max_pages,
        now=now,
    )


def write_catalog_atomic(path: str | Path, payload: Mapping[str, Any]) -> Path:
    selected = Path(path)
    selected.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(
        dict(payload),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(selected.parent),
        prefix=selected.name + ".",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        handle.write(rendered)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, selected)
    return selected


def update_manifest_entry(
    manifest_path: str | Path,
    *,
    file_path: str | Path,
    root: str | Path | None = None,
) -> None:
    root_path = Path(root) if root else ROOT_DIR
    manifest = Path(manifest_path)
    selected = Path(file_path)
    relative = selected.resolve().relative_to(root_path.resolve()).as_posix()
    digest = hashlib.sha256(selected.read_bytes()).hexdigest()
    lines = manifest.read_text(encoding="utf-8").splitlines()
    suffix = "  " + relative
    replaced = False
    for index, line in enumerate(lines):
        if line.endswith(suffix):
            lines[index] = f"{digest}  {relative}"
            replaced = True
            break
    if not replaced:
        lines.append(f"{digest}  {relative}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def sync_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    validation = validate_catalog_payload(payload)
    source = payload.get("source_snapshot")
    source_snapshot = dict(source) if isinstance(source, Mapping) else {}
    return {
        "sync_version": DEPENDENCY_ADVISORY_CATALOG_SYNC_VERSION,
        "rule_version": DEPENDENCY_ADVISORY_CATALOG_SYNC_RULE_VERSION,
        "catalog_version": str(payload.get("version") or ""),
        "generated_at": str(payload.get("generated_at") or ""),
        "completeness": str(payload.get("completeness") or ""),
        "sync_complete": bool(source_snapshot.get("sync_complete")),
        "page_count": int(source_snapshot.get("page_count") or 0),
        "source_advisory_count": int(source_snapshot.get("source_advisory_count") or 0),
        "normalized_package_entry_count": int(
            source_snapshot.get("normalized_package_entry_count") or 0
        ),
        "supported_match_entry_count": int(
            source_snapshot.get("supported_match_entry_count") or 0
        ),
        "unsupported_match_entry_count": int(
            source_snapshot.get("unsupported_match_entry_count") or 0
        ),
        "withdrawn_excluded_count": int(
            source_snapshot.get("withdrawn_excluded_count") or 0
        ),
        "malformed_excluded_count": int(
            source_snapshot.get("malformed_excluded_count") or 0
        ),
        "last_updated_at": str(source_snapshot.get("last_updated_at") or ""),
        "integrity_valid": bool(validation.get("integrity_valid")),
        "runtime_network_dependency": False,
        "catalog_miss_means_safe": False,
        "target_contact_performed": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Synchronize the offline dependency advisory catalog"
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Catalog JSON output path",
    )
    parser.add_argument(
        "--aliases",
        default=str(DEFAULT_ALIASES),
        help="Package alias registry JSON",
    )
    parser.add_argument(
        "--github-token",
        default="",
        help="GitHub token; defaults to GITHUB_TOKEN",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=0,
        help="0 traverses the full reviewed-advisory cursor; positive values are test/debug caps",
    )
    parser.add_argument(
        "--update-manifest",
        action="store_true",
        help="Refresh the output file entry in MANIFEST.sha256",
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help="Manifest path used with --update-manifest",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = sync_catalog(
        token=_text(args.github_token) or os.environ.get("GITHUB_TOKEN", ""),
        alias_path=args.aliases,
        max_pages=max(0, int(args.max_pages or 0)),
    )
    output = write_catalog_atomic(args.output, payload)
    if bool(args.update_manifest):
        update_manifest_entry(
            args.manifest,
            file_path=output,
            root=ROOT_DIR,
        )
    print(json.dumps(sync_summary(payload), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
