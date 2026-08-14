from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from raw_recon_corpus import ROOT, prior_source_index
from raw_recon_v5_source_discovery import exposure_index as prior_discovery_exposure
import raw_recon_v4_source_discovery as v4

VERSION = "1.1.0"
RULE_VERSION = "2026.08.14.6.31.1"
V5_CORPUS = ROOT / "benchmarks/raw/analysis_raw_v5.jsonl"
V5_SOURCE_FILES = (
    ROOT / "benchmarks/raw/sources/v5_candidates.json",
    ROOT / "benchmarks/raw/sources/v5_exact_source_supplement.json",
    ROOT / "benchmarks/raw/sources/v5_shortlist.json",
    ROOT / "benchmarks/raw/sources/v5_prepare_report.json",
)
CAL630 = ROOT / "benchmarks/calibration/analysis_630_open_redirect.json"
IDENTIFIER_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})\b", re.IGNORECASE)
GITHUB_HOSTS = {"github.com", "www.github.com", "api.github.com"}


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _identity(value: Any) -> str:
    return _norm(value).casefold()


def _identifiers(value: Any) -> set[str]:
    return {match.group(0).casefold() for match in IDENTIFIER_RE.finditer(_norm(value))}


def canonical_url(value: Any) -> str:
    text = _norm(value)
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text.rstrip("/")
    if not parsed.scheme or not parsed.netloc:
        return text.rstrip("/")
    host = (parsed.hostname or "").lower()
    if host == "www.github.com":
        host = "github.com"
    port = parsed.port
    if port and not ((parsed.scheme.lower() == "https" and port == 443) or (parsed.scheme.lower() == "http" and port == 80)):
        host = f"{host}:{port}"
    path = parsed.path.rstrip("/")
    if host in {"github.com", "api.github.com"}:
        path = path.casefold()
    return urlunsplit((parsed.scheme.lower(), host, path, parsed.query, ""))


def _project_from_url(value: Any) -> str:
    url = canonical_url(value)
    if not url:
        return ""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.hostname == "github.com" and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}".casefold()
    if parsed.hostname == "api.github.com" and len(parts) >= 3 and parts[0] == "repos":
        return f"{parts[1]}/{parts[2]}".casefold()
    return ""


def _row_urls(row: Mapping[str, Any]) -> set[str]:
    urls = {
        canonical_url(row.get("canonical_advisory_url")),
        canonical_url(row.get("repository_advisory_url")),
        canonical_url(row.get("source_code_location")),
        canonical_url(row.get("source_url")),
    }
    provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
    urls.add(canonical_url(provenance.get("url")))
    urls.update(canonical_url(value) for value in row.get("references") or [])
    urls.update(canonical_url(value) for value in row.get("source_url_aliases") or [])
    urls.discard("")
    return urls


def _row_projects(row: Mapping[str, Any], urls: Iterable[str] = ()) -> set[str]:
    projects = {_identity(row.get("source_project"))}
    projects.update(_identity(value) for value in row.get("source_project_aliases") or [])
    projects.update(_identity(value) for value in row.get("redirected_from_projects") or [])
    projects.update(_project_from_url(value) for value in urls)
    projects.discard("")
    return projects


def _row_roots(row: Mapping[str, Any], urls: Iterable[str] = ()) -> set[str]:
    roots = {_identity(row.get("source_root"))}
    roots.update(_identity(value) for value in row.get("source_root_aliases") or [])
    for value in urls:
        roots.update(_identifiers(value))
    for value in list(roots):
        roots.update(_identifiers(value))
    roots.discard("")
    return roots


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _walk_rows(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        if any(key in value for key in ("source_root", "source_project", "canonical_advisory_url", "source_url")):
            yield value
        for child in value.values():
            yield from _walk_rows(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_rows(child)


def _add_row(index: dict[str, set[str]], row: Mapping[str, Any]) -> None:
    urls = _row_urls(row)
    roots = _row_roots(row, urls)
    projects = _row_projects(row, urls)
    index["roots"].update(roots)
    index["projects"].update(projects)
    index["urls"].update(urls)
    for value in roots:
        index["identifiers"].update(_identifiers(value))
    for value in urls:
        index["identifiers"].update(_identifiers(value))


def exposure_index() -> dict[str, set[str]]:
    prior = prior_discovery_exposure()
    prior_roots = {_identity(value) for value in prior.get("roots", set()) if _identity(value)}
    prior_projects = {_identity(value) for value in prior.get("projects", set()) if _identity(value)}
    prior_urls = {canonical_url(value) for value in prior.get("urls", set()) if canonical_url(value)}
    index = {
        "roots": prior_roots,
        "projects": prior_projects,
        "urls": prior_urls,
        "identifiers": set(),
    }
    for value in prior_roots | prior_urls:
        index["identifiers"].update(_identifiers(value))

    if V5_CORPUS.exists():
        corpus = prior_source_index((V5_CORPUS,))
        corpus_roots = {_identity(value) for value in corpus["roots"] if _identity(value)}
        corpus_projects = {_identity(value) for value in corpus["projects"] if _identity(value)}
        corpus_urls = {canonical_url(value) for value in corpus["urls"] if canonical_url(value)}
        index["roots"].update(corpus_roots)
        index["projects"].update(corpus_projects)
        index["urls"].update(corpus_urls)
        for value in corpus_roots | corpus_urls:
            index["identifiers"].update(_identifiers(value))

    for path in V5_SOURCE_FILES:
        value = _read_json(path)
        if value is None:
            continue
        for row in _walk_rows(value):
            _add_row(index, row)

    calibration = _read_json(CAL630)
    if calibration is not None:
        for row in _walk_rows(calibration):
            _add_row(index, row)

    grounding_urls = {canonical_url(value) for value in v4._grounding_writeup_urls() if canonical_url(value)}
    index["urls"].update(grounding_urls)
    for value in grounding_urls:
        index["identifiers"].update(_identifiers(value))
    return index


def check_candidate(row: Mapping[str, Any]) -> dict[str, Any]:
    index = exposure_index()
    urls = _row_urls(row)
    roots = _row_roots(row, urls)
    projects = _row_projects(row, urls)
    identifiers = set()
    for value in roots | urls:
        identifiers.update(_identifiers(value))

    root_overlap = sorted(roots & index["roots"])
    project_overlap = sorted(projects & index["projects"])
    url_overlap = sorted(urls & index["urls"])
    identifier_overlap = sorted(identifiers & index["identifiers"])
    primary_root = _identity(row.get("source_root"))
    primary_project = _identity(row.get("source_project"))
    allowed = bool(primary_root and primary_project) and not (
        root_overlap or project_overlap or url_overlap or identifier_overlap
    )
    return {
        "allowed": allowed,
        "source_root": primary_root,
        "source_project": primary_project,
        "root_overlap": root_overlap,
        "project_overlap": project_overlap,
        "url_overlap": url_overlap,
        "identifier_overlap": identifier_overlap,
        "checked_root_aliases": sorted(roots),
        "checked_project_aliases": sorted(projects),
        "firewall_version": VERSION,
        "firewall_rule_version": RULE_VERSION,
        "scoring_executed": False,
    }


def validate_shortlist(rows: Iterable[Mapping[str, Any]], *, required_count: int = 36) -> dict[str, Any]:
    candidates = [dict(row) for row in rows]
    checks = [check_candidate(row) for row in candidates]
    roots = {_identity(row.get("source_root")) for row in candidates if _identity(row.get("source_root"))}
    projects = {_identity(row.get("source_project")) for row in candidates if _identity(row.get("source_project"))}
    failed = [check for check in checks if not check["allowed"]]
    errors: list[str] = []
    if len(candidates) != required_count:
        errors.append(f"shortlist count must be {required_count}: {len(candidates)}")
    if len(roots) != required_count:
        errors.append(f"shortlist must contain {required_count} unique roots: {len(roots)}")
    if len(projects) != required_count:
        errors.append(f"shortlist must contain {required_count} unique projects: {len(projects)}")
    if failed:
        errors.append(f"source firewall rejected {len(failed)} candidate(s)")
    return {
        "passed": not errors,
        "errors": errors,
        "candidate_count": len(candidates),
        "unique_root_count": len(roots),
        "unique_project_count": len(projects),
        "rejected": failed,
        "firewall_version": VERSION,
        "firewall_rule_version": RULE_VERSION,
        "scoring_executed": False,
    }


__all__ = [
    "VERSION",
    "RULE_VERSION",
    "canonical_url",
    "exposure_index",
    "check_candidate",
    "validate_shortlist",
]
