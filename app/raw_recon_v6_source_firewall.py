from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from raw_recon_corpus import ROOT, prior_source_index
from raw_recon_v5_source_discovery import exposure_index as prior_discovery_exposure
import raw_recon_v4_source_discovery as v4

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.31"
V5_CORPUS = ROOT / "benchmarks/raw/analysis_raw_v5.jsonl"
V5_SOURCE_FILES = (
    ROOT / "benchmarks/raw/sources/v5_candidates.json",
    ROOT / "benchmarks/raw/sources/v5_exact_source_supplement.json",
    ROOT / "benchmarks/raw/sources/v5_shortlist.json",
    ROOT / "benchmarks/raw/sources/v5_prepare_report.json",
)
CAL630 = ROOT / "benchmarks/calibration/analysis_630_open_redirect.json"


def _norm(value: Any) -> str:
    return str(value or "").strip()


def canonical_url(value: Any) -> str:
    text = _norm(value)
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    if not parsed.scheme or not parsed.netloc:
        return text.rstrip("/")
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port and not ((parsed.scheme.lower() == "https" and port == 443) or (parsed.scheme.lower() == "http" and port == 80)):
        host = f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), host, parsed.path.rstrip("/"), parsed.query, ""))


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
    root = _norm(row.get("source_root"))
    project = _norm(row.get("source_project"))
    if root:
        index["roots"].add(root)
    if project:
        index["projects"].add(project)
    for key in ("canonical_advisory_url", "repository_advisory_url", "source_code_location", "source_url"):
        url = canonical_url(row.get(key))
        if url:
            index["urls"].add(url)
    provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
    url = canonical_url(provenance.get("url"))
    if url:
        index["urls"].add(url)
    for value in row.get("references") or []:
        url = canonical_url(value)
        if url:
            index["urls"].add(url)


def exposure_index() -> dict[str, set[str]]:
    prior = prior_discovery_exposure()
    index = {
        "roots": set(prior.get("roots", set())),
        "projects": set(prior.get("projects", set())),
        "urls": {canonical_url(value) for value in prior.get("urls", set()) if canonical_url(value)},
    }

    if V5_CORPUS.exists():
        corpus = prior_source_index((V5_CORPUS,))
        index["roots"].update(corpus["roots"])
        index["projects"].update(corpus["projects"])
        index["urls"].update(canonical_url(value) for value in corpus["urls"] if canonical_url(value))

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

    index["urls"].update(canonical_url(value) for value in v4._grounding_writeup_urls() if canonical_url(value))
    return index


def check_candidate(row: Mapping[str, Any]) -> dict[str, Any]:
    index = exposure_index()
    root = _norm(row.get("source_root"))
    project = _norm(row.get("source_project"))
    urls = {
        canonical_url(row.get("canonical_advisory_url")),
        canonical_url(row.get("repository_advisory_url")),
        canonical_url(row.get("source_code_location")),
        canonical_url(row.get("source_url")),
    }
    urls.update(canonical_url(value) for value in row.get("references") or [])
    urls.discard("")

    root_overlap = root in index["roots"] if root else False
    project_overlap = project in index["projects"] if project else False
    url_overlap = sorted(urls & index["urls"])
    return {
        "allowed": bool(root and project) and not root_overlap and not project_overlap and not url_overlap,
        "source_root": root,
        "source_project": project,
        "root_overlap": root_overlap,
        "project_overlap": project_overlap,
        "url_overlap": url_overlap,
        "firewall_version": VERSION,
        "firewall_rule_version": RULE_VERSION,
        "scoring_executed": False,
    }


def validate_shortlist(rows: Iterable[Mapping[str, Any]], *, required_count: int = 36) -> dict[str, Any]:
    candidates = [dict(row) for row in rows]
    checks = [check_candidate(row) for row in candidates]
    roots = {_norm(row.get("source_root")) for row in candidates if _norm(row.get("source_root"))}
    projects = {_norm(row.get("source_project")) for row in candidates if _norm(row.get("source_project"))}
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


__all__ = ["VERSION", "RULE_VERSION", "canonical_url", "exposure_index", "check_candidate", "validate_shortlist"]
