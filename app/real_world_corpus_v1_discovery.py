from __future__ import annotations

"""Hardened source-discovery entrypoint for Real-World Corpus V1.

Corrections live here so the baseline 8.6 implementation remains easy to
review:

1. historical exposure is derived only from explicit source identity fields;
   vulnerability IDs merely mentioned in prose do not poison the fresh pool;
2. consumed Raw v4 and Raw v5 are included in the exposure firewall, while V6
   remains reserved blind;
3. GitHub global advisories are traversed through the REST Link cursor rather
   than a numeric ``page`` parameter, which that endpoint does not advance.

This module never scores Analysis output, contacts vulnerability targets, or
creates human labels.
"""

import json
import re
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any, Iterable, Mapping

import real_world_corpus_v1 as corpus

_API_REPO_RE = re.compile(r"^https?://api\.github\.com/repos/([^/]+)/([^/]+)/security-advisories/", re.I)
_WEB_ADVISORY_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/security/advisories/", re.I)
_WEB_REPO_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/#?]+)", re.I)
_NEXT_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="next"')

EXTRA_CONSUMED_CORPORA = (
    (
        "analysis_raw_v4",
        "agent/analysis-engine-6.26-fresh-raw-holdout-v4",
        "benchmarks/raw/analysis_raw_v4.jsonl",
        "consumed_benchmark",
    ),
    (
        "analysis_raw_v5",
        "agent/analysis-engine-6.29-fresh-blind-v5-multifamily",
        "benchmarks/raw/analysis_raw_v5.jsonl",
        "consumed_benchmark",
    ),
)


def resolve_source_project(row: Mapping[str, Any]) -> str:
    direct = corpus._project(row.get("source_code_location"))
    if direct:
        return direct

    repository_advisory = str(row.get("repository_advisory_url") or "").strip()
    match = _API_REPO_RE.match(repository_advisory)
    if match:
        return f"{match.group(1)}/{match.group(2)}".lower()

    for reference in row.get("references", []) or []:
        text = str(reference or "").strip()
        match = _WEB_ADVISORY_RE.match(text)
        if match:
            return f"{match.group(1)}/{match.group(2)}".lower()
        match = _WEB_REPO_RE.match(text)
        if match and match.group(1).lower() not in {"advisories"}:
            return f"{match.group(1)}/{match.group(2)}".lower()
    return ""


def _values(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def strict_identities_from_records(records: Iterable[Any]) -> dict[str, set[str]]:
    """Extract only explicit source identity, never identifiers from prose."""

    roots: set[str] = set()
    projects: set[str] = set()
    urls: set[str] = set()
    identifiers: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            for raw_key, child in value.items():
                key = str(raw_key).lower()
                if key in {"source_root", "ghsa_id"}:
                    for item in _values(child):
                        token = str(item or "").strip().upper()
                        if token:
                            roots.add(token)
                            identifiers.add(token)
                elif key in {"source_project", "source_code_location"}:
                    for item in _values(child):
                        project = corpus._project(item)
                        if project:
                            projects.add(project)
                elif key == "cve_id":
                    for item in _values(child):
                        token = str(item or "").strip().upper()
                        if token:
                            identifiers.add(token)
                elif key == "identifiers":
                    for item in _values(child):
                        if isinstance(item, Mapping):
                            token = str(item.get("value") or "").strip().upper()
                        else:
                            token = str(item or "").strip().upper()
                        if token:
                            identifiers.add(token)
                elif key in {
                    "canonical_advisory_url",
                    "repository_advisory_url",
                    "source_code_location",
                    "capture_reference",
                }:
                    for item in _values(child):
                        token = str(item or "").strip()
                        if token.startswith("http"):
                            urls.add(corpus._norm(token))
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for record in records:
        visit(record)

    return {
        "roots": roots,
        "projects": projects,
        "urls": urls,
        "identifiers": identifiers,
    }


_base_normalize_advisory = corpus.normalize_advisory


def normalize_advisory_with_project_fallback(row: Mapping[str, Any]) -> dict[str, Any]:
    candidate = _base_normalize_advisory(row)
    if not str(candidate.get("source_project") or "").strip():
        candidate["source_project"] = resolve_source_project(row)
    return candidate


def _api_page(url: str, token: str = "") -> tuple[Any, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-real-world-corpus-v1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
        link = str(response.headers.get("Link") or "")
    match = _NEXT_LINK_RE.search(link)
    return payload, (match.group(1) if match else "")


def discover_candidates_cursor(
    exposed: Mapping[str, set[str]],
    *,
    token: str = "",
    max_pages: int = 20,
    selection_limit: int = 180,
) -> dict[str, Any]:
    """Discover independent advisory roots through GitHub's cursor links."""

    accepted: list[dict[str, Any]] = []
    rejected: Counter[str] = Counter()
    seen_roots: set[str] = set()
    seen_projects: set[str] = set()
    fetched = 0
    pages_fetched = 0
    first_query = urllib.parse.urlencode(
        {"per_page": 100, "type": "reviewed", "sort": "published", "direction": "desc"}
    )
    next_url = f"https://api.github.com/advisories?{first_query}"
    seen_page_heads: set[str] = set()

    while next_url and pages_fetched < max(1, int(max_pages)):
        rows, following = _api_page(next_url, token=token)
        if not isinstance(rows, list) or not rows:
            break
        pages_fetched += 1
        fetched += len(rows)
        page_head = str(rows[0].get("ghsa_id") or "") if isinstance(rows[0], Mapping) else ""
        if page_head and page_head in seen_page_heads:
            rejected["repeated_api_page_guard"] += len(rows)
            break
        if page_head:
            seen_page_heads.add(page_head)

        for raw in rows:
            if not isinstance(raw, Mapping):
                continue
            candidate = normalize_advisory_with_project_fallback(raw)
            root = str(candidate.get("source_root") or "").strip()
            project = corpus._project(candidate.get("source_project"))
            if not root or not project:
                rejected["missing_root_or_project"] += 1
                continue
            if raw.get("withdrawn_at"):
                rejected["withdrawn"] += 1
                continue
            reasons = corpus.exposure_reasons(candidate, exposed)
            if reasons:
                for reason in reasons:
                    rejected[reason] += 1
                continue
            if root in seen_roots:
                rejected["duplicate_new_root"] += 1
                continue
            if project in seen_projects:
                rejected["duplicate_new_project"] += 1
                continue
            seen_roots.add(root)
            seen_projects.add(project)
            accepted.append(candidate)
            if len(accepted) >= int(selection_limit):
                break
        if len(accepted) >= int(selection_limit):
            break
        next_url = following

    family_counts = Counter(hint for row in accepted for hint in row.get("family_hints", []))
    return {
        "version": corpus.REAL_WORLD_CORPUS_VERSION,
        "rule_version": corpus.REAL_WORLD_CORPUS_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_pre_score_source_discovery",
        "scoring_executed": False,
        "target_contact_performed": False,
        "human_labels_created": False,
        "pagination_mode": "github_link_cursor",
        "pages_fetched": pages_fetched,
        "fetched_advisory_count": fetched,
        "selected_candidate_count": len(accepted),
        "unique_source_root_count": len(seen_roots),
        "unique_source_project_count": len(seen_projects),
        "family_hint_count": len(family_counts),
        "family_hint_counts": dict(sorted(family_counts.items())),
        "rejected_counts": dict(sorted(rejected.items())),
        "candidates": accepted,
    }


def main() -> int:
    corpus.identities_from_records = strict_identities_from_records
    corpus.normalize_advisory = normalize_advisory_with_project_fallback
    corpus.discover_candidates = discover_candidates_cursor
    existing_names = {item[0] for item in corpus.HISTORICAL_CORPORA}
    corpus.HISTORICAL_CORPORA = corpus.HISTORICAL_CORPORA + tuple(
        item for item in EXTRA_CONSUMED_CORPORA if item[0] not in existing_names
    )
    return corpus.main()


if __name__ == "__main__":
    raise SystemExit(main())
