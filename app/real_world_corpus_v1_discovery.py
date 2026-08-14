from __future__ import annotations

"""Hardened source-discovery entrypoint for Real-World Corpus V1.

Two corrections live here so the baseline 8.6 implementation remains easy to
review:

1. historical exposure is derived only from explicit source identity fields;
   vulnerability IDs merely mentioned in prose do not poison the fresh pool;
2. consumed Raw v4 and Raw v5 are included in the exposure firewall, while V6
   remains reserved blind.

This module never scores Analysis output, contacts vulnerability targets, or
creates human labels.
"""

import re
from typing import Any, Iterable, Mapping

import real_world_corpus_v1 as corpus

_API_REPO_RE = re.compile(r"^https?://api\.github\.com/repos/([^/]+)/([^/]+)/security-advisories/", re.I)
_WEB_ADVISORY_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/security/advisories/", re.I)
_WEB_REPO_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/#?]+)", re.I)

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
        match = _WEB_ADVISORY_RE.match(text) or _WEB_REPO_RE.match(text)
        if match:
            return f"{match.group(1)}/{match.group(2)}".lower()
    return ""


def _values(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def strict_identities_from_records(records: Iterable[Any]) -> dict[str, set[str]]:
    """Extract only explicit source identity, never identifiers from prose.

    A historical case can quote neighboring advisories in description, notes,
    write-ups or diagnostic material. Those mentions are not proof that the
    neighboring advisory was used as a benchmark source. Treating them as roots
    caused false historical exposure and collapsed the fresh source pool.
    """

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
                elif key in {"cve_id"}:
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


def main() -> int:
    corpus.identities_from_records = strict_identities_from_records
    corpus.normalize_advisory = normalize_advisory_with_project_fallback
    existing_names = {item[0] for item in corpus.HISTORICAL_CORPORA}
    corpus.HISTORICAL_CORPORA = corpus.HISTORICAL_CORPORA + tuple(
        item for item in EXTRA_CONSUMED_CORPORA if item[0] not in existing_names
    )
    return corpus.main()


if __name__ == "__main__":
    raise SystemExit(main())
