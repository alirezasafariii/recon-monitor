from __future__ import annotations

"""Compatibility entrypoint that enriches Corpus V1 advisory project identity.

GitHub-reviewed global advisories do not always populate source_code_location.
This resolver derives the same canonical owner/repo identity from the repository
advisory URL or a GitHub security-advisory reference before the historical
exposure firewall runs. It does not weaken source-project uniqueness.
"""

import re
from typing import Any, Mapping

import real_world_corpus_v1 as corpus

_API_REPO_RE = re.compile(r"^https?://api\.github\.com/repos/([^/]+)/([^/]+)/security-advisories/", re.I)
_WEB_ADVISORY_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/security/advisories/", re.I)
_WEB_REPO_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/#?]+)", re.I)


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


_base_normalize_advisory = corpus.normalize_advisory


def normalize_advisory_with_project_fallback(row: Mapping[str, Any]) -> dict[str, Any]:
    candidate = _base_normalize_advisory(row)
    if not str(candidate.get("source_project") or "").strip():
        candidate["source_project"] = resolve_source_project(row)
    return candidate


def main() -> int:
    corpus.normalize_advisory = normalize_advisory_with_project_fallback
    return corpus.main()


if __name__ == "__main__":
    raise SystemExit(main())
