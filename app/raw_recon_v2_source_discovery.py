from __future__ import annotations

import argparse
import json
import os
import re
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from raw_recon_v2_corpus import ROOT, V2_PRIOR_CORPORA
from raw_recon_corpus import prior_source_index

SOURCE_DISCOVERY_VERSION = "1.0.0"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"
KNOWN_PREVIOUSLY_EXPOSED_ROOTS = {
    "GHSA-c9w5-rwh3-7pm9",
    "GHSA-v8fg-2rw7-q452",
    "GHSA-p849-8hwh-84j9",
    "GHSA-6wcc-39rp-hh9p",
    "GHSA-pmpg-2mxq-6xwr",
}
SOURCE_BUCKETS = (
    ("broken_object_authorization", "CWE-639"),
    ("broken_function_authorization", "CWE-862"),
    ("mass_assignment", "CWE-915"),
    ("authentication_session", "CWE-287"),
    ("account_enumeration", "CWE-203"),
    ("open_redirect", "CWE-601"),
    ("ssrf", "CWE-918"),
    ("file_upload", "CWE-434"),
    ("path_traversal", "CWE-22"),
    ("information_disclosure", "CWE-200"),
    ("cors_misconfiguration", "CWE-942"),
    ("race_condition", "CWE-362"),
    ("sql_injection", "CWE-89"),
    ("nosql_injection", "CWE-943"),
    ("command_injection", "CWE-78"),
    ("server_side_template_injection", "CWE-1336"),
    ("ldap_injection", "CWE-90"),
    ("unrestricted_resource_consumption", "CWE-400"),
    ("security_misconfiguration", "CWE-209"),
    ("secret_exposure", "CWE-798"),
)
BUCKET_BY_CWE = {cwe: family for family, cwe in SOURCE_BUCKETS}
OBSERVABILITY_TERMS = {
    "broken_object_authorization": ("unauthorized", "other user", "another user", "access", "object", "tenant", "owner"),
    "broken_function_authorization": ("unauthorized", "privilege", "admin", "role", "permission", "bypass"),
    "mass_assignment": ("mass assignment", "property", "field", "role", "admin", "privilege", "update"),
    "authentication_session": ("authentication", "login", "session", "token", "oauth", "bypass", "unauthenticated"),
    "account_enumeration": ("enumerat", "different response", "exist", "username", "email", "account"),
    "open_redirect": ("redirect", "location", "external", "url"),
    "ssrf": ("server-side request", "ssrf", "fetch", "request", "url", "internal"),
    "file_upload": ("upload", "file", "extension", "mime", "attachment"),
    "path_traversal": ("path traversal", "directory traversal", "../", "arbitrary file", "path"),
    "information_disclosure": ("disclos", "expos", "response", "sensitive", "debug", "information"),
    "cors_misconfiguration": ("cors", "access-control-allow-origin", "origin", "cross-origin"),
    "race_condition": ("race", "concurrent", "atomic", "double", "simultaneous"),
    "sql_injection": ("sql injection", "database", "query", "sql"),
    "nosql_injection": ("nosql", "mongodb", "mongo", "operator", "query"),
    "command_injection": ("command injection", "shell", "command", "execute", "process"),
    "server_side_template_injection": ("template injection", "ssti", "template", "render", "expression"),
    "ldap_injection": ("ldap", "directory", "filter", "distinguished name"),
    "unrestricted_resource_consumption": ("resource", "memory", "cpu", "denial of service", "dos", "large", "unbounded"),
    "security_misconfiguration": ("stack trace", "error message", "debug", "misconfiguration", "configuration"),
    "secret_exposure": ("hard-coded", "credential", "secret", "api key", "password", "token"),
}


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _project_from_source(url: str) -> str:
    match = re.match(r"https://github\.com/([^/]+/[^/#?]+)", url or "")
    return match.group(1).removesuffix(".git") if match else ""


def _headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "recon-monitor-analysis-6.13"}
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_page(page: int, per_page: int = 100) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"type": "reviewed", "per_page": per_page, "page": page})
    request = urllib.request.Request(f"{GITHUB_ADVISORY_API}?{query}", headers=_headers())
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    return [dict(row) for row in data if isinstance(row, Mapping)]


def _eligible_rows(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    prior = prior_source_index(V2_PRIOR_CORPORA)
    seen_roots = set(prior["roots"]) | KNOWN_PREVIOUSLY_EXPOSED_ROOTS
    seen_urls = set(prior["urls"])
    result: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        root = _norm(row.get("ghsa_id"))
        repo_api = _norm(row.get("repository_advisory_url"))
        source = _norm(row.get("source_code_location"))
        description = _norm(row.get("description"))
        withdrawn = row.get("withdrawn_at")
        refs = [_norm(value) for value in row.get("references") or [] if _norm(value)]
        canonical = next((value for value in refs if "/security/advisories/" in value and value.startswith("https://github.com/")), "")
        cwes = {_norm(item.get("cwe_id")) for item in row.get("cwes") or [] if isinstance(item, Mapping)}
        matching = [(BUCKET_BY_CWE[cwe], cwe) for cwe in cwes if cwe in BUCKET_BY_CWE]
        if not matching:
            continue
        if root in seen_roots or canonical in seen_urls:
            continue
        if withdrawn or not repo_api or not source or not canonical or len(description) < 160:
            continue
        project = _project_from_source(source)
        if not project:
            continue
        for family, cwe in matching:
            lower = description.lower()
            hits = [term for term in OBSERVABILITY_TERMS[family] if term in lower]
            if not hits:
                continue
            result.append({
                "source_root": root,
                "source_project": project,
                "family": family,
                "cwe": cwe,
                "published_at": _norm(row.get("published_at")),
                "updated_at": _norm(row.get("updated_at")),
                "severity": _norm(row.get("severity")),
                "summary": _norm(row.get("summary")),
                "description": description,
                "repository_advisory_url": repo_api,
                "source_code_location": source,
                "canonical_advisory_url": canonical,
                "references": refs,
                "observable_term_hits": hits,
            })
    return result


def discover(*, pages: int = 30) -> dict[str, Any]:
    all_rows: list[dict[str, Any]] = []
    for page in range(1, pages + 1):
        rows = _fetch_page(page)
        if not rows:
            break
        all_rows.extend(rows)
    eligible = _eligible_rows(all_rows)
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in eligible:
        by_family[row["family"]].append(row)
    for family in by_family:
        by_family[family].sort(key=lambda item: (item["published_at"], item["source_root"]), reverse=True)
    return {
        "source_discovery_version": SOURCE_DISCOVERY_VERSION,
        "queried_reviewed_advisory_count": len(all_rows),
        "eligible_candidate_count": len(eligible),
        "family_candidate_counts": {family: len(by_family.get(family, [])) for family, _ in SOURCE_BUCKETS},
        "candidates_by_family": {family: by_family.get(family, []) for family, _ in SOURCE_BUCKETS},
        "known_previously_exposed_roots": sorted(KNOWN_PREVIOUSLY_EXPOSED_ROOTS),
        "note": "Discovery only. No Analysis Engine detector, ranking, admission, reconstruction, or benchmark scoring is executed by this collector.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover fresh primary advisory candidates for Analysis 6.13 raw v2")
    parser.add_argument("--pages", type=int, default=30)
    parser.add_argument("--output", default=str(ROOT / "benchmarks" / "raw" / "sources" / "v2_candidates.json"))
    args = parser.parse_args()
    report = discover(pages=max(1, args.pages))
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("queried_reviewed_advisory_count", "eligible_candidate_count", "family_candidate_counts")}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
