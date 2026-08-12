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

from raw_recon_corpus import prior_source_index
from raw_recon_v3_corpus import ROOT, V3_PRIOR_CORPORA

SOURCE_DISCOVERY_VERSION = "1.0.0"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"
V2_CANDIDATES = ROOT / "benchmarks" / "raw" / "sources" / "v2_candidates.json"
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
OBSERVABILITY_TERMS = {
    "broken_object_authorization": ("unauthorized", "other user", "another user", "access", "object", "tenant", "owner"),
    "broken_function_authorization": ("unauthorized", "privilege", "admin", "role", "permission", "bypass"),
    "mass_assignment": ("mass assignment", "property", "field", "role", "admin", "privilege", "update"),
    "authentication_session": ("authentication", "login", "session", "token", "oauth", "bypass", "unauthenticated"),
    "account_enumeration": ("enumerat", "different response", "timing", "exist", "username", "email", "account"),
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
    "secret_exposure": ("hard-coded", "hardcoded", "credential", "secret", "api key", "password", "token"),
}


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _project_from_source(url: str) -> str:
    match = re.match(r"https://github\.com/([^/]+/[^/#?]+)", url or "")
    return match.group(1).removesuffix(".git") if match else ""


def _headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "recon-monitor-analysis-6.15"}
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _v2_exposure_index() -> tuple[set[str], set[str]]:
    roots: set[str] = set(KNOWN_PREVIOUSLY_EXPOSED_ROOTS)
    urls: set[str] = set()
    if not V2_CANDIDATES.exists():
        return roots, urls
    data = json.loads(V2_CANDIDATES.read_text(encoding="utf-8"))
    pools = data.get("candidates_by_family") if isinstance(data.get("candidates_by_family"), Mapping) else {}
    for rows in pools.values():
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, Mapping):
                continue
            root = _norm(row.get("source_root"))
            url = _norm(row.get("canonical_advisory_url"))
            if root:
                roots.add(root)
            if url:
                urls.add(url)
    return roots, urls


def _next_link(header: str) -> str:
    for part in (header or "").split(","):
        if 'rel="next"' not in part:
            continue
        match = re.search(r"<([^>]+)>", part)
        if match:
            return match.group(1)
    return ""


def _fetch_pages(cwe: str, *, max_pages: int, per_page: int = 100) -> Iterable[list[dict[str, Any]]]:
    numeric = cwe.removeprefix("CWE-")
    query = urllib.parse.urlencode({"type": "reviewed", "cwes": numeric, "per_page": per_page})
    url = f"{GITHUB_ADVISORY_API}?{query}"
    for _ in range(max_pages):
        request = urllib.request.Request(url, headers=_headers())
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
            link = response.headers.get("Link", "")
        rows = [dict(row) for row in data if isinstance(row, Mapping)]
        if not rows:
            return
        yield rows
        url = _next_link(link)
        if not url:
            return


def _eligible_rows(rows: Iterable[Mapping[str, Any]], family: str, cwe: str, *, excluded_roots: set[str], excluded_urls: set[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        root = _norm(row.get("ghsa_id"))
        repo_api = _norm(row.get("repository_advisory_url"))
        source = _norm(row.get("source_code_location"))
        description = _norm(row.get("description"))
        refs = [_norm(value) for value in row.get("references") or [] if _norm(value)]
        canonical = next((value for value in refs if "/security/advisories/" in value and value.startswith("https://github.com/")), "")
        row_cwes = {_norm(item.get("cwe_id")) for item in row.get("cwes") or [] if isinstance(item, Mapping)}
        if cwe not in row_cwes or not root or root in excluded_roots or canonical in excluded_urls or row.get("withdrawn_at"):
            continue
        if not repo_api or not source or not canonical or len(description) < 160:
            continue
        project = _project_from_source(source)
        if not project:
            continue
        hits = [term for term in OBSERVABILITY_TERMS[family] if term in description.lower()]
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


def discover(*, max_pages: int = 5, target_per_family: int = 80) -> dict[str, Any]:
    prior = prior_source_index(V3_PRIOR_CORPORA)
    v2_roots, v2_urls = _v2_exposure_index()
    excluded_roots = set(prior["roots"]) | v2_roots
    excluded_urls = set(prior["urls"]) | v2_urls
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    queried = 0
    for family, cwe in SOURCE_BUCKETS:
        seen: set[str] = set()
        for page in _fetch_pages(cwe, max_pages=max_pages):
            queried += len(page)
            for row in _eligible_rows(page, family, cwe, excluded_roots=excluded_roots, excluded_urls=excluded_urls):
                root = row["source_root"]
                if root in seen:
                    continue
                seen.add(root)
                by_family[family].append(row)
                if len(by_family[family]) >= target_per_family:
                    break
            if len(by_family[family]) >= target_per_family:
                break
        by_family[family].sort(key=lambda item: (item["published_at"], item["source_root"]), reverse=True)
    unique = {(row["source_root"], row["family"]) for rows in by_family.values() for row in rows}
    return {
        "source_discovery_version": SOURCE_DISCOVERY_VERSION,
        "queried_reviewed_advisory_count": queried,
        "eligible_candidate_count": len(unique),
        "family_candidate_counts": {family: len(by_family.get(family, [])) for family, _ in SOURCE_BUCKETS},
        "candidates_by_family": {family: by_family.get(family, []) for family, _ in SOURCE_BUCKETS},
        "excluded_prior_root_count": len(excluded_roots),
        "excluded_v2_candidate_root_count": len(v2_roots),
        "note": "Discovery only. All raw-v2 candidate roots are excluded in addition to prior benchmark roots. No Analysis Engine detector, ranking, admission, reconstruction, or benchmark scoring is executed.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover unseen primary advisory candidates for Analysis 6.15 raw v3")
    parser.add_argument("--max-pages", type=int, default=5)
    parser.add_argument("--target-per-family", type=int, default=80)
    parser.add_argument("--output", default=str(ROOT / "benchmarks" / "raw" / "sources" / "v3_candidates.json"))
    args = parser.parse_args()
    report = discover(max_pages=max(1, args.max_pages), target_per_family=max(1, args.target_per_family))
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("queried_reviewed_advisory_count", "eligible_candidate_count", "family_candidate_counts", "excluded_v2_candidate_root_count")}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
