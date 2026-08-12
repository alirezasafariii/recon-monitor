from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping

from raw_recon_v3_corpus import ROOT

SHORTLIST_VERSION = "1.0.0"
DEFAULT_CANDIDATES = ROOT / "benchmarks" / "raw" / "sources" / "v3_candidates.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v3_shortlist.json"
DEFAULT_EXTERNAL = ROOT / "benchmarks" / "raw" / "sources" / "v3_external_primary_candidates.json"

ARTIFACT_MARKERS = {
    "broken_object_authorization": ("http ", "curl ", "status", "response", "other user", "another user", "unauthorized"),
    "broken_function_authorization": ("http ", "curl ", "status", "response", "admin", "unauthorized", "permission"),
    "mass_assignment": ("request", "response", "json", "field", "property", "role", "admin"),
    "authentication_session": ("http ", "curl ", "response", "login", "oauth", "session", "token", "unauthenticated"),
    "account_enumeration": ("http ", "status", "response", "timing", " ms", "different", "oracle"),
    "open_redirect": ("location:", "302", "301", "redirect", "http://", "https://"),
    "ssrf": ("curl ", "http://", "127.0.0.1", "localhost", "internal", "metadata", "response"),
    "file_upload": ("multipart", "content-type", "filename", "upload", "extension", "mime", "response"),
    "path_traversal": ("../", "..\\", "%2e%2e", "curl ", "response", "arbitrary file", "/etc/"),
    "information_disclosure": ("response", "http ", "stack trace", "debug", "sensitive", "exposed", "body"),
    "cors_misconfiguration": ("access-control-allow-origin", "access-control-allow-credentials", "origin:", "fetch(", "xmlhttprequest", "cross-origin"),
    "race_condition": ("concurrent", "simultaneous", "parallel", "double", "requests", "race", "thread"),
    "sql_injection": ("sql", "query", "database", "error", "poc", "curl ", "select "),
    "nosql_injection": ("mongodb", "mongo", "nosql", "$where", "$regex", "operator", "query", "poc"),
    "command_injection": ("command", "shell", "exec", "spawn", "poc", "curl ", "process"),
    "server_side_template_injection": ("{{", "${", "template", "render", "expression", "poc", "jinja", "twig"),
    "ldap_injection": ("ldap", "filter", "directory", "distinguished name", "poc", "search"),
    "unrestricted_resource_consumption": ("memory", "cpu", "seconds", "minutes", "mb", "gb", "large", "size", "runtime", "requests"),
    "security_misconfiguration": ("stack trace", "error message", "debug", "response", "http ", "configuration"),
    "secret_exposure": ("hard-coded", "hardcoded", "credential", "api key", "password", "token", "secret"),
}

# Semantic requirements prevent a broad CWE from becoming a mislabeled family
# fixture (for example, a generic CWE-203 padding oracle is not account enumeration).
SEMANTIC_GROUPS = {
    "broken_object_authorization": (("object", "record", "resource", "id", "tenant", "owner"), ("unauthorized", "other user", "another user", "access", "permission", "scope")),
    "broken_function_authorization": (("admin", "privilege", "permission", "role", "management"), ("unauthorized", "bypass", "lower privilege", "access")),
    "mass_assignment": (("mass assignment", "property", "field", "parameter", "json"), ("role", "admin", "permission", "privilege", "owner", "tenant", "sensitive")),
    "authentication_session": (("authentication", "login", "session", "oauth", "token", "password", "mfa"), ("bypass", "unauthenticated", "takeover", "impersonat", "without")),
    "account_enumeration": (("username", "email", "user account", "account", "user exists", "identity"), ("enumerat", "oracle", "timing", "different response", "existence")),
    "open_redirect": (("redirect",), ("location", "external", "attacker-controlled", "url")),
    "ssrf": (("ssrf", "server-side request", "server side request"), ("url", "fetch", "internal", "localhost", "metadata", "request")),
    "file_upload": (("upload",), ("file", "filename", "mime", "extension", "attachment")),
    "path_traversal": (("path traversal", "directory traversal", "../", "..\\"), ("file", "path", "directory", "archive")),
    "information_disclosure": (("disclos", "expos", "leak"), ("information", "sensitive", "response", "debug", "data", "secret")),
    "cors_misconfiguration": (("cors", "cross-origin", "cross origin", "access-control-allow-origin"), ("origin", "credential", "response", "read")),
    "race_condition": (("race", "concurrent", "simultaneous", "parallel"), ("double", "duplicate", "atomic", "balance", "single-use", "redeem", "claim", "transfer")),
    "sql_injection": (("sql injection", "sqli"), ("query", "database", "sql")),
    "nosql_injection": (("nosql", "mongodb", "mongo"), ("injection", "operator", "query", "$where", "$regex")),
    "command_injection": (("command injection",), ("shell", "command", "exec", "process", "spawn")),
    "server_side_template_injection": (("template injection", "ssti", "server-side template", "server side template"), ("template", "render", "expression", "jinja", "twig")),
    "ldap_injection": (("ldap",), ("injection", "filter", "directory", "search")),
    "unrestricted_resource_consumption": (("resource", "denial of service", " dos", "memory", "cpu"), ("unbounded", "large", "size", "runtime", "exhaust", "amplif", "limit")),
    "security_misconfiguration": (("stack trace", "debug", "misconfiguration", "configuration", "directory listing"), ("response", "error", "enabled", "exposed", "http")),
    "secret_exposure": (("hard-coded", "hardcoded", "embedded", "bundled"), ("credential", "secret", "api key", "password", "token", "private key", "key")),
}

MIN_ARTIFACT_SCORE = {family: (1 if family == "secret_exposure" else 2) for family in ARTIFACT_MARKERS}

# These families have a conservative raw-condition reconstruction path in the
# frozen 6.14 engine. This is a materializability property, not a score result.
REPLAYABLE_CONDITION_FAMILIES = {
    "broken_object_authorization",
    "broken_function_authorization",
    "mass_assignment",
    "authentication_session",
    "account_enumeration",
    "open_redirect",
    "ssrf",
    "file_upload",
    "path_traversal",
    "information_disclosure",
    "cors_misconfiguration",
    "sql_injection",
    "nosql_injection",
    "server_side_template_injection",
    "ldap_injection",
    "security_misconfiguration",
    "secret_exposure",
    "command_injection",
    "race_condition",
    "unrestricted_resource_consumption",
}


def _semantic_match(family: str, text: str) -> bool:
    groups = SEMANTIC_GROUPS.get(family, ())
    return bool(groups) and all(any(term in text for term in group) for group in groups)


def _artifact_score(row: Mapping[str, Any]) -> int:
    family = str(row.get("family") or "")
    text = (str(row.get("description") or "") + "\n" + str(row.get("summary") or "")).lower()
    hits = {marker for marker in ARTIFACT_MARKERS.get(family, ()) if marker in text}
    score = len(hits)
    if "proof of concept" in text or re.search(r"(?im)^##+\s*(poc|proof of concept)", text):
        score += 3
    if "```" in text:
        score += 2
    if re.search(r"\b(?:http|status)\s*(?:code)?\s*[:=\-]?\s*[1-5][0-9]{2}\b", text):
        score += 2
    if "-> http " in text or "→ http " in text:
        score += 2
    return score


def build_shortlist(candidates: Mapping[str, Any], *, target_roots: int = 24) -> dict[str, Any]:
    pools = candidates.get("candidates_by_family") if isinstance(candidates.get("candidates_by_family"), Mapping) else {}
    eligible: dict[str, list[dict[str, Any]]] = {}
    rejected_semantic: dict[str, int] = {}
    for family, raw_rows in pools.items():
        rows: list[dict[str, Any]] = []
        semantic_rejects = 0
        for raw in raw_rows if isinstance(raw_rows, list) else []:
            if not isinstance(raw, Mapping):
                continue
            row = dict(raw)
            text = (str(row.get("description") or "") + "\n" + str(row.get("summary") or "")).lower()
            if not _semantic_match(str(family), text):
                semantic_rejects += 1
                continue
            row["artifact_score"] = _artifact_score(row)
            row["raw_condition_replayable"] = str(family) in REPLAYABLE_CONDITION_FAMILIES
            if row["artifact_score"] >= MIN_ARTIFACT_SCORE.get(str(family), 2):
                rows.append(row)
        rows.sort(key=lambda item: (item["artifact_score"], item.get("published_at") or "", item.get("source_root") or ""), reverse=True)
        eligible[str(family)] = rows
        rejected_semantic[str(family)] = semantic_rejects

    selected: list[dict[str, Any]] = []
    used_roots: set[str] = set()
    used_projects: set[str] = set()

    # First pass: one semantically aligned, artifact-rich, unique-project root per family.
    for family in pools:
        for row in eligible.get(str(family), []):
            root = str(row.get("source_root") or "")
            project = str(row.get("source_project") or "")
            if root in used_roots or project in used_projects:
                continue
            selected.append(row)
            used_roots.add(root)
            used_projects.add(project)
            break

    # Extra roots prefer families with a raw-condition replay path because they can
    # be materialized from target-observable artifacts rather than advisory labels.
    remainder = [row for rows in eligible.values() for row in rows if str(row.get("source_root") or "") not in used_roots]
    remainder.sort(
        key=lambda item: (
            bool(item.get("raw_condition_replayable")),
            item["artifact_score"],
            item.get("published_at") or "",
            item.get("source_root") or "",
        ),
        reverse=True,
    )
    for row in remainder:
        if len(selected) >= target_roots:
            break
        root = str(row.get("source_root") or "")
        project = str(row.get("source_project") or "")
        if root in used_roots or project in used_projects:
            continue
        selected.append(row)
        used_roots.add(root)
        used_projects.add(project)

    families = sorted({str(row.get("family") or "") for row in selected})
    projects = sorted({str(row.get("source_project") or "") for row in selected})
    replayable = sum(1 for row in selected if row.get("raw_condition_replayable"))
    return {
        "shortlist_version": SHORTLIST_VERSION,
        "target_root_count": target_roots,
        "selected_root_count": len(selected),
        "selected_family_count": len(families),
        "selected_project_count": len(projects),
        "selected_replayable_condition_root_count": replayable,
        "selected_families": families,
        "eligible_family_counts": {family: len(rows) for family, rows in eligible.items()},
        "semantic_rejection_counts": rejected_semantic,
        "selected": selected,
        "selection_note": "Shortlist uses only primary-advisory family semantics, raw-artifact richness, source recency, and project diversity. Extra roots prefer families with conservative raw-condition replay structures in the pre-frozen engine. It never executes Analysis Engine scoring.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Analysis 6.15 v3 source shortlist without scoring")
    parser.add_argument("--candidates", default=str(DEFAULT_CANDIDATES))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--target-roots", type=int, default=24)
    args = parser.parse_args()
    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
    if DEFAULT_EXTERNAL.exists():
        external = json.loads(DEFAULT_EXTERNAL.read_text(encoding="utf-8"))
        pools = candidates.setdefault("candidates_by_family", {})
        for family, rows in (external.get("candidates_by_family") or {}).items():
            pools.setdefault(family, []).extend(rows if isinstance(rows, list) else [])
    report = build_shortlist(candidates, target_roots=args.target_roots)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("selected_root_count", "selected_family_count", "selected_project_count", "selected_replayable_condition_root_count", "selected_families", "eligible_family_counts")}, indent=2, sort_keys=True))
    if report["selected_root_count"] < args.target_roots or report["selected_family_count"] < 18 or report["selected_project_count"] < 20:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
