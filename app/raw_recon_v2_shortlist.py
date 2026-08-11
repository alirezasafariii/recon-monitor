from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping

from raw_recon_v2_corpus import ROOT

SHORTLIST_VERSION = "1.0.0"
DEFAULT_CANDIDATES = ROOT / "benchmarks" / "raw" / "sources" / "v2_candidates.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v2_shortlist.json"

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

# Families where advisory prose must expose stronger artifacts than a generic
# vulnerability description to be safely transformed into a raw replay.
MIN_ARTIFACT_SCORE = {
    "broken_object_authorization": 2,
    "broken_function_authorization": 2,
    "mass_assignment": 2,
    "authentication_session": 2,
    "account_enumeration": 2,
    "open_redirect": 2,
    "ssrf": 2,
    "file_upload": 2,
    "path_traversal": 2,
    "information_disclosure": 2,
    "cors_misconfiguration": 2,
    "race_condition": 2,
    "sql_injection": 2,
    "nosql_injection": 2,
    "command_injection": 2,
    "server_side_template_injection": 2,
    "ldap_injection": 2,
    "unrestricted_resource_consumption": 2,
    "security_misconfiguration": 2,
    "secret_exposure": 3,
}


def _artifact_score(row: Mapping[str, Any]) -> int:
    family = str(row.get("family") or "")
    text = (str(row.get("description") or "") + "\n" + str(row.get("summary") or "")).lower()
    markers = ARTIFACT_MARKERS.get(family, ())
    hits = {marker for marker in markers if marker in text}
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
    for family, raw_rows in pools.items():
        rows: list[dict[str, Any]] = []
        for raw in raw_rows if isinstance(raw_rows, list) else []:
            if not isinstance(raw, Mapping):
                continue
            row = dict(raw)
            row["artifact_score"] = _artifact_score(row)
            if row["artifact_score"] >= MIN_ARTIFACT_SCORE.get(str(family), 2):
                rows.append(row)
        rows.sort(key=lambda item: (item["artifact_score"], item.get("published_at") or "", item.get("source_root") or ""), reverse=True)
        eligible[str(family)] = rows

    selected: list[dict[str, Any]] = []
    used_roots: set[str] = set()
    used_projects: set[str] = set()

    # First pass: maximize family coverage with unique projects.
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

    # Second pass: fill to target with the strongest remaining unique-project roots.
    remainder = [row for rows in eligible.values() for row in rows if str(row.get("source_root") or "") not in used_roots]
    remainder.sort(key=lambda item: (item["artifact_score"], item.get("published_at") or "", item.get("source_root") or ""), reverse=True)
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
    return {
        "shortlist_version": SHORTLIST_VERSION,
        "target_root_count": target_roots,
        "selected_root_count": len(selected),
        "selected_family_count": len(families),
        "selected_project_count": len(projects),
        "selected_families": families,
        "eligible_family_counts": {family: len(rows) for family, rows in eligible.items()},
        "selected": selected,
        "selection_note": "Shortlist uses only primary-advisory artifact richness, family coverage, recency, and project diversity. It does not execute or inspect Analysis Engine scoring.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Analysis 6.13 v2 source shortlist without scoring")
    parser.add_argument("--candidates", default=str(DEFAULT_CANDIDATES))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--target-roots", type=int, default=24)
    args = parser.parse_args()
    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
    report = build_shortlist(candidates, target_roots=args.target_roots)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("selected_root_count", "selected_family_count", "selected_project_count", "selected_families", "eligible_family_counts")}, indent=2, sort_keys=True))
    if report["selected_root_count"] < args.target_roots or report["selected_family_count"] < 18 or report["selected_project_count"] < 20:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
