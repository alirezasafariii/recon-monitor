from __future__ import annotations

"""Passive source feasibility assessment for Real-World Corpus V1.

This stage enriches the 100-source pre-adjudication shortlist with public GitHub
advisory metadata. It does not contact vulnerability targets, run vulnerable
applications, execute payloads, score Analysis, or create human labels.

A CWE match is recorded as source-taxonomy evidence only. It never silently
becomes a final family label. Capture feasibility means only that a source has
sufficient public version/revision metadata to *plan* a controlled replay.
"""

import argparse
import json
import os
import re
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

FEASIBILITY_VERSION = "1.0.0"
FEASIBILITY_RULE_VERSION = "2026.08.14.5"
MIN_EXACT_TARGET_FAMILIES = 50
REQUIRED_SOURCE_COUNT = 100

_GHSA_RE = re.compile(r"^GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}$")
_COMMIT_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})(?:$|[?#])")
_COMPARE_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/compare/([^?#]+)")
_PULL_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/pull/(\d+)(?:$|[/?#])")
_RELEASE_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/releases/tag/([^?#]+)")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _api_get_json(url: str, token: str = "") -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-real-world-corpus-v1-feasibility",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _cwe_ids(advisory: Mapping[str, Any]) -> list[str]:
    values: set[str] = set()
    for item in advisory.get("cwes", []) or []:
        value = item.get("cwe_id") if isinstance(item, Mapping) else item
        token = _text(value).upper()
        if token:
            values.add(token)
    return sorted(values)


def _version_boundaries(advisory: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in advisory.get("vulnerabilities", []) or []:
        if not isinstance(item, Mapping):
            continue
        package = item.get("package") if isinstance(item.get("package"), Mapping) else {}
        patched = item.get("first_patched_version")
        if isinstance(patched, Mapping):
            patched = patched.get("identifier") or patched.get("version")
        rows.append({
            "ecosystem": _text(package.get("ecosystem")),
            "package": _text(package.get("name")),
            "vulnerable_version_range": _text(item.get("vulnerable_version_range")),
            "first_patched_version": _text(patched),
        })
    return rows


def _reference_inventory(advisory: Mapping[str, Any], project: str) -> dict[str, list[str]]:
    result: dict[str, set[str]] = {
        "commits": set(),
        "compares": set(),
        "pulls": set(),
        "releases": set(),
        "repository_advisories": set(),
    }
    project_lower = project.lower()
    for raw in advisory.get("references", []) or []:
        url = _text(raw)
        if not url.startswith("https://"):
            continue
        for key, regex in (
            ("commits", _COMMIT_RE),
            ("compares", _COMPARE_RE),
            ("pulls", _PULL_RE),
            ("releases", _RELEASE_RE),
        ):
            match = regex.match(url)
            if match and f"{match.group(1)}/{match.group(2)}".lower() == project_lower:
                result[key].add(url)
        if f"https://github.com/{project_lower}/security/advisories/" in url.lower():
            result["repository_advisories"].add(url)
    repository_advisory = _text(advisory.get("repository_advisory_url"))
    if repository_advisory:
        result["repository_advisories"].add(repository_advisory)
    return {key: sorted(values) for key, values in result.items()}


def assess_source(row: Mapping[str, Any], advisory: Mapping[str, Any]) -> dict[str, Any]:
    source = dict(row)
    root = _text(source.get("source_root")).upper()
    project = _text(source.get("source_project")).lower()
    target_family = _text(source.get("family_target"))
    target_cwe = _text(source.get("target_cwe")).upper()
    advisory_cwes = _cwe_ids(advisory)
    boundaries = _version_boundaries(advisory)
    references = _reference_inventory(advisory, project)

    exact_target_cwe = bool(target_family and target_cwe and target_cwe in advisory_cwes)
    has_vulnerable_range = any(bool(item["vulnerable_version_range"]) for item in boundaries)
    has_patched_version = any(bool(item["first_patched_version"]) for item in boundaries)
    has_code_reference = any(references[key] for key in ("commits", "compares", "pulls", "releases"))
    has_repo_advisory = bool(references["repository_advisories"])

    if has_vulnerable_range and has_patched_version and has_code_reference:
        feasibility = "strong_revision_boundary"
    elif has_vulnerable_range and has_patched_version:
        feasibility = "version_boundary_available"
    elif has_code_reference or has_repo_advisory:
        feasibility = "source_reference_available"
    else:
        feasibility = "manual_source_research_required"

    source.update({
        "advisory_fetch_status": "retrieved",
        "advisory_cwes": advisory_cwes,
        "source_taxonomy_match": {
            "family_target": target_family or None,
            "target_cwe": target_cwe or None,
            "target_cwe_present": exact_target_cwe,
            "status": (
                "exact_target_cwe_match"
                if exact_target_cwe
                else "not_applicable_general_source"
                if not target_family
                else "target_cwe_mismatch_requires_review"
            ),
            "final_family_assigned": False,
        },
        "version_boundaries": boundaries,
        "reference_inventory": references,
        "capture_feasibility": feasibility,
        "capture_plan_status": "pending_design",
        "variant_feasibility": {
            "positive": "candidate" if (has_vulnerable_range or has_code_reference) else "manual_research_required",
            "secure_negative": "candidate" if (has_patched_version or has_code_reference) else "manual_research_required",
            "near_miss": "manual_control_design_required",
            "sparse_noisy": "candidate_from_minimal_source_metadata",
        },
        "family_label_adjudicated": False,
        "final_family": None,
        "human_verified": False,
        "scoring_executed": False,
        "target_contact_performed": False,
    })
    return source


def assess_shortlist(rows: Iterable[Mapping[str, Any]], *, token: str = "") -> dict[str, Any]:
    sources = [dict(row) for row in rows]
    assessed: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    feasibility_counts: Counter[str] = Counter()
    exact_target_families: set[str] = set()

    for row in sources:
        root = _text(row.get("source_root")).upper()
        if not _GHSA_RE.match(root):
            failures.append({"source_root": root, "error": "invalid_ghsa_source_root"})
            continue
        try:
            advisory = _api_get_json(f"https://api.github.com/advisories/{root}", token=token)
            if not isinstance(advisory, Mapping):
                raise ValueError("unexpected_advisory_payload")
            item = assess_source(row, advisory)
            assessed.append(item)
            feasibility_counts[item["capture_feasibility"]] += 1
            taxonomy = item["source_taxonomy_match"]
            if taxonomy["status"] == "exact_target_cwe_match" and taxonomy["family_target"]:
                exact_target_families.add(str(taxonomy["family_target"]))
        except Exception as exc:
            failures.append({"source_root": root, "error": type(exc).__name__})

    gates = {
        "all_100_advisories_retrieved": len(assessed) == REQUIRED_SOURCE_COUNT and not failures,
        "minimum_50_exact_target_families": len(exact_target_families) >= MIN_EXACT_TARGET_FAMILIES,
        "no_final_family_assigned": all(row.get("final_family") in (None, "") for row in assessed),
        "no_human_labels_created": all(not bool(row.get("human_verified")) for row in assessed),
        "no_scoring_executed": all(not bool(row.get("scoring_executed")) for row in assessed),
        "no_target_contact_performed": all(not bool(row.get("target_contact_performed")) for row in assessed),
    }
    return {
        "version": FEASIBILITY_VERSION,
        "rule_version": FEASIBILITY_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_passive_source_feasibility",
        "status": "source_feasibility_complete" if all(gates.values()) else "source_feasibility_incomplete",
        "source_count": len(sources),
        "assessed_source_count": len(assessed),
        "failure_count": len(failures),
        "failures": failures,
        "exact_target_family_count": len(exact_target_families),
        "exact_target_families": sorted(exact_target_families),
        "capture_feasibility_counts": dict(sorted(feasibility_counts.items())),
        "gates": gates,
        "passed": all(gates.values()),
        "scoring_executed": False,
        "target_contact_performed": False,
        "human_labels_created": False,
        "family_assignment_is_final": False,
        "sources": assessed,
        "next_transition": "controlled_capture_plan_design",
    }


def _load_sources(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("sources")
    if not isinstance(rows, list):
        raise ValueError("shortlist_sources_missing")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assess Real-World Corpus V1 source feasibility")
    parser.add_argument("--shortlist", default="benchmarks/real_world/v1/source_shortlist.json")
    parser.add_argument("--output", default="benchmarks/real_world/v1/source_feasibility.json")
    parser.add_argument("--report", default="benchmarks/real_world/v1/source_feasibility_report.json")
    parser.add_argument("--github-token", default="")
    args = parser.parse_args(argv)

    result = assess_shortlist(
        _load_sources(Path(args.shortlist)),
        token=args.github_token or os.environ.get("GITHUB_TOKEN", ""),
    )
    _write(Path(args.output), result)
    report = {key: value for key, value in result.items() if key != "sources"}
    _write(Path(args.report), report)
    print(json.dumps({
        "ok": result["passed"],
        "assessed": result["assessed_source_count"],
        "failures": result["failure_count"],
        "exact_target_families": result["exact_target_family_count"],
        "capture_feasibility": result["capture_feasibility_counts"],
    }, sort_keys=True))
    if not result["passed"]:
        raise SystemExit("source_feasibility_gate_failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
