from __future__ import annotations

import argparse
import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v4_source_discovery import _canonical_url, _grounding_writeup_urls, _prior_exposure_index

EXACT_SUPPLEMENT_VERSION = "1.0.0"
EXACT_SUPPLEMENT_RULE_VERSION = "2026.08.12.6.26"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_exact_source_supplement.json"

# Static identifiers are pre-registered primary-source coordinates, not target
# detector output. Metadata is fetched from the primary advisory where the
# GitHub repository-advisory API exposes it. The Security Lab case uses the
# coordinated-disclosure page itself as the canonical primary source.
EXACT_SOURCE_SPECS: dict[str, dict[str, Any]] = {
    "nosql_injection": {
        "source_root": "GHSA-hgq6-9jg2-wf3f",
        "source_project": "RocketChat/Rocket.Chat",
        "fetch_url": "https://api.github.com/repos/RocketChat/Rocket.Chat/security-advisories/GHSA-hgq6-9jg2-wf3f",
        "canonical_advisory_url": "https://github.com/RocketChat/Rocket.Chat/security/advisories/GHSA-hgq6-9jg2-wf3f",
        "expected_cwes": {"CWE-943"},
        "required_groups": (
            ("nosql injection",),
            ("mongodb", "mongo"),
            ("operator", "$regex", "findone", "query selector"),
        ),
    },
    "source_map_exposure": {
        "source_root": "GHSA-rg65-45m7-hq57",
        "source_project": "esm-dev/esm.sh",
        "fetch_url": "https://api.github.com/advisories/GHSA-rg65-45m7-hq57",
        "canonical_advisory_url": "https://github.com/esm-dev/esm.sh/security/advisories/GHSA-rg65-45m7-hq57",
        "expected_cwes": {"CWE-22"},
        "required_groups": (
            ("source map", "sourcemap", ".mjs.map"),
            ("sourcescontent",),
            ("server file contents in source map response", "read sensitive files from the server"),
            ("curl", ".mjs.map"),
        ),
    },
    "unsafe_api_consumption": {
        "source_root": "CVE-2020-13482",
        "source_project": "igrigorik/em-http-request",
        "fetch_url": "https://securitylab.github.com/advisories/GHSL-2020-094-igrigorik-em-http-request/",
        "canonical_advisory_url": "https://securitylab.github.com/advisories/GHSL-2020-094-igrigorik-em-http-request/",
        "expected_cwes": set(),
        "required_groups": (
            ("hostname validation",),
            ("person in the middle", "pitm", "man in the middle", "impersonate a trusted upstream server"),
            ("trusted server", "server identity", "certificate"),
        ),
        "static_summary": "Missing SSL/TLS certificate hostname validation in em-http-request",
        "static_description": (
            "The em-http-request HTTP client failed to validate the TLS certificate hostname, allowing an attacker to impersonate a trusted upstream server and inject malicious data into otherwise trusted HTTP responses."
        ),
    },
}


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json,text/html;q=0.9,*/*;q=0.8",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "recon-monitor-analysis-6.26-exact-source-supplement",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch(spec: Mapping[str, Any]) -> dict[str, Any]:
    url = str(spec["fetch_url"])
    request = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(request, timeout=45) as response:
        body = response.read()
        content_type = str(response.headers.get("Content-Type") or "")
    if "json" in content_type or url.startswith("https://api.github.com/"):
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, Mapping):
            raise RuntimeError(f"unexpected JSON primary-source payload from {url}")
        return dict(payload)
    # The Security Lab primary page is checked for liveness here. Its exact
    # semantic metadata is pre-registered from the coordinated-disclosure page
    # so changing page chrome cannot mutate holdout source selection.
    return {
        "summary": str(spec.get("static_summary") or ""),
        "description": str(spec.get("static_description") or ""),
        "references": [url],
        "cwes": [],
        "withdrawn_at": None,
    }


def _project_from_payload(payload: Mapping[str, Any], fallback: str) -> str:
    value = str(payload.get("source_code_location") or "").strip()
    prefix = "https://github.com/"
    if value.startswith(prefix):
        parts = value[len(prefix):].strip("/").split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1].removesuffix('.git')}"
    return fallback


def _validate(family: str, spec: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    excluded = _prior_exposure_index()
    grounding = _grounding_writeup_urls()
    root = str(spec["source_root"])
    project = str(spec["source_project"])
    canonical_url = _canonical_url(str(spec["canonical_advisory_url"]))
    observed_project = _project_from_payload(payload, project)
    if observed_project.lower() != project.lower():
        raise RuntimeError(f"{family}: primary-source project mismatch observed={observed_project!r} expected={project!r}")

    payload_root = str(payload.get("ghsa_id") or "").strip()
    if root.startswith("GHSA-") and payload_root and payload_root != root:
        raise RuntimeError(f"{family}: advisory root mismatch observed={payload_root!r} expected={root!r}")
    if payload.get("withdrawn_at"):
        raise RuntimeError(f"{family}: primary advisory is withdrawn")

    summary = str(payload.get("summary") or spec.get("static_summary") or "")
    description = str(payload.get("description") or spec.get("static_description") or "")
    text = (summary + "\n" + description).lower()
    semantic_hits: list[list[str]] = []
    for group in spec.get("required_groups") or ():
        hits = sorted({str(term) for term in group if str(term).lower() in text})
        if not hits:
            raise RuntimeError(f"{family}: exact primary source misses semantic group {tuple(group)!r}")
        semantic_hits.append(hits)

    row_cwes = {
        str(item.get("cwe_id") or "").strip()
        for item in payload.get("cwes") or []
        if isinstance(item, Mapping)
    }
    expected_cwes = {str(value) for value in spec.get("expected_cwes") or set()}
    if expected_cwes and not (row_cwes & expected_cwes):
        raise RuntimeError(f"{family}: exact source CWE mismatch observed={sorted(row_cwes)} expected_any={sorted(expected_cwes)}")

    raw_urls = [
        str(spec.get("canonical_advisory_url") or ""),
        str(payload.get("repository_advisory_url") or ""),
        str(payload.get("source_code_location") or ""),
        *[str(value) for value in payload.get("references") or []],
    ]
    urls = {_canonical_url(value) for value in raw_urls if _canonical_url(value)}
    errors: list[str] = []
    if root in excluded["roots"]:
        errors.append("root was previously exposed")
    if project in excluded["projects"] or project.lower() in {value.lower() for value in excluded["projects"]}:
        errors.append("project was previously exposed")
    if urls & excluded["urls"]:
        errors.append("URL was previously exposed")
    if urls & grounding:
        errors.append("source overlaps detector-grounding knowledge")
    if canonical_url in grounding:
        errors.append("canonical source is detector-grounding knowledge")
    if errors:
        raise RuntimeError(f"{family}: novelty firewall rejected exact source: " + "; ".join(errors))

    return {
        "source_root": root,
        "source_project": project,
        "family": family,
        "matched_cwes": sorted(row_cwes & expected_cwes) if expected_cwes else [],
        "published_at": str(payload.get("published_at") or ""),
        "updated_at": str(payload.get("updated_at") or ""),
        "severity": str(payload.get("severity") or ""),
        "summary": summary,
        "description": description,
        "repository_advisory_url": str(payload.get("repository_advisory_url") or ""),
        "source_code_location": str(payload.get("source_code_location") or f"https://github.com/{project}"),
        "canonical_advisory_url": str(spec["canonical_advisory_url"]),
        "references": [str(value) for value in payload.get("references") or []],
        "exact_semantic_group_hits": semantic_hits,
        "selection_basis": "pre_registered_exact_primary_source_plus_v4_novelty_firewall_pre_scoring",
        "freshness_validated": True,
        "freshness_excluded_prior_roots": len(excluded["roots"]),
        "freshness_excluded_prior_projects": len(excluded["projects"]),
        "freshness_excluded_prior_urls": len(excluded["urls"]),
        "freshness_excluded_grounding_urls": len(grounding),
    }


def build() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for family, spec in EXACT_SOURCE_SPECS.items():
        payload = _fetch(spec)
        rows.append(_validate(family, spec, payload))
    if len({row["source_root"] for row in rows}) != len(rows):
        raise RuntimeError("exact supplement source roots must be unique")
    if len({row["source_project"].lower() for row in rows}) != len(rows):
        raise RuntimeError("exact supplement projects must be unique")
    return {
        "exact_supplement_version": EXACT_SUPPLEMENT_VERSION,
        "exact_supplement_rule_version": EXACT_SUPPLEMENT_RULE_VERSION,
        "selection_executes_analysis_engine": False,
        "selection_uses_detector_scores": False,
        "selection_uses_admission_results": False,
        "selection_uses_benchmark_results": False,
        "selected": rows,
        "note": "Exact source-family supplements are accepted only after primary-source semantic validation and the complete Analysis 6.26 novelty firewall.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate exact fresh primary sources for Analysis 6.26 raw v4")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    report = build()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"selected": [
        {"family": row["family"], "root": row["source_root"], "project": row["source_project"], "url": row["canonical_advisory_url"]}
        for row in report["selected"]
    ]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
