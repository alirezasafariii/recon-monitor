from __future__ import annotations

import argparse
import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v4_source_discovery import _canonical_url, _grounding_writeup_urls, _prior_exposure_index, _project_from_url

SUPPLEMENT_VERSION = "1.0.0"
SUPPLEMENT_RULE_VERSION = "2026.08.12.6.26"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_primary_supplement.json"

# These sources are used only where a broad CWE bucket cannot distinguish the
# specialized protocol family. Selection is pre-scoring and based on explicit
# primary-advisory behavior, not any Analysis Engine output.
SUPPLEMENT_SPECS: dict[str, dict[str, Any]] = {
    "graphql_authorization": {
        "ghsa_id": "GHSA-gj2p-p9m4-c8gw",
        "expected_project": "craftcms/cms",
        "expected_cwes": {"CWE-862"},
        "required_text_groups": (
            ("graphql",),
            ("authorization", "scope filtering", "unauthorized"),
            ("resolver", "token", "ownerid", "user group"),
        ),
        "preferred_primary_url": "https://github.com/craftcms/cms/security/advisories/GHSA-gj2p-p9m4-c8gw",
    },
    "websocket_authorization": {
        "ghsa_id": "GHSA-7fch-4f2f-jcgm",
        "expected_project": "spring-projects/spring-framework",
        "expected_cwes": {"CWE-352"},
        "required_text_groups": (
            ("websocket",),
            ("unauthorized messages", "security bypass"),
            ("stomp",),
        ),
        "preferred_primary_url": "https://spring.io/security/cve/2025-41254",
    },
}


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "recon-monitor-analysis-6.26-v4-primary-supplement",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_advisory(ghsa_id: str) -> dict[str, Any]:
    request = urllib.request.Request(f"https://api.github.com/advisories/{ghsa_id}", headers=_headers())
    with urllib.request.urlopen(request, timeout=45) as response:
        payload = json.load(response)
    if not isinstance(payload, Mapping):
        raise RuntimeError(f"unexpected advisory payload for {ghsa_id}")
    return dict(payload)


def _project(row: Mapping[str, Any]) -> str:
    source = str(row.get("source_code_location") or "").strip()
    project = _project_from_url(source)
    if project:
        return project
    repo_advisory = str(row.get("repository_advisory_url") or "").strip()
    return _project_from_url(repo_advisory)


def _validate_freshness(*, family: str, row: Mapping[str, Any], spec: Mapping[str, Any]) -> dict[str, Any]:
    excluded = _prior_exposure_index()
    grounding = _grounding_writeup_urls()
    root = str(row.get("ghsa_id") or "").strip()
    project = _project(row)
    primary_url = str(spec.get("preferred_primary_url") or row.get("repository_advisory_url") or row.get("source_code_location") or "").strip()
    canonical_primary = _canonical_url(primary_url)
    references = [str(value).strip() for value in row.get("references") or [] if str(value).strip()]
    reference_urls = {_canonical_url(value) for value in references if _canonical_url(value)}
    row_cwes = {
        str(item.get("cwe_id") or "").strip()
        for item in row.get("cwes") or []
        if isinstance(item, Mapping)
    }
    expected_cwes = {str(value) for value in spec.get("expected_cwes") or set()}
    text = (str(row.get("summary") or "") + "\n" + str(row.get("description") or "")).lower()

    errors: list[str] = []
    if root != str(spec.get("ghsa_id") or ""):
        errors.append(f"root mismatch {root!r}")
    if project != str(spec.get("expected_project") or ""):
        errors.append(f"project mismatch {project!r}")
    if expected_cwes and not (row_cwes & expected_cwes):
        errors.append(f"CWE mismatch observed={sorted(row_cwes)} expected_any={sorted(expected_cwes)}")
    for group in spec.get("required_text_groups") or ():
        if not any(str(term).lower() in text for term in group):
            errors.append(f"semantic group missing {tuple(group)!r}")
    if root in excluded["roots"]:
        errors.append("source root already exposed in prior corpus/discovery")
    if project in excluded["projects"]:
        errors.append("source project already exposed in prior corpus/discovery")
    if canonical_primary in excluded["urls"]:
        errors.append("primary URL already exposed in prior corpus/discovery")
    if canonical_primary in grounding or reference_urls & grounding:
        errors.append("source overlaps current detector-grounding write-up knowledge")
    if row.get("withdrawn_at"):
        errors.append("advisory is withdrawn")
    if errors:
        raise RuntimeError(f"Analysis 6.26 primary supplement rejected {family}: " + "; ".join(errors))

    return {
        "source_root": root,
        "source_project": project,
        "family": family,
        "matched_cwes": sorted(row_cwes & expected_cwes),
        "published_at": str(row.get("published_at") or ""),
        "updated_at": str(row.get("updated_at") or ""),
        "severity": str(row.get("severity") or ""),
        "summary": str(row.get("summary") or ""),
        "description": str(row.get("description") or ""),
        "repository_advisory_url": str(row.get("repository_advisory_url") or ""),
        "source_code_location": str(row.get("source_code_location") or ""),
        "canonical_advisory_url": primary_url,
        "references": references,
        "selection_basis": "reviewed_primary_advisory_specialized_semantic_supplement_pre_scoring",
        "freshness_validated": True,
        "freshness_excluded_prior_roots": len(excluded["roots"]),
        "freshness_excluded_prior_projects": len(excluded["projects"]),
        "freshness_excluded_prior_urls": len(excluded["urls"]),
        "freshness_excluded_grounding_urls": len(grounding),
    }


def build() -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    for family, spec in sorted(SUPPLEMENT_SPECS.items()):
        row = _fetch_advisory(str(spec["ghsa_id"]))
        selected.append(_validate_freshness(family=family, row=row, spec=spec))
    if len({row["source_root"] for row in selected}) != len(selected):
        raise RuntimeError("supplement roots must be unique")
    if len({row["source_project"] for row in selected}) != len(selected):
        raise RuntimeError("supplement projects must be unique")
    return {
        "supplement_version": SUPPLEMENT_VERSION,
        "supplement_rule_version": SUPPLEMENT_RULE_VERSION,
        "selection_executes_analysis_engine": False,
        "selection_uses_detector_scores": False,
        "selection_uses_admission_results": False,
        "selection_uses_benchmark_results": False,
        "selected": selected,
        "note": (
            "Specialized GraphQL/WebSocket sources are accepted only after exact primary-advisory semantic checks and the same prior-root, "
            "prior-project, prior-URL and detector-grounding exclusions as the general v4 discovery pool."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Analysis 6.26 specialized primary source supplement")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    report = build()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "selected": [
            {"family": row["family"], "root": row["source_root"], "project": row["source_project"], "url": row["canonical_advisory_url"]}
            for row in report["selected"]
        ]
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
