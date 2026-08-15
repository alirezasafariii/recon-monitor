from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v8_source_firewall import check_candidate, exposure_index
from researcher_logic import researcher_logic_for_family

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v8.targeted3.1"
SOURCES = ROOT / "benchmarks/raw/sources"
CANDIDATES = SOURCES / "v8_candidates.json"
PATCHABLE = SOURCES / "v8_candidates_patchable.json"
BLOCKER = SOURCES / "v8_preblind_blocker.json"

EXPECTED_GAPS = {
    "graphql_authorization",
    "sensitive_business_flow_abuse",
    "software_supply_chain_failure",
}

# Source identifiers are selected from the preregistered family semantics and
# canonical condition anchors before any v8 scoring. Target text remains the
# verbatim upstream PR title/body and later the verbatim upstream patch.
SPECS: tuple[dict[str, Any], ...] = (
    {
        "family": "graphql_authorization",
        "project": "AseemPrasad/Legalassist-AI",
        "number": 1227,
    },
    {
        "family": "sensitive_business_flow_abuse",
        "project": "winnersfrown/Rekono",
        "number": 50,
    },
    {
        "family": "software_supply_chain_failure",
        "project": "BlakeMatthews-dev/maistro-engine",
        "number": 252,
    },
)


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-633-v8-targeted3",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get_json(url: str) -> Mapping[str, Any]:
    request = urllib.request.Request(url, headers=_headers())
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            value = json.load(response)
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")[:1500]
        raise RuntimeError(f"upstream metadata fetch failed {exc.code} {url}: {payload}") from exc
    if not isinstance(value, Mapping):
        raise RuntimeError(f"upstream metadata payload is not an object: {url}")
    return value


def _iso(value: Any) -> str:
    text = str(value or "").strip()
    if text:
        return text
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _grounding(family: str) -> dict[str, Any]:
    logic = researcher_logic_for_family(family)
    return {
        "role": logic.get("role"),
        "security_principle": logic.get("security_principle"),
        "testing_concepts": (logic.get("standards_logic") or {}).get("testing_concepts", []),
        "risk_concepts": (logic.get("standards_logic") or {}).get("risk_concepts", []),
        "weakness_concepts": (logic.get("standards_logic") or {}).get("weakness_concepts", []),
        "writeup_logic": logic.get("writeup_logic"),
        "grounding_role": "source_selection_reasoning_only_not_target_evidence",
        "counts_as_target_evidence": False,
    }


def _base_row(family: str, project: str) -> dict[str, Any]:
    return {
        "family": family,
        "source_project": project,
        "matched_cwes": [],
        "severity": "",
        "freshness_validated": True,
        "selection_basis": "preregistered final-gap upstream source selected from family semantic/condition contracts before any v8 scoring",
        "source_selection_reasoning_grounding": _grounding(family),
        "grounding_counts_as_target_evidence": False,
        "selection_uses_v6_score": False,
        "selection_uses_v6_case_errors": False,
        "selection_uses_v7_score": False,
        "selection_uses_v7_case_errors": False,
        "selection_uses_v7_execution_error": False,
        "candidate_selection_uses_v7_first_blind_score": False,
        "candidate_selection_uses_v7_first_blind_case_errors": False,
        "candidate_selection_uses_v7_first_blind_error": False,
        "active_target_validation_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def _pr_row(spec: Mapping[str, Any]) -> dict[str, Any]:
    family = str(spec["family"])
    project = str(spec["project"])
    number = int(spec["number"])
    value = _get_json(f"https://api.github.com/repos/{project}/pulls/{number}")
    if value.get("merged_at") in (None, ""):
        raise RuntimeError(f"targeted v8 PR is not merged: {project}#{number}")
    html_url = str(value.get("html_url") or f"https://github.com/{project}/pull/{number}")
    row = _base_row(family, project)
    row.update({
        "source_root": f"GITHUB-PR-{project.replace('/', '-')}-{number}",
        "summary": str(value.get("title") or ""),
        "description": str(value.get("body") or ""),
        "published_at": _iso(value.get("created_at")),
        "updated_at": _iso(value.get("updated_at")),
        "repository_advisory_url": "",
        "source_code_location": html_url,
        "canonical_advisory_url": "",
        "references": [html_url],
        "upstream_repository_reference": html_url,
        "source_kind": "github_merged_security_pr_targeted3",
        "advisory_source_type": "targeted_merged_pr",
        "targeted_spec_kind": "pr",
        "targeted_spec_number": number,
        "upstream_merge_commit_sha": str(value.get("merge_commit_sha") or ""),
    })
    return row


def _validate_resume_state() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    candidates = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    patchable = json.loads(PATCHABLE.read_text(encoding="utf-8"))
    blocker = json.loads(BLOCKER.read_text(encoding="utf-8"))
    for name, artifact in (("candidates", candidates), ("patchable", patchable)):
        if artifact.get("scoring_executed") is not False:
            raise RuntimeError(f"targeted3 requires unscored {name}")
        for key in (
            "candidate_selection_uses_v7_first_blind_score",
            "candidate_selection_uses_v7_first_blind_case_errors",
            "candidate_selection_uses_v7_first_blind_error",
        ):
            if artifact.get(key) is not False:
                raise RuntimeError(f"targeted3 refuses contaminated {name}: {key}")
    missing = set(str(x) for x in patchable.get("families_without_candidates") or [])
    if missing != EXPECTED_GAPS:
        raise RuntimeError(f"targeted3 expected exact three gaps, got: {sorted(missing)}")
    blocker_missing = set(str(x) for x in blocker.get("families_without_candidates") or [])
    if blocker_missing != EXPECTED_GAPS:
        raise RuntimeError(f"targeted3 blocker mismatch: {sorted(blocker_missing)}")
    if blocker.get("scoring_executed") is not False or blocker.get("first_blind_consumed") is not False:
        raise RuntimeError("targeted3 blocker is not clean preblind state")
    if (SOURCES / "v8_first_blind_consumption.json").exists():
        raise RuntimeError("v8 First Blind receipt already exists")
    if (ROOT / "benchmarks/raw/results/analysis_raw_v8_first_blind.json").exists():
        raise RuntimeError("v8 First Blind result already exists")
    if (SOURCES / "v8_pre_score_checkpoint.json").exists():
        raise RuntimeError("targeted3 refuses an already sealed/checkpointed v8 state")
    return candidates, patchable, blocker


def supplement() -> dict[str, Any]:
    candidates, _, _ = _validate_resume_state()
    pools_raw = candidates.get("candidates_by_family")
    if not isinstance(pools_raw, Mapping) or len(pools_raw) != 36:
        raise RuntimeError("targeted3 requires 36 candidate family buckets")
    pools: dict[str, list[dict[str, Any]]] = {
        str(family): [dict(row) for row in rows or [] if isinstance(row, Mapping)]
        for family, rows in pools_raw.items()
    }
    prior = exposure_index()
    diagnostics: list[dict[str, Any]] = []
    added = 0
    for spec in SPECS:
        family = str(spec["family"])
        row = _pr_row(spec)
        existing_roots = {str(item.get("source_root") or "") for item in pools[family]}
        check = check_candidate(row, index=prior)
        entry = {
            "family": family,
            "source_root": row["source_root"],
            "source_project": row["source_project"],
            "source_code_location": row["source_code_location"],
            "firewall_allowed": bool(check["allowed"]),
            "root_overlap": check.get("root_overlap", []),
            "project_overlap": check.get("project_overlap", []),
            "url_overlap": check.get("url_overlap", []),
            "identifier_overlap": check.get("identifier_overlap", []),
            "already_present": row["source_root"] in existing_roots,
        }
        diagnostics.append(entry)
        if not check["allowed"] or row["source_root"] in existing_roots:
            continue
        pools[family].append(row)
        added += 1

    report = dict(candidates)
    report.update({
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v8_targeted3_source_supplement_unscored",
        "candidates_by_family": pools,
        "family_candidate_counts": {family: len(rows) for family, rows in pools.items()},
        "targeted3_expected_gaps": sorted(EXPECTED_GAPS),
        "targeted3_spec_count": len(SPECS),
        "targeted3_added_count": added,
        "targeted3_diagnostics": diagnostics,
        "targeted3_source_text_policy": "title/body fetched verbatim from upstream GitHub metadata; patch fetched by the existing patch probe; no synthetic vulnerability description injected",
        "source_selection_grounding": "WSTG/CWE/OWASP/write-up concepts guide source selection only and never count as target evidence",
        "grounding_counts_as_target_evidence": False,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_ranking_results": False,
        "candidate_selection_uses_v6_first_blind_score": False,
        "candidate_selection_uses_v6_first_blind_case_errors": False,
        "candidate_selection_uses_v7_first_blind_score": False,
        "candidate_selection_uses_v7_first_blind_case_errors": False,
        "candidate_selection_uses_v7_first_blind_error": False,
        "active_target_validation_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    })
    CANDIDATES.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    report = supplement()
    print(json.dumps({
        "targeted3_spec_count": report["targeted3_spec_count"],
        "targeted3_added_count": report["targeted3_added_count"],
        "targeted3_diagnostics": report["targeted3_diagnostics"],
        "scoring_executed": report["scoring_executed"],
        "first_blind_consumed": report["first_blind_consumed"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
