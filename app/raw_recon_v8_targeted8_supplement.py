from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v8_source_firewall import check_candidate, exposure_index
from researcher_logic import researcher_logic_for_family

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v8.targeted8.1"
SOURCES = ROOT / "benchmarks/raw/sources"
CANDIDATES = SOURCES / "v8_candidates.json"
PATCHABLE = SOURCES / "v8_candidates_patchable.json"
BLOCKER = SOURCES / "v8_preblind_blocker.json"

EXPECTED_GAPS = {
    "exceptional_condition_mishandling",
    "graphql_authorization",
    "graphql_data_exposure",
    "improper_inventory_management",
    "security_misconfiguration",
    "sensitive_business_flow_abuse",
    "sensitive_caching",
    "software_supply_chain_failure",
}

# Selection is preregistered from the family semantic/condition contracts and
# standards-grounded researcher logic. These are source identifiers only.
# Title/body/message and patch evidence are fetched verbatim from upstream.
SPECS: tuple[dict[str, Any], ...] = (
    {
        "family": "exceptional_condition_mishandling",
        "kind": "pr",
        "project": "openai/openai-node",
        "number": 2350,
    },
    {
        "family": "graphql_authorization",
        "kind": "pr",
        "project": "connorshea/vglist",
        "number": 4642,
    },
    {
        "family": "graphql_data_exposure",
        "kind": "commit",
        "project": "nautobot/nautobot",
        "sha": "a05eb7d0c939dd4205aca839955e4b3ee5f32af4",
    },
    {
        "family": "improper_inventory_management",
        "kind": "commit",
        "project": "CodeByelo/Monorepo-Koda",
        "sha": "a9a30e92630944c58ec74f6448983f312891e79a",
    },
    {
        "family": "security_misconfiguration",
        "kind": "commit",
        "project": "keyorixhq/keyorix",
        "sha": "770bdca54fac8cfdef492864b904d9b731e20cd6",
    },
    {
        "family": "sensitive_business_flow_abuse",
        "kind": "commit",
        "project": "gleissondouglas/rotabus-api",
        "sha": "d4059f58c1343e6b588dabb7ae83216ca6567c2e",
    },
    {
        "family": "sensitive_caching",
        "kind": "pr",
        "project": "The-Verscienta/kiln_cms",
        "number": 1005,
    },
    {
        "family": "software_supply_chain_failure",
        "kind": "commit",
        "project": "mastra-ai/mastra",
        "sha": "ec4da8a09e0d2ab452c6ee2c786042ea826b77e5",
    },
)


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-633-v8-targeted8",
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
    if not text:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return text


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
        "source_kind": "github_merged_security_pr_targeted8",
        "advisory_source_type": "targeted_merged_pr",
        "targeted_spec_kind": "pr",
        "targeted_spec_number": number,
        "upstream_merge_commit_sha": str(value.get("merge_commit_sha") or ""),
    })
    return row


def _commit_row(spec: Mapping[str, Any]) -> dict[str, Any]:
    family = str(spec["family"])
    project = str(spec["project"])
    sha = str(spec["sha"])
    value = _get_json(f"https://api.github.com/repos/{project}/commits/{sha}")
    actual_sha = str(value.get("sha") or "")
    if not actual_sha or not actual_sha.startswith(sha[:12]):
        raise RuntimeError(f"targeted v8 commit identity mismatch: {project}@{sha}")
    commit = value.get("commit") if isinstance(value.get("commit"), Mapping) else {}
    message = str(commit.get("message") or "")
    title, _, body = message.partition("\n")
    committer = commit.get("committer") if isinstance(commit.get("committer"), Mapping) else {}
    html_url = str(value.get("html_url") or f"https://github.com/{project}/commit/{actual_sha}")
    row = _base_row(family, project)
    row.update({
        "source_root": f"GITHUB-COMMIT-{project.replace('/', '-')}-{actual_sha}",
        "summary": title.strip(),
        "description": body.strip(),
        "published_at": _iso(committer.get("date")),
        "updated_at": _iso(committer.get("date")),
        "repository_advisory_url": "",
        "source_code_location": html_url,
        "canonical_advisory_url": "",
        "references": [html_url],
        "upstream_repository_reference": html_url,
        "source_kind": "github_security_fix_commit_targeted8",
        "advisory_source_type": "targeted_security_commit",
        "targeted_spec_kind": "commit",
        "targeted_spec_sha": actual_sha,
    })
    return row


def _validate_resume_state() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    candidates = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    patchable = json.loads(PATCHABLE.read_text(encoding="utf-8"))
    blocker = json.loads(BLOCKER.read_text(encoding="utf-8"))
    for name, artifact in (("candidates", candidates), ("patchable", patchable)):
        if artifact.get("scoring_executed") is not False:
            raise RuntimeError(f"targeted8 requires unscored {name}")
        for key in (
            "candidate_selection_uses_v7_first_blind_score",
            "candidate_selection_uses_v7_first_blind_case_errors",
            "candidate_selection_uses_v7_first_blind_error",
        ):
            if artifact.get(key) is not False:
                raise RuntimeError(f"targeted8 refuses contaminated {name}: {key}")
    missing = set(str(x) for x in patchable.get("families_without_candidates") or [])
    if missing != EXPECTED_GAPS:
        raise RuntimeError(f"targeted8 expected exact eight gaps, got: {sorted(missing)}")
    blocker_missing = set(str(x) for x in blocker.get("families_without_candidates") or [])
    if blocker_missing != EXPECTED_GAPS:
        raise RuntimeError(f"targeted8 blocker mismatch: {sorted(blocker_missing)}")
    if blocker.get("scoring_executed") is not False or blocker.get("first_blind_consumed") is not False:
        raise RuntimeError("targeted8 blocker is not clean preblind state")
    if (SOURCES / "v8_first_blind_consumption.json").exists():
        raise RuntimeError("v8 First Blind receipt already exists")
    if (ROOT / "benchmarks/raw/results/analysis_raw_v8_first_blind.json").exists():
        raise RuntimeError("v8 First Blind result already exists")
    return candidates, patchable, blocker


def supplement() -> dict[str, Any]:
    candidates, _, _ = _validate_resume_state()
    pools_raw = candidates.get("candidates_by_family")
    if not isinstance(pools_raw, Mapping) or len(pools_raw) != 36:
        raise RuntimeError("targeted8 requires 36 candidate family buckets")
    pools: dict[str, list[dict[str, Any]]] = {
        str(family): [dict(row) for row in rows or [] if isinstance(row, Mapping)]
        for family, rows in pools_raw.items()
    }
    prior = exposure_index()
    diagnostics: list[dict[str, Any]] = []
    added = 0
    for spec in SPECS:
        family = str(spec["family"])
        row = _pr_row(spec) if spec["kind"] == "pr" else _commit_row(spec)
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
        "evaluation_kind": "fresh_blind_v8_targeted8_source_supplement_unscored",
        "candidates_by_family": pools,
        "family_candidate_counts": {family: len(rows) for family, rows in pools.items()},
        "targeted8_expected_gaps": sorted(EXPECTED_GAPS),
        "targeted8_spec_count": len(SPECS),
        "targeted8_added_count": added,
        "targeted8_diagnostics": diagnostics,
        "targeted8_source_text_policy": "summary/body/message fetched verbatim from upstream GitHub metadata; no synthetic vulnerability description injected; existing patch probe remains final verifier",
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
    OUT = CANDIDATES
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    report = supplement()
    print(json.dumps({
        "targeted8_spec_count": report["targeted8_spec_count"],
        "targeted8_added_count": report["targeted8_added_count"],
        "targeted8_diagnostics": report["targeted8_diagnostics"],
        "scoring_executed": report["scoring_executed"],
        "first_blind_consumed": report["first_blind_consumed"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
