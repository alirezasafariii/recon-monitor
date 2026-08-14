from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v7_source_firewall import check_candidate, exposure_index
from v7_pre_score_condition_audit import audit_conditions
from v7_source_semantic_audit import audit_row

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.32.v7.11"
OUT = ROOT / "benchmarks/raw/sources/v7_targeted_supplement.json"

TARGETS = {
    "command_injection": "https://api.github.com/repos/automateyournetwork/netdiag-vuln-sample/issues/21",
    "unsafe_api_consumption": "https://api.github.com/repos/groupthinking/EventRelay/issues/770",
}


def _request(url: str, token: str | None) -> tuple[int, Any, str | None]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-632-v7-targeted-supplement",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
            return int(response.status), json.loads(response.read(2 * 1024 * 1024).decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        return int(exc.code), None, f"HTTP {exc.code}: " + exc.read().decode("utf-8", errors="replace")[:1200]
    except Exception as exc:
        return 0, None, f"{type(exc).__name__}: {exc}"


def _project(item: Mapping[str, Any]) -> str:
    url = str(item.get("repository_url") or "")
    return url.split("/repos/", 1)[1].strip("/") if "/repos/" in url else ""


def _row(item: Mapping[str, Any]) -> dict[str, Any]:
    project = _project(item)
    number = int(item.get("number") or 0)
    html = str(item.get("html_url") or "").strip()
    title = str(item.get("title") or "").strip()
    body = str(item.get("body") or "").strip()
    owner, repo = project.split("/", 1)
    return {
        "source_root": f"GITHUB-PR-{owner}-{repo}-{number}",
        "source_project": project,
        "source_kind": "github_merged_security_pr_targeted_supplement",
        "summary": title,
        "description": "\n".join(part for part in (title, body) if part),
        "canonical_advisory_url": html,
        "repository_advisory_url": "",
        "source_code_location": html,
        "references": [html],
        "published_at": str(item.get("created_at") or ""),
        "updated_at": str(item.get("updated_at") or ""),
        "advisory_source_type": "upstream_pr",
        "pr_number": number,
        "upstream_repository_reference": html,
        "scoring_executed": False,
        "active_target_validation_performed": False,
        "selection_uses_v6_score": False,
        "selection_uses_v6_case_errors": False,
    }


def build(token: str | None = None) -> dict[str, Any]:
    prior = exposure_index()
    pools: dict[str, list[dict[str, Any]]] = {family: [] for family in TARGETS}
    diagnostics: dict[str, Any] = {}
    for family, url in TARGETS.items():
        status, payload, error = _request(url, token)
        if status == 403 and token:
            status, payload, error = _request(url, None)
        if status != 200 or not isinstance(payload, Mapping):
            diagnostics[family] = {"fetch_status": status, "error": error, "accepted": False}
            continue
        item = dict(payload)
        pr = item.get("pull_request") if isinstance(item.get("pull_request"), Mapping) else {}
        if not pr or not pr.get("merged_at"):
            diagnostics[family] = {"fetch_status": status, "error": "target is not a merged PR", "accepted": False}
            continue
        row = _row(item)
        firewall = check_candidate(row, index=prior)
        family_pass, family_hits, family_score = audit_row(family, row)
        conditions, condition_hits = audit_conditions(family, row)
        accepted = bool(firewall["allowed"] and family_pass and conditions)
        if accepted:
            row.update({
                "family": family,
                "freshness_validated": True,
                "v7_firewall_allowed": True,
                "source_family_audit_passed": True,
                "source_family_audit_group_hits": family_hits,
                "source_family_audit_score": family_score,
                "pre_score_expected_condition_signals": conditions,
                "pre_score_condition_source_hits": condition_hits,
            })
            pools[family].append(row)
        diagnostics[family] = {
            "fetch_status": status,
            "error": error,
            "firewall_allowed": firewall["allowed"],
            "firewall_root_overlap": firewall["root_overlap"],
            "firewall_project_overlap": firewall["project_overlap"],
            "firewall_url_overlap": firewall["url_overlap"],
            "firewall_identifier_overlap": firewall.get("identifier_overlap", []),
            "source_family_audit_passed": family_pass,
            "source_family_audit_group_hits": family_hits,
            "source_family_audit_score": family_score,
            "condition_signals": conditions,
            "condition_hits": condition_hits,
            "accepted": accepted,
        }
    missing = sorted(family for family, rows in pools.items() if not rows)
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_targeted_passive_source_supplement_unscored",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "family_count": len(TARGETS),
        "candidates_by_family": pools,
        "family_candidate_counts": {family: len(rows) for family, rows in pools.items()},
        "families_without_candidates": missing,
        "diagnostics": diagnostics,
        "candidate_selection_uses_detector_scores": False,
        "candidate_selection_uses_admission_results": False,
        "candidate_selection_uses_ranking_results": False,
        "candidate_selection_uses_v6_first_blind_score": False,
        "candidate_selection_uses_v6_first_blind_case_errors": False,
        "active_target_validation_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def main() -> int:
    report = build(os.environ.get("GITHUB_TOKEN"))
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_candidate_counts": report["family_candidate_counts"],
        "families_without_candidates": report["families_without_candidates"],
        "diagnostics": report["diagnostics"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0 if not report["families_without_candidates"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
