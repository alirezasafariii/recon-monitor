from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from typing import Any, Mapping
from urllib.parse import urlparse

from raw_recon_corpus import ROOT
from v7_source_semantic_audit import audit_row
from raw_recon_v7_source_firewall import check_candidate, exposure_index
from v7_pre_score_condition_audit import audit_conditions

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.32.v7.8"
INPUT = ROOT / "benchmarks/raw/sources/v7_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_candidates_patchable.json"
MAX_CANDIDATES_PER_FAMILY = 16


def _request_json(url: str, token: str | None) -> tuple[int, Any, str | None]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-632-v7-patch-probe",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
            raw = response.read(5 * 1024 * 1024)
            return int(response.status), json.loads(raw.decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        return int(exc.code), None, f"HTTP {exc.code}: " + exc.read().decode("utf-8", errors="replace")[:1200]
    except Exception as exc:
        return 0, None, f"{type(exc).__name__}: {exc}"


def _repo_ref(row: Mapping[str, Any]) -> tuple[str, str, str] | None:
    candidates = [
        str(row.get("upstream_repository_reference") or "").strip(),
        str(row.get("source_code_location") or "").strip(),
    ]
    candidates.extend(str(value).strip() for value in row.get("references") or [] if str(value).strip())
    project = str(row.get("source_project") or "").strip().casefold()
    for value in candidates:
        p = urlparse(value)
        if p.scheme != "https" or p.netloc.casefold() != "github.com":
            continue
        parts = [part for part in p.path.split("/") if part]
        if len(parts) < 4:
            continue
        repo = f"{parts[0]}/{parts[1]}"
        if project and repo.casefold() != project:
            continue
        if parts[2] == "pull" and parts[3].isdigit():
            return "pull", repo, parts[3]
        if parts[2] == "commit" and parts[3]:
            return "commit", repo, parts[3]
    return None


def _patch_payload(route: str, project: str, ident: str, token: str | None) -> tuple[int, Any, str | None, str]:
    if route == "pull":
        url = f"https://api.github.com/repos/{project}/pulls/{ident}/files?per_page=100"
        status, payload, error = _request_json(url, token)
        return status, payload, error, url
    url = f"https://api.github.com/repos/{project}/commits/{ident}"
    status, payload, error = _request_json(url, token)
    return status, payload, error, url


def _files(payload: Any, route: str) -> list[dict[str, Any]]:
    if route == "pull" and isinstance(payload, list):
        return [dict(row) for row in payload if isinstance(row, Mapping)]
    if route == "commit" and isinstance(payload, Mapping):
        return [dict(row) for row in payload.get("files") or [] if isinstance(row, Mapping)]
    return []


def _patch_lines(files: list[dict[str, Any]]) -> tuple[list[str], list[str], list[str], str]:
    added: list[str] = []
    removed: list[str] = []
    context: list[str] = []
    chunks: list[str] = []
    for row in files[:100]:
        filename = str(row.get("filename") or "")
        patch = str(row.get("patch") or "")
        if filename or patch:
            chunks.append(f"FILE {filename}\n{patch}"[:10000])
        for line in patch.splitlines():
            if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
                continue
            if line.startswith("+"):
                added.append(line[1:])
            elif line.startswith("-"):
                removed.append(line[1:])
            elif line.startswith(" "):
                context.append(line[1:])
    combined = "\n".join(chunks)[:120000]
    return added[:400], removed[:400], context[:400], combined


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _partial_score(family: str, row: Mapping[str, Any]) -> int:
    passed, hits, score = audit_row(family, row)
    condition_signals, condition_hits = audit_conditions(family, row)
    return score + 8 * int(passed) + 6 * len(condition_signals) + sum(len(v) for v in condition_hits.values())


def probe(token: str | None = None) -> dict[str, Any]:
    source = json.loads(INPUT.read_text(encoding="utf-8"))
    if source.get("scoring_executed") is not False:
        raise RuntimeError("v7 candidate pool must remain unscored")
    if source.get("candidate_selection_uses_v6_first_blind_score") is not False or source.get("candidate_selection_uses_v6_first_blind_case_errors") is not False:
        raise RuntimeError("v7 candidate pool contaminated by v6 result")
    pools = source.get("candidates_by_family") if isinstance(source.get("candidates_by_family"), Mapping) else {}
    if len(pools) != 36:
        raise RuntimeError(f"v7 patch probe expects 36 family buckets, got {len(pools)}")

    prior = exposure_index()
    output: dict[str, list[dict[str, Any]]] = {}
    diagnostics: dict[str, Any] = {}
    api_calls = 0

    for family in sorted(pools):
        raw_rows = [dict(row) for row in pools.get(family) or [] if isinstance(row, Mapping)]
        raw_rows.sort(key=lambda row: (_partial_score(family, row), str(row.get("updated_at") or "")), reverse=True)
        kept: list[dict[str, Any]] = []
        rejected: dict[str, int] = {}
        seen_projects: set[str] = set()

        for row in raw_rows:
            if len(kept) >= MAX_CANDIDATES_PER_FAMILY:
                break
            check = check_candidate(row, index=prior)
            if not check["allowed"]:
                rejected["firewall"] = rejected.get("firewall", 0) + 1
                continue
            ref = _repo_ref(row)
            if ref is None:
                rejected["no_patch_reference"] = rejected.get("no_patch_reference", 0) + 1
                continue
            route, project, ident = ref
            # Avoid spending API budget repeatedly on near-identical candidates from one project.
            project_key = project.casefold()
            if project_key in seen_projects and len(kept) >= 4:
                continue
            status, payload, error, api_ref = _patch_payload(route, project, ident, token)
            api_calls += 1
            if status == 403 and token:
                status, payload, error, api_ref = _patch_payload(route, project, ident, None)
                api_calls += 1
            if status != 200:
                rejected["patch_fetch"] = rejected.get("patch_fetch", 0) + 1
                continue
            files = _files(payload, route)
            added, removed, context, patch_text = _patch_lines(files)
            if not files or not patch_text or not added or not removed:
                rejected["patch_not_bidirectional"] = rejected.get("patch_not_bidirectional", 0) + 1
                continue

            enriched = dict(row)
            original_description = str(enriched.get("description") or "")
            enriched["patch_text"] = patch_text
            # The audit text remains source-grounded: title/body plus verbatim upstream diff.
            enriched["description"] = (original_description + "\n\nUPSTREAM PATCH\n" + patch_text).strip()
            passed, family_hits, family_score = audit_row(family, enriched)
            condition_signals, condition_hits = audit_conditions(family, enriched)
            if not passed:
                rejected["family_semantic"] = rejected.get("family_semantic", 0) + 1
                continue
            if not condition_signals:
                rejected["condition_semantic"] = rejected.get("condition_semantic", 0) + 1
                continue

            enriched.update({
                "family": family,
                "upstream_repository_reference": f"https://github.com/{project}/{route}/{ident}",
                "patch_probe_passed": True,
                "patch_probe_version": VERSION,
                "patch_probe_rule_version": RULE_VERSION,
                "patch_api_reference": api_ref,
                "patch_route": route,
                "patch_file_count": len(files),
                "patch_added_line_count": len(added),
                "patch_removed_line_count": len(removed),
                "patch_context_line_count": len(context),
                "patch_text_sha256": _sha_text(patch_text),
                "patch_added_lines": added,
                "patch_removed_lines": removed,
                "patch_context_lines": context,
                "source_family_audit_passed": True,
                "source_family_audit_group_hits": family_hits,
                "source_family_audit_score": family_score,
                "pre_score_expected_condition_signals": condition_signals,
                "pre_score_condition_source_hits": condition_hits,
                "selection_uses_v6_score": False,
                "selection_uses_v6_case_errors": False,
                "scoring_executed": False,
                "active_target_validation_performed": False,
            })
            kept.append(enriched)
            seen_projects.add(project_key)

        output[str(family)] = kept
        diagnostics[str(family)] = {
            "input_candidate_count": len(raw_rows),
            "patchable_candidate_count": len(kept),
            "rejections": rejected,
        }

    missing = sorted(family for family, rows in output.items() if not rows)
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_unscored_patch_feasibility_pool",
        "family_count": 36,
        "candidates_by_family": output,
        "family_candidate_counts": {family: len(rows) for family, rows in output.items()},
        "families_without_candidates": missing,
        "diagnostics": diagnostics,
        "patch_api_call_count": api_calls,
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
    report = probe(os.environ.get("GITHUB_TOKEN"))
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_candidate_counts": report["family_candidate_counts"],
        "families_without_candidates": report["families_without_candidates"],
        "patch_api_call_count": report["patch_api_call_count"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
