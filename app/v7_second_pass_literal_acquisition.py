from __future__ import annotations

"""Second-pass passive acquisition for the 66 missing Fresh Blind V7 literal observations.

The collector is intentionally pre-scoring and non-adjudicating. It may only inspect
public GitHub material belonging to the already-frozen source project/root. It never
replaces a source, synthesizes a fixture, executes third-party code, contacts a target,
publishes benchmark evidence, or assigns a semantic label.
"""

import base64
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze
from v7_unseen_source_snippet_capture import test_controls

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.second-pass.1"
WORKLIST = ROOT / "benchmarks/raw/sources/v7_missing_literal_source_worklist.json"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
BOUNDARY = ROOT / "benchmarks/raw/sources/v7_boundary_evidence.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_second_pass_literal_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_second_pass_literal_candidates_report.json"

COMMIT_URL = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})(?:\b|[/?#])")
PULL_URL = re.compile(r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)(?:\b|[/?#])")
ISSUE_URL = re.compile(r"https://github\.com/([^/]+)/([^/]+)/issues/(\d+)(?:\b|[/?#])")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
GHSA_RE = re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", re.I)
TEST_PATH = re.compile(r"(^|/)(tests?|specs?|__tests__)(/|$)|[^/]*(test|spec)[._-]", re.I)
MAX_BODY = 1_000_000
MAX_TEST_BYTES = 2_000_000
MAX_IDENTIFIER_SEARCHES = 3
MAX_SEARCH_ITEMS = 10
MAX_COMMIT_CANDIDATES = 10
MAX_TEST_FILES_PER_COMMIT = 8


def text(value: Any) -> str:
    return str(value or "").strip()


def sha_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def api(url: str, token: str) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-633-v7-second-pass",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise RuntimeError("GitHub response exceeds passive acquisition bound")
        return json.loads(raw.decode("utf-8"))


def repo_api(project: str, suffix: str, token: str) -> Any:
    return api(f"https://api.github.com/repos/{project}/{suffix.lstrip('/')}", token)


def identifiers(entry: Mapping[str, Any], root: str) -> list[str]:
    values = [root]
    snapshot = entry.get("snapshot_payload") if isinstance(entry.get("snapshot_payload"), Mapping) else {}
    for key in ("ghsa_id", "cve_id"):
        if text(snapshot.get(key)):
            values.append(text(snapshot.get(key)))
    for alias in snapshot.get("identifiers") or []:
        if isinstance(alias, Mapping) and text(alias.get("value")):
            values.append(text(alias.get("value")))
    blob = json.dumps(snapshot, sort_keys=True)
    values.extend(m.group(0) for m in CVE_RE.finditer(blob))
    values.extend(m.group(0) for m in GHSA_RE.finditer(blob))
    result = []
    for value in values:
        normalized = value.upper()
        if (CVE_RE.fullmatch(normalized) or GHSA_RE.fullmatch(normalized)) and normalized not in result:
            result.append(normalized)
    return result[:MAX_IDENTIFIER_SEARCHES]


def same_project(match_owner: str, match_repo: str, project: str) -> bool:
    return f"{match_owner}/{match_repo}".casefold() == project.casefold()


def extract_linked_refs(value: Any, project: str) -> tuple[set[str], set[int], set[int]]:
    blob = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    commits: set[str] = set()
    pulls: set[int] = set()
    issues: set[int] = set()
    for match in COMMIT_URL.finditer(blob):
        if same_project(match.group(1), match.group(2), project):
            commits.add(match.group(3))
    for match in PULL_URL.finditer(blob):
        if same_project(match.group(1), match.group(2), project):
            pulls.add(int(match.group(3)))
    for match in ISSUE_URL.finditer(blob):
        if same_project(match.group(1), match.group(2), project):
            issues.add(int(match.group(3)))
    return commits, pulls, issues


def search_identifier(project: str, identifier: str, token: str) -> dict[str, Any]:
    result: dict[str, Any] = {"identifier": identifier, "commit_shas": [], "issue_numbers": [], "errors": []}
    q = urllib.parse.quote(f'"{identifier}" repo:{project}', safe="")
    try:
        payload = api(f"https://api.github.com/search/commits?q={q}&per_page={MAX_SEARCH_ITEMS}", token)
        for item in (payload.get("items") if isinstance(payload, Mapping) else []) or []:
            if isinstance(item, Mapping) and text(item.get("sha")):
                result["commit_shas"].append(text(item.get("sha")))
    except Exception as exc:
        result["errors"].append({"stage": "commit_search", "error": type(exc).__name__})
    try:
        payload = api(f"https://api.github.com/search/issues?q={q}&per_page={MAX_SEARCH_ITEMS}", token)
        for item in (payload.get("items") if isinstance(payload, Mapping) else []) or []:
            if isinstance(item, Mapping) and item.get("number") is not None:
                result["issue_numbers"].append(int(item.get("number")))
    except Exception as exc:
        result["errors"].append({"stage": "issue_search", "error": type(exc).__name__})
    result["commit_shas"] = sorted(set(result["commit_shas"]))[:MAX_SEARCH_ITEMS]
    result["issue_numbers"] = sorted(set(result["issue_numbers"]))[:MAX_SEARCH_ITEMS]
    return result


def fetch_issue_or_pull(project: str, number: int, token: str) -> dict[str, Any]:
    issue = repo_api(project, f"issues/{number}", token)
    issue = issue if isinstance(issue, Mapping) else {}
    commits, pulls, issues = extract_linked_refs(issue, project)
    out: dict[str, Any] = {
        "number": number,
        "html_url": text(issue.get("html_url")),
        "title": text(issue.get("title"))[:500],
        "is_pull_request": isinstance(issue.get("pull_request"), Mapping),
        "linked_commit_shas": sorted(commits),
        "linked_pull_numbers": sorted(pulls),
        "linked_issue_numbers": sorted(issues),
    }
    if out["is_pull_request"]:
        try:
            pull = repo_api(project, f"pulls/{number}", token)
            pull = pull if isinstance(pull, Mapping) else {}
            for candidate in (
                text(pull.get("merge_commit_sha")),
                text((pull.get("head") or {}).get("sha") if isinstance(pull.get("head"), Mapping) else ""),
            ):
                if candidate:
                    out["linked_commit_shas"].append(candidate)
            out["linked_commit_shas"] = sorted(set(out["linked_commit_shas"]))
        except Exception as exc:
            out["pull_fetch_error"] = type(exc).__name__
    return out


def file_bytes(project: str, path: str, ref: str, token: str) -> bytes | None:
    try:
        encoded_path = urllib.parse.quote(path, safe="/")
        encoded_ref = urllib.parse.quote(ref, safe="")
        payload = repo_api(project, f"contents/{encoded_path}?ref={encoded_ref}", token)
        if not isinstance(payload, Mapping) or text(payload.get("type")) != "file":
            return None
        raw = base64.b64decode(text(payload.get("content")).replace("\n", ""))
        return raw if len(raw) <= MAX_TEST_BYTES else None
    except Exception:
        return None


def commit_candidate(project: str, sha: str, token: str, basis: list[str]) -> dict[str, Any] | None:
    try:
        payload = repo_api(project, f"commits/{sha}", token)
    except Exception:
        return None
    if not isinstance(payload, Mapping) or not text(payload.get("sha")):
        return None
    parents = [text(x.get("sha")) for x in payload.get("parents") or [] if isinstance(x, Mapping) and text(x.get("sha"))]
    files = []
    control_candidates = []
    for item in payload.get("files") or []:
        if not isinstance(item, Mapping):
            continue
        path = text(item.get("filename"))
        patch = text(item.get("patch"))
        row = {
            "filename": path,
            "status": text(item.get("status")),
            "is_test_path": bool(TEST_PATH.search(path)),
            "patch_sha256": hashlib.sha256(patch.encode()).hexdigest() if patch else None,
        }
        files.append(row)
        if row["is_test_path"] and len(control_candidates) < MAX_TEST_FILES_PER_COMMIT:
            raw = file_bytes(project, path, text(payload.get("sha")), token)
            controls = test_controls(raw)
            if controls:
                control_candidates.append({
                    "filename": path,
                    "commit_sha": text(payload.get("sha")),
                    "controls": controls,
                })
    return {
        "commit_sha": text(payload.get("sha")),
        "parent_shas": parents,
        "single_parent_pair_candidate": len(parents) == 1,
        "message": text((payload.get("commit") or {}).get("message") if isinstance(payload.get("commit"), Mapping) else "")[:1000],
        "html_url": text(payload.get("html_url")),
        "discovery_basis": sorted(set(basis)),
        "changed_file_count": len(files),
        "changed_test_file_count": sum(bool(x["is_test_path"]) for x in files),
        "files": files,
        "upstream_test_control_candidates": control_candidates,
        "semantic_role": "unadjudicated_identifier_linked_revision_candidate",
    }


def normalize_version(value: str) -> str:
    value = text(value).strip()
    value = re.sub(r"^[<>=~^\s]+", "", value)
    value = value.split(",")[0].strip()
    return value


def version_tag_candidates(project: str, boundaries: list[Mapping[str, Any]], token: str) -> list[dict[str, Any]]:
    try:
        tags = repo_api(project, "tags?per_page=100", token)
    except Exception:
        return []
    if not isinstance(tags, list):
        return []
    tag_rows = [x for x in tags if isinstance(x, Mapping) and text(x.get("name"))]
    results = []
    for boundary in boundaries:
        patched = normalize_version(text(boundary.get("patched_version")))
        if not patched:
            continue
        for index, tag in enumerate(tag_rows):
            name = text(tag.get("name"))
            if name.casefold() not in {patched.casefold(), f"v{patched}".casefold()}:
                continue
            commit_obj = tag.get("commit") if isinstance(tag.get("commit"), Mapping) else {}
            previous = tag_rows[index + 1] if index + 1 < len(tag_rows) else None
            results.append({
                "patched_version": patched,
                "patched_tag": name,
                "patched_tag_commit_sha": text(commit_obj.get("sha")) or None,
                "adjacent_older_tag": text(previous.get("name")) if isinstance(previous, Mapping) else None,
                "adjacent_older_tag_commit_sha": text((previous.get("commit") or {}).get("sha")) if isinstance(previous, Mapping) and isinstance(previous.get("commit"), Mapping) else None,
                "vulnerable_version_range": text(boundary.get("vulnerable_version_range")),
                "semantic_role": "unadjudicated_version_boundary_candidate",
            })
            break
    return results


def main() -> int:
    freeze = assert_capture_source_freeze()
    work = load(WORKLIST)
    research = load(RESEARCH)
    boundary = load(BOUNDARY)
    for doc in (work, research, boundary):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 second-pass input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 second-pass requires unconsumed pre-scoring inputs")
    if work.get("work_item_count") != 66 or work.get("families_with_missing_items") != 26:
        raise RuntimeError("V7 missing-source worklist coverage drift")
    if work.get("source_replacement_allowed") is not False or work.get("synthetic_fixture_allowed") is not False:
        raise RuntimeError("V7 second-pass source/synthetic firewall violated")

    research_by = {text(x.get("family")): x for x in research.get("entries") or [] if isinstance(x, Mapping)}
    boundary_by = {text(x.get("family")): x for x in boundary.get("sources") or [] if isinstance(x, Mapping)}
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in work.get("items") or []:
        if isinstance(item, Mapping):
            grouped[text(item.get("family"))].append(item)
    if len(grouped) != 26:
        raise RuntimeError("V7 second-pass family grouping drift")

    token = os.environ.get("GITHUB_TOKEN", "")
    families = []
    total_revision_candidates = 0
    total_controls = 0
    total_version_tags = 0
    for family in sorted(grouped):
        items = grouped[family]
        root = text(items[0].get("source_root"))
        project = text(items[0].get("source_project"))
        if not root or not project:
            raise RuntimeError(f"{family}: missing frozen source identity")
        if any(text(x.get("source_root")) != root or text(x.get("source_project")) != project for x in items):
            raise RuntimeError(f"{family}: source identity differs across missing variants")
        research_entry = research_by.get(family, {})
        boundary_entry = boundary_by.get(family, {})
        ids = identifiers(research_entry, root)

        commit_basis: dict[str, set[str]] = defaultdict(set)
        issue_numbers: set[int] = set()
        searches = []
        for ident in ids:
            search = search_identifier(project, ident, token)
            searches.append(search)
            for sha in search["commit_shas"]:
                commit_basis[sha].add(f"identifier_search:{ident}")
            issue_numbers.update(search["issue_numbers"])

        # Revisit every already-frozen upstream link, including issue/PR references that
        # the first pass did not promote to an exact direct advisory commit.
        linked_values = [research_entry.get("snapshot_payload"), research_entry.get("discovered_upstream_links")]
        for value in linked_values:
            commits, pulls, issues = extract_linked_refs(value, project)
            for sha in commits:
                commit_basis[sha].add("frozen_advisory_reference")
            issue_numbers.update(issues)
            issue_numbers.update(pulls)

        issue_snapshots = []
        for number in sorted(issue_numbers)[:MAX_SEARCH_ITEMS]:
            try:
                snap = fetch_issue_or_pull(project, number, token)
                issue_snapshots.append(snap)
                for sha in snap.get("linked_commit_shas") or []:
                    commit_basis[text(sha)].add(f"issue_or_pr:{number}")
            except Exception as exc:
                issue_snapshots.append({"number": number, "fetch_error": type(exc).__name__})

        # Include first-pass candidate commits even if direct-fix selection rejected them
        # as ambiguous. They remain unadjudicated candidates here.
        for ref in boundary_entry.get("reference_snapshots") or []:
            if isinstance(ref, Mapping) and text(ref.get("kind")) == "commit" and text(ref.get("sha")):
                commit_basis[text(ref.get("sha"))].add("first_pass_reference_snapshot")

        revision_candidates = []
        for sha in sorted(commit_basis)[:MAX_COMMIT_CANDIDATES]:
            candidate = commit_candidate(project, sha, token, sorted(commit_basis[sha]))
            if candidate:
                revision_candidates.append(candidate)
        controls = sum(
            len(row.get("upstream_test_control_candidates") or [])
            for row in revision_candidates
        )
        tag_candidates = version_tag_candidates(
            project,
            [x for x in boundary_entry.get("version_boundaries") or [] if isinstance(x, Mapping)],
            token,
        )
        total_revision_candidates += len(revision_candidates)
        total_controls += controls
        total_version_tags += len(tag_candidates)
        families.append({
            "family": family,
            "source_root": root,
            "source_project": project,
            "missing_case_kinds": sorted(text(x.get("case_kind")) for x in items),
            "missing_item_count": len(items),
            "identifiers": ids,
            "identifier_searches": searches,
            "issue_or_pull_snapshots": issue_snapshots,
            "revision_candidates": revision_candidates,
            "revision_candidate_count": len(revision_candidates),
            "upstream_test_control_candidate_group_count": controls,
            "version_tag_candidates": tag_candidates,
            "version_tag_candidate_count": len(tag_candidates),
            "candidate_semantics_adjudicated": False,
            "source_replacement_used": False,
            "synthetic_fixture_used": False,
            "third_party_code_executed": False,
            "target_contact_performed": False,
            "scoring_executed": False,
            "first_blind_consumed": False,
        })

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_second_pass_literal_candidate_inventory_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "missing_work_item_count": 66,
        "missing_family_count": 26,
        "family_result_count": len(families),
        "families_with_revision_candidates": sum(x["revision_candidate_count"] > 0 for x in families),
        "revision_candidate_count": total_revision_candidates,
        "families_with_test_control_candidates": sum(x["upstream_test_control_candidate_group_count"] > 0 for x in families),
        "upstream_test_control_candidate_group_count": total_controls,
        "families_with_version_tag_candidates": sum(x["version_tag_candidate_count"] > 0 for x in families),
        "version_tag_candidate_count": total_version_tags,
        "candidate_semantics_adjudicated": False,
        "evidence_published": False,
        "publication_authorized": False,
        "source_assignment_locked": True,
        "source_replacement_allowed": False,
        "source_replacement_used": False,
        "synthetic_fixture_allowed": False,
        "synthetic_fixture_used": False,
        "cross_variant_mutation_allowed": False,
        "third_party_code_executed": False,
        "target_contact_performed": False,
        "human_adjudication_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
    }
    document = dict(report)
    document["families"] = families
    document["candidate_inventory_sha256"] = sha_json(families)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
