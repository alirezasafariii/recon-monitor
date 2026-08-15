from __future__ import annotations

"""Sixth-pass acquisition for the 18 residual Fresh Blind V7 gaps.

This pass fixes two discovery blind spots without weakening semantics:
1) resolve explicitly frozen GitHub release references directly, then compare to the
   nearest older same-series tag in the same repository;
2) enumerate the real repository tree and capture adjacent upstream test/spec files
   nearest to source-specific security modules, instead of relying on code-search.

All outputs remain candidate-only, source-locked, unadjudicated, and pre-scoring.
"""

import hashlib
import json
import os
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze
from v7_fifth_pass_source_specific_acquisition import semver, source_specific_terms
from v7_second_pass_source_capture import capture_compare_pair
from v7_third_pass_source_capture import TEST_PATH
from v7_unseen_source_snippet_capture import api, file_bytes

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.sixth-pass.reference-tree.1"
RESIDUAL = ROOT / "benchmarks/raw/sources/v7_residual_unresolved_worklist.json"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
BOUNDARY = ROOT / "benchmarks/raw/sources/v7_boundary_evidence.json"
THIRD_DEEP = ROOT / "benchmarks/raw/sources/v7_third_pass_deep_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_sixth_pass_reference_tree_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_sixth_pass_reference_tree_candidates_report.json"

RELEASE_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/releases/tag/(.+?)(?:[?#].*)?$", re.I)
SEMVER_RE = re.compile(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?(?!\d)")
TEST_CASE_RE = re.compile(
    r"(?m)^\s*(?:def\s+test_[A-Za-z0-9_]+|(?:public\s+)?function\s+test[A-Za-z0-9_]*|"
    r"func\s+Test[A-Za-z0-9_]+|(?:it|test|describe)\s*\([^\n]{0,220}|#\[test\]|"
    r"(?:Feature|Scenario(?: Outline)?):[^\n]{0,220})",
    re.I,
)
MAX_RELEASE_REFS_PER_FAMILY = 4
MAX_TREE_TEST_FILES_PER_FAMILY = 8
MAX_TEST_CASES_PER_FILE = 10
MAX_SNIPPET = 2600
MAX_FILE_BYTES = 1_500_000


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def same_project(owner: str, repo: str, project: str) -> bool:
    return f"{owner}/{repo}".casefold() == project.casefold()


def frozen_release_tags(research: Mapping[str, Any], project: str) -> list[str]:
    snapshot = research.get("snapshot_payload") if isinstance(research.get("snapshot_payload"), Mapping) else {}
    values = []
    for value in snapshot.get("references") or []:
        if not isinstance(value, str):
            continue
        match = RELEASE_RE.match(value)
        if not match or not same_project(match.group(1), match.group(2), project):
            continue
        tag = urllib.parse.unquote(match.group(3))
        if tag not in values:
            values.append(tag)
    return values[:MAX_RELEASE_REFS_PER_FAMILY]


def resolve_commit(project: str, ref: str, token: str) -> str | None:
    try:
        payload = api(
            f"https://api.github.com/repos/{project}/commits/{urllib.parse.quote(ref, safe='')}",
            token,
        )
    except Exception:
        return None
    return text(payload.get("sha")) if isinstance(payload, Mapping) and text(payload.get("sha")) else None


def matching_series_tags(project: str, tag: str, token: str) -> list[dict[str, str]]:
    match = SEMVER_RE.search(tag)
    if not match:
        return []
    prefix = tag[: match.start()]
    major, minor = int(match.group(1)), int(match.group(2))
    series_prefix = f"{prefix}{major}.{minor}"
    endpoint = (
        f"https://api.github.com/repos/{project}/git/matching-refs/tags/"
        f"{urllib.parse.quote(series_prefix, safe='')}"
    )
    try:
        payload = api(endpoint, token)
    except Exception:
        return []
    rows = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, Mapping):
            continue
        ref = text(item.get("ref"))
        name = ref[len("refs/tags/") :] if ref.startswith("refs/tags/") else ""
        obj = item.get("object") if isinstance(item.get("object"), Mapping) else {}
        sha = text(obj.get("sha"))
        version = semver(name)
        if name and sha and version is not None and name.startswith(prefix):
            rows.append({"name": name, "object_sha": sha, "version": version})
    return rows


def direct_release_pairs(project: str, research: Mapping[str, Any], token: str) -> list[dict[str, Any]]:
    pairs = []
    for tag in frozen_release_tags(research, project):
        current_version = semver(tag)
        fixed_sha = resolve_commit(project, tag, token)
        if current_version is None or not fixed_sha:
            continue
        older = [row for row in matching_series_tags(project, tag, token) if tuple(row["version"]) < current_version]
        older.sort(key=lambda row: tuple(row["version"]), reverse=True)
        if not older:
            continue
        old = older[0]
        old_sha = resolve_commit(project, text(old.get("name")), token)
        if not old_sha:
            continue
        pair = capture_compare_pair(project, old_sha, fixed_sha, token)
        pair["fixed_release_tag"] = tag
        pair["adjacent_older_tag"] = old.get("name")
        pair["frozen_release_reference"] = True
        pair["semantic_role"] = "unadjudicated_sixth_pass_explicit_release_boundary_candidate"
        pairs.append(pair)
    return pairs


def default_branch_and_tree(project: str, token: str) -> tuple[str, str, bool]:
    try:
        repo = api(f"https://api.github.com/repos/{project}", token)
        branch = text(repo.get("default_branch")) if isinstance(repo, Mapping) else ""
        commit = api(
            f"https://api.github.com/repos/{project}/commits/{urllib.parse.quote(branch, safe='')}",
            token,
        ) if branch else {}
        commit_obj = commit.get("commit") if isinstance(commit, Mapping) and isinstance(commit.get("commit"), Mapping) else {}
        tree_obj = commit_obj.get("tree") if isinstance(commit_obj.get("tree"), Mapping) else {}
        tree_sha = text(tree_obj.get("sha"))
        return branch, tree_sha, False
    except Exception:
        return "", "", False


def tree_test_paths(project: str, tree_sha: str, token: str) -> tuple[list[str], bool]:
    if not tree_sha:
        return [], False
    try:
        payload = api(f"https://api.github.com/repos/{project}/git/trees/{tree_sha}?recursive=1", token)
    except Exception:
        return [], False
    if not isinstance(payload, Mapping):
        return [], False
    paths = []
    for item in payload.get("tree") or []:
        if not isinstance(item, Mapping) or text(item.get("type")) != "blob":
            continue
        path = text(item.get("path"))
        if path and TEST_PATH.search(path):
            paths.append(path)
    return paths, bool(payload.get("truncated"))


def module_tokens(deep: Mapping[str, Any], research: Mapping[str, Any], family: str) -> list[str]:
    values = list(source_specific_terms(research, deep, family))
    for candidate in deep.get("revision_candidates") or []:
        if not isinstance(candidate, Mapping):
            continue
        for file_row in candidate.get("files") or []:
            if not isinstance(file_row, Mapping):
                continue
            path = text(file_row.get("filename"))
            p = PurePosixPath(path)
            for part in list(p.parts[-4:]) + [p.stem]:
                for token in re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", part):
                    normalized = token.casefold().strip("_-")
                    if normalized and normalized not in values:
                        values.append(normalized)
    return values[:20]


def path_score(path: str, terms: list[str]) -> tuple[int, int, str]:
    haystack = path.casefold()
    matches = sum(term.casefold() in haystack for term in terms)
    depth = len(PurePosixPath(path).parts)
    return (-matches, depth, path)


def extract_test_cases(raw: bytes | None, terms: list[str]) -> list[dict[str, Any]]:
    if raw is None or len(raw) > MAX_FILE_BYTES:
        return []
    source = raw.decode("utf-8", errors="replace")
    lines = source.splitlines()
    rows = []
    for match in TEST_CASE_RE.finditer(source):
        line_no = source[: match.start()].count("\n")
        lo = max(0, line_no - 1)
        hi = min(len(lines), lo + 36)
        body = "\n".join(lines[lo:hi])[:MAX_SNIPPET]
        rows.append({
            "line_start": lo + 1,
            "line_end": hi,
            "matched_terms": sorted({term for term in terms if term.casefold() in body.casefold()}),
            "text": body,
            "text_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "semantic_role": "unadjudicated_sixth_pass_adjacent_upstream_test_case_candidate",
        })
        if len(rows) >= MAX_TEST_CASES_PER_FILE:
            break
    if rows:
        return rows
    # Some real regression fixtures (SQL/GraphQL/query-language files) contain no
    # conventional test function. Keep a bounded term-matched neighborhood for human review.
    for idx, line in enumerate(lines):
        matched = [term for term in terms if term.casefold() in line.casefold()]
        if not matched:
            continue
        lo = max(0, idx - 8)
        hi = min(len(lines), idx + 14)
        body = "\n".join(lines[lo:hi])[:MAX_SNIPPET]
        rows.append({
            "line_start": lo + 1,
            "line_end": hi,
            "matched_terms": matched,
            "text": body,
            "text_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "semantic_role": "unadjudicated_sixth_pass_test_fixture_neighborhood_candidate",
        })
        if len(rows) >= MAX_TEST_CASES_PER_FILE:
            break
    return rows


def adjacent_tree_tests(project: str, deep: Mapping[str, Any], research: Mapping[str, Any], family: str, token: str) -> dict[str, Any]:
    branch, tree_sha, _ = default_branch_and_tree(project, token)
    paths, truncated = tree_test_paths(project, tree_sha, token)
    terms = module_tokens(deep, research, family)
    ranked = sorted(paths, key=lambda path: path_score(path, terms))
    selected = []
    for path in ranked:
        if len(selected) >= MAX_TREE_TEST_FILES_PER_FAMILY:
            break
        score = -path_score(path, terms)[0]
        if score <= 0:
            continue
        raw = file_bytes(project, path, branch, token)
        cases = extract_test_cases(raw, terms)
        if not cases:
            continue
        selected.append({
            "path": path,
            "ref": branch,
            "tree_sha": tree_sha,
            "path_term_match_count": score,
            "file_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
            "test_cases": cases,
            "test_case_count": len(cases),
            "semantic_role": "unadjudicated_sixth_pass_adjacent_tree_test_file_candidate",
        })
    return {
        "default_branch": branch or None,
        "tree_sha": tree_sha or None,
        "tree_truncated": truncated,
        "test_path_count": len(paths),
        "module_terms": terms,
        "selected_test_files": selected,
        "selected_test_file_count": len(selected),
        "selected_test_case_count": sum(int(x.get("test_case_count") or 0) for x in selected),
    }


def main() -> int:
    freeze = assert_capture_source_freeze()
    residual = load(RESIDUAL)
    research = load(RESEARCH)
    boundary = load(BOUNDARY)
    deep = load(THIRD_DEEP)
    for doc in (residual, research, boundary, deep):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 sixth-pass input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 sixth-pass requires unconsumed pre-scoring inputs")
    if residual.get("unresolved_item_count") != 18 or residual.get("unresolved_family_count") != 14:
        raise RuntimeError("V7 sixth-pass residual coverage drift")

    research_by = {text(x.get("family")): x for x in research.get("entries") or [] if isinstance(x, Mapping)}
    deep_by = {text(x.get("family")): x for x in deep.get("families") or [] if isinstance(x, Mapping)}
    token = os.environ.get("GITHUB_TOKEN", "")
    families = []
    for residual_row in residual.get("families") or []:
        if not isinstance(residual_row, Mapping):
            continue
        family = text(residual_row.get("family"))
        project = text(residual_row.get("source_project"))
        root = text(residual_row.get("source_root"))
        kinds = list(residual_row.get("unresolved_case_kinds") or [])
        research_row = research_by.get(family, {})
        deep_row = deep_by.get(family, {})

        release_pairs = direct_release_pairs(project, research_row, token) if ("positive" in kinds or "secure_negative" in kinds) else []
        tree_tests = adjacent_tree_tests(project, deep_row, research_row, family, token) if "near_miss" in kinds else {
            "default_branch": None,
            "tree_sha": None,
            "tree_truncated": False,
            "test_path_count": 0,
            "module_terms": [],
            "selected_test_files": [],
            "selected_test_file_count": 0,
            "selected_test_case_count": 0,
        }

        families.append({
            "family": family,
            "source_root": root,
            "source_project": project,
            "unresolved_case_kinds": kinds,
            "frozen_release_tags": frozen_release_tags(research_row, project),
            "explicit_release_boundary_candidates": release_pairs,
            "explicit_release_boundary_candidate_count": len(release_pairs),
            "two_sided_explicit_release_boundary_count": sum(
                int(x.get("source_code_parent_snippet_count") or 0) > 0
                and int(x.get("source_code_fix_snippet_count") or 0) > 0
                for x in release_pairs
            ),
            "tree_test_acquisition": tree_tests,
            "candidate_semantics_adjudicated": False,
            "source_replacement_used": False,
            "synthetic_fixture_used": False,
            "cross_variant_mutation_used": False,
            "third_party_code_executed": False,
            "target_contact_performed": False,
            "evidence_published": False,
            "publication_authorized": False,
            "scoring_executed": False,
            "first_blind_consumed": False,
        })

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_sixth_pass_reference_tree_candidates_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "residual_input_count": 18,
        "residual_family_count": 14,
        "family_result_count": len(families),
        "explicit_release_boundary_candidate_count": sum(x["explicit_release_boundary_candidate_count"] for x in families),
        "two_sided_explicit_release_boundary_count": sum(x["two_sided_explicit_release_boundary_count"] for x in families),
        "families_with_two_sided_explicit_release_boundaries": sum(x["two_sided_explicit_release_boundary_count"] > 0 for x in families),
        "tree_test_path_count": sum(int(x["tree_test_acquisition"].get("test_path_count") or 0) for x in families),
        "adjacent_tree_test_file_candidate_count": sum(int(x["tree_test_acquisition"].get("selected_test_file_count") or 0) for x in families),
        "adjacent_tree_test_case_candidate_count": sum(int(x["tree_test_acquisition"].get("selected_test_case_count") or 0) for x in families),
        "families_with_adjacent_tree_test_candidates": sum(int(x["tree_test_acquisition"].get("selected_test_file_count") or 0) > 0 for x in families),
        "truncated_tree_family_count": sum(bool(x["tree_test_acquisition"].get("tree_truncated")) for x in families),
        "candidate_semantics_adjudicated": False,
        "human_adjudication_performed": False,
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
