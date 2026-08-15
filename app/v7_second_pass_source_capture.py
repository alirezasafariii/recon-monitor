from __future__ import annotations

"""Capture bounded literal source neighborhoods from V7 second-pass candidates.

This is still candidate acquisition, not semantic adjudication. Only the frozen project
is read, third-party code is never executed, and no benchmark evidence is published.
"""

import hashlib
import json
import os
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze
from v7_unseen_source_snippet_capture import api, file_bytes, hunk_ranges, line_snippet, test_controls

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.second-pass.capture.1"
SECOND = ROOT / "benchmarks/raw/sources/v7_second_pass_literal_candidates.json"
WORKLIST = ROOT / "benchmarks/raw/sources/v7_missing_literal_source_worklist.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_second_pass_source_snippet_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_second_pass_source_snippet_candidates_report.json"
DOC_PATH = re.compile(r"(^|/)(docs?|documentation)(/|$)|(^|/)(readme|changelog|changes|upgrade|history)([._-]|$)|\.(md|rst|txt)$", re.I)
TEST_PATH = re.compile(r"(^|/)(tests?|specs?|__tests__)(/|$)|[^/]*(test|spec)[._-]", re.I)
MAX_FILES_PER_PAIR = 12
MAX_SNIPPETS_PER_SIDE = 32
MAX_REVISION_PAIRS_PER_FAMILY = 8
MAX_VERSION_PAIRS_PER_FAMILY = 3


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def capture_pair(project: str, parent_sha: str, fix_sha: str, token: str, basis: str) -> dict[str, Any]:
    try:
        payload = api(f"https://api.github.com/repos/{project}/commits/{fix_sha}", token)
    except Exception as exc:
        return {
            "parent_sha": parent_sha,
            "fix_sha": fix_sha,
            "basis": basis,
            "files": [],
            "failure": type(exc).__name__,
            "semantic_role": "unadjudicated_literal_revision_pair_candidate",
        }
    files = []
    parent_count = 0
    fix_count = 0
    controls_count = 0
    for item in (payload.get("files") if isinstance(payload, Mapping) else []) or []:
        if not isinstance(item, Mapping) or len(files) >= MAX_FILES_PER_PAIR:
            continue
        path = text(item.get("filename"))
        previous = text(item.get("previous_filename")) or path
        patch = text(item.get("patch"))
        if not path or not patch:
            continue
        parent_raw = file_bytes(project, previous, parent_sha, token)
        fix_raw = file_bytes(project, path, fix_sha, token)
        parent_snippets = []
        fix_snippets = []
        for old_start, old_count, new_start, new_count in hunk_ranges(patch):
            if parent_count < MAX_SNIPPETS_PER_SIDE:
                snippet = line_snippet(parent_raw, old_start, old_count)
                if snippet:
                    parent_snippets.append(snippet)
                    parent_count += 1
            if fix_count < MAX_SNIPPETS_PER_SIDE:
                snippet = line_snippet(fix_raw, new_start, new_count)
                if snippet:
                    fix_snippets.append(snippet)
                    fix_count += 1
        controls = test_controls(fix_raw) if TEST_PATH.search(path) else []
        controls_count += len(controls)
        files.append({
            "filename": path,
            "previous_filename": previous,
            "status": text(item.get("status")),
            "documentation_path": bool(DOC_PATH.search(path)),
            "test_path": bool(TEST_PATH.search(path)),
            "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
            "parent_present": parent_raw is not None,
            "fix_present": fix_raw is not None,
            "parent_snippets": parent_snippets,
            "fix_snippets": fix_snippets,
            "upstream_test_control_candidates": controls,
        })
    result = {
        "parent_sha": parent_sha,
        "fix_sha": fix_sha,
        "basis": basis,
        "files": files,
        "changed_file_count": len(files),
        "source_code_file_count": sum(not x["documentation_path"] for x in files),
        "parent_snippet_count": sum(len(x["parent_snippets"]) for x in files),
        "fix_snippet_count": sum(len(x["fix_snippets"]) for x in files),
        "source_code_parent_snippet_count": sum(len(x["parent_snippets"]) for x in files if not x["documentation_path"]),
        "source_code_fix_snippet_count": sum(len(x["fix_snippets"]) for x in files if not x["documentation_path"]),
        "test_control_candidate_count": controls_count,
        "failure": None,
        "semantic_role": "unadjudicated_literal_revision_pair_candidate",
    }
    result["pair_candidate_sha256"] = sha_json(result)
    return result


def capture_compare_pair(project: str, old_sha: str, patched_sha: str, token: str) -> dict[str, Any]:
    comp = urllib.parse.quote(f"{old_sha}...{patched_sha}", safe=".-_~")
    try:
        payload = api(f"https://api.github.com/repos/{project}/compare/{comp}", token)
    except Exception as exc:
        return {
            "parent_sha": old_sha,
            "fix_sha": patched_sha,
            "basis": "version_tag_compare",
            "files": [],
            "failure": type(exc).__name__,
            "semantic_role": "unadjudicated_literal_version_pair_candidate",
        }
    files = []
    controls_count = 0
    for item in (payload.get("files") if isinstance(payload, Mapping) else []) or []:
        if not isinstance(item, Mapping) or len(files) >= MAX_FILES_PER_PAIR:
            continue
        path = text(item.get("filename"))
        previous = text(item.get("previous_filename")) or path
        patch = text(item.get("patch"))
        if not path or not patch:
            continue
        old_raw = file_bytes(project, previous, old_sha, token)
        new_raw = file_bytes(project, path, patched_sha, token)
        parent_snippets = []
        fix_snippets = []
        for old_start, old_count, new_start, new_count in hunk_ranges(patch):
            s = line_snippet(old_raw, old_start, old_count)
            if s:
                parent_snippets.append(s)
            s = line_snippet(new_raw, new_start, new_count)
            if s:
                fix_snippets.append(s)
        controls = test_controls(new_raw) if TEST_PATH.search(path) else []
        controls_count += len(controls)
        files.append({
            "filename": path,
            "previous_filename": previous,
            "status": text(item.get("status")),
            "documentation_path": bool(DOC_PATH.search(path)),
            "test_path": bool(TEST_PATH.search(path)),
            "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
            "parent_present": old_raw is not None,
            "fix_present": new_raw is not None,
            "parent_snippets": parent_snippets,
            "fix_snippets": fix_snippets,
            "upstream_test_control_candidates": controls,
        })
    result = {
        "parent_sha": old_sha,
        "fix_sha": patched_sha,
        "basis": "version_tag_compare",
        "files": files,
        "changed_file_count": len(files),
        "source_code_file_count": sum(not x["documentation_path"] for x in files),
        "parent_snippet_count": sum(len(x["parent_snippets"]) for x in files),
        "fix_snippet_count": sum(len(x["fix_snippets"]) for x in files),
        "source_code_parent_snippet_count": sum(len(x["parent_snippets"]) for x in files if not x["documentation_path"]),
        "source_code_fix_snippet_count": sum(len(x["fix_snippets"]) for x in files if not x["documentation_path"]),
        "test_control_candidate_count": controls_count,
        "failure": None,
        "semantic_role": "unadjudicated_literal_version_pair_candidate",
    }
    result["pair_candidate_sha256"] = sha_json(result)
    return result


def main() -> int:
    freeze = assert_capture_source_freeze()
    second = load(SECOND)
    work = load(WORKLIST)
    for doc in (second, work):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 second-pass source-capture assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 second-pass source capture requires unconsumed inputs")
    if work.get("work_item_count") != 66 or second.get("family_result_count") != 26:
        raise RuntimeError("V7 second-pass source capture coverage drift")
    if second.get("candidate_semantics_adjudicated") is not False or second.get("evidence_published") is not False:
        raise RuntimeError("second-pass candidates unexpectedly adjudicated/published")

    token = os.environ.get("GITHUB_TOKEN", "")
    families = []
    for source in second.get("families") or []:
        if not isinstance(source, Mapping):
            continue
        family = text(source.get("family"))
        project = text(source.get("source_project"))
        root = text(source.get("source_root"))
        revision_pairs = []
        seen_pairs = set()
        for candidate in source.get("revision_candidates") or []:
            if not isinstance(candidate, Mapping) or len(revision_pairs) >= MAX_REVISION_PAIRS_PER_FAMILY:
                continue
            fix_sha = text(candidate.get("commit_sha"))
            parents = [text(x) for x in candidate.get("parent_shas") or [] if text(x)]
            if not fix_sha or len(parents) != 1:
                continue
            key = (parents[0], fix_sha)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            revision_pairs.append(capture_pair(project, parents[0], fix_sha, token, "identifier_or_frozen_reference"))

        version_pairs = []
        for candidate in source.get("version_tag_candidates") or []:
            if not isinstance(candidate, Mapping) or len(version_pairs) >= MAX_VERSION_PAIRS_PER_FAMILY:
                continue
            old_sha = text(candidate.get("adjacent_older_tag_commit_sha"))
            patched_sha = text(candidate.get("patched_tag_commit_sha"))
            if not old_sha or not patched_sha or (old_sha, patched_sha) in seen_pairs:
                continue
            seen_pairs.add((old_sha, patched_sha))
            pair = capture_compare_pair(project, old_sha, patched_sha, token)
            pair["patched_tag"] = candidate.get("patched_tag")
            pair["adjacent_older_tag"] = candidate.get("adjacent_older_tag")
            pair["vulnerable_version_range"] = candidate.get("vulnerable_version_range")
            version_pairs.append(pair)

        all_pairs = revision_pairs + version_pairs
        families.append({
            "family": family,
            "source_root": root,
            "source_project": project,
            "missing_case_kinds": list(source.get("missing_case_kinds") or []),
            "revision_pair_candidates": revision_pairs,
            "version_pair_candidates": version_pairs,
            "pair_candidate_count": len(all_pairs),
            "pairs_with_source_code_parent_snippets": sum(int(x.get("source_code_parent_snippet_count") or 0) > 0 for x in all_pairs),
            "pairs_with_source_code_fix_snippets": sum(int(x.get("source_code_fix_snippet_count") or 0) > 0 for x in all_pairs),
            "test_control_candidate_count": sum(int(x.get("test_control_candidate_count") or 0) for x in all_pairs),
            "capture_failures": [x.get("failure") for x in all_pairs if x.get("failure")],
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
        "evaluation_kind": "fresh_blind_v7_engine_unseen_second_pass_literal_source_neighborhoods_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "family_count": len(families),
        "pair_candidate_count": sum(x["pair_candidate_count"] for x in families),
        "families_with_source_code_parent_snippets": sum(x["pairs_with_source_code_parent_snippets"] > 0 for x in families),
        "families_with_source_code_fix_snippets": sum(x["pairs_with_source_code_fix_snippets"] > 0 for x in families),
        "families_with_test_control_candidates": sum(x["test_control_candidate_count"] > 0 for x in families),
        "source_code_parent_snippet_pair_count": sum(x["pairs_with_source_code_parent_snippets"] for x in families),
        "source_code_fix_snippet_pair_count": sum(x["pairs_with_source_code_fix_snippets"] for x in families),
        "test_control_candidate_count": sum(x["test_control_candidate_count"] for x in families),
        "failure_count": sum(len(x["capture_failures"]) for x in families),
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
    document["capture_set_sha256"] = sha_json(families)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
