from __future__ import annotations

"""Capture literal source neighborhoods for frozen V7 third-pass revision candidates.

This stage is still candidate-only. It reads only the already-frozen public GitHub
project, never executes third-party code, never contacts a target, never publishes
benchmark evidence, and never assigns semantic labels.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze
from v7_unseen_source_snippet_capture import api, file_bytes, hunk_ranges, line_snippet, test_controls

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.third-pass.capture.1"
THIRD = ROOT / "benchmarks/raw/sources/v7_third_pass_deep_candidates.json"
RESOLUTION = ROOT / "benchmarks/raw/sources/v7_second_pass_resolution_queue.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_third_pass_source_snippet_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_third_pass_source_snippet_candidates_report.json"

MAX_PAIRS_PER_FAMILY = 6
MAX_FILES_PER_PAIR = 10
MAX_SNIPPETS_PER_SIDE = 28


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def priority(candidate: Mapping[str, Any]) -> tuple[int, int, int, str]:
    """Prioritize stronger discovery breadcrumbs without adjudicating semantics."""
    return (
        0 if candidate.get("matched_identifiers") else 1,
        0 if candidate.get("matched_terms") else 1,
        0 if candidate.get("security_word_match") else 1,
        text(candidate.get("commit_sha")),
    )


def capture_pair(project: str, candidate: Mapping[str, Any], token: str) -> dict[str, Any]:
    fix_sha = text(candidate.get("commit_sha"))
    parents = [text(x) for x in candidate.get("parent_shas") or [] if text(x)]
    parent_sha = parents[0] if len(parents) == 1 else ""
    if not fix_sha or not parent_sha:
        return {
            "parent_sha": parent_sha or None,
            "fix_sha": fix_sha or None,
            "files": [],
            "failure": "non_single_parent_candidate",
            "semantic_role": "unadjudicated_third_pass_literal_revision_pair_candidate",
        }
    try:
        payload = api(f"https://api.github.com/repos/{project}/commits/{fix_sha}", token)
    except Exception as exc:
        return {
            "parent_sha": parent_sha,
            "fix_sha": fix_sha,
            "files": [],
            "failure": type(exc).__name__,
            "semantic_role": "unadjudicated_third_pass_literal_revision_pair_candidate",
        }

    files = []
    parent_total = 0
    fix_total = 0
    control_total = 0
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
            if parent_total < MAX_SNIPPETS_PER_SIDE:
                snippet = line_snippet(parent_raw, old_start, old_count)
                if snippet:
                    parent_snippets.append(snippet)
                    parent_total += 1
            if fix_total < MAX_SNIPPETS_PER_SIDE:
                snippet = line_snippet(fix_raw, new_start, new_count)
                if snippet:
                    fix_snippets.append(snippet)
                    fix_total += 1
        controls = test_controls(fix_raw) if bool(candidate.get("changed_test_file_count")) and path else []
        # test_controls itself requires recognizable test definitions/control words;
        # the path is also retained so a human can reject false test-path assumptions.
        control_total += len(controls)
        files.append({
            "filename": path,
            "previous_filename": previous,
            "status": text(item.get("status")),
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
        "discovery_basis": candidate.get("basis"),
        "matched_terms": list(candidate.get("matched_terms") or []),
        "matched_identifiers": list(candidate.get("matched_identifiers") or []),
        "security_word_match": bool(candidate.get("security_word_match")),
        "files": files,
        "changed_file_count": len(files),
        "parent_snippet_count": sum(len(x["parent_snippets"]) for x in files),
        "fix_snippet_count": sum(len(x["fix_snippets"]) for x in files),
        "two_sided_literal_pair": bool(
            sum(len(x["parent_snippets"]) for x in files) > 0
            and sum(len(x["fix_snippets"]) for x in files) > 0
        ),
        "test_control_candidate_count": control_total,
        "failure": None,
        "semantic_role": "unadjudicated_third_pass_literal_revision_pair_candidate",
    }
    result["pair_candidate_sha256"] = sha_json(result)
    return result


def main() -> int:
    freeze = assert_capture_source_freeze()
    third = load(THIRD)
    resolution = load(RESOLUTION)
    for doc in (third, resolution):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 third-pass source-capture assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 third-pass source capture requires unconsumed inputs")
    if third.get("unresolved_input_count") != 39 or third.get("family_result_count") != 21:
        raise RuntimeError("V7 third-pass source-capture input coverage drift")
    if third.get("candidate_semantics_adjudicated") is not False or third.get("evidence_published") is not False:
        raise RuntimeError("V7 third-pass candidates unexpectedly adjudicated/published")
    if resolution.get("still_unresolved_count") != 39:
        raise RuntimeError("V7 third-pass source-capture resolution drift")

    token = os.environ.get("GITHUB_TOKEN", "")
    families = []
    for source in third.get("families") or []:
        if not isinstance(source, Mapping):
            continue
        family = text(source.get("family"))
        project = text(source.get("source_project"))
        root = text(source.get("source_root"))
        candidates = [x for x in source.get("revision_candidates") or [] if isinstance(x, Mapping)]
        chosen = sorted(candidates, key=priority)[:MAX_PAIRS_PER_FAMILY]
        pairs = [capture_pair(project, candidate, token) for candidate in chosen]
        families.append({
            "family": family,
            "source_root": root,
            "source_project": project,
            "unresolved_case_kinds": list(source.get("unresolved_case_kinds") or []),
            "selected_revision_candidate_count": len(chosen),
            "literal_pair_candidates": pairs,
            "literal_pair_candidate_count": len(pairs),
            "two_sided_literal_pair_count": sum(bool(x.get("two_sided_literal_pair")) for x in pairs),
            "test_control_candidate_count": sum(int(x.get("test_control_candidate_count") or 0) for x in pairs),
            "failure_count": sum(bool(x.get("failure")) for x in pairs),
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
        "evaluation_kind": "fresh_blind_v7_engine_unseen_third_pass_literal_source_neighborhoods_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "family_count": len(families),
        "literal_pair_candidate_count": sum(x["literal_pair_candidate_count"] for x in families),
        "two_sided_literal_pair_count": sum(x["two_sided_literal_pair_count"] for x in families),
        "families_with_two_sided_literal_pairs": sum(x["two_sided_literal_pair_count"] > 0 for x in families),
        "test_control_candidate_count": sum(x["test_control_candidate_count"] for x in families),
        "families_with_test_control_candidates": sum(x["test_control_candidate_count"] > 0 for x in families),
        "failure_count": sum(x["failure_count"] for x in families),
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
    document["capture_set_sha256"] = sha_json(families)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
