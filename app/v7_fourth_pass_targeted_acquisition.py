from __future__ import annotations

"""Targeted fourth-pass acquisition for only the 21 unresolved Fresh Blind V7 items.

Positive/secure-negative gaps inspect uncaptured same-source revision candidates.
Near-miss gaps inspect real upstream changed tests and bounded lexical code-search
results in the same frozen project. This stage remains candidate-only and unscored.
"""

import hashlib
import json
import os
import re
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze
from v7_third_pass_source_capture import TEST_PATH, capture_pair, priority
from v7_unseen_source_snippet_capture import api, file_bytes, test_controls

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.fourth-pass.targeted.1"
RESOLUTION = ROOT / "benchmarks/raw/sources/v7_third_pass_resolution_queue.json"
THIRD_DEEP = ROOT / "benchmarks/raw/sources/v7_third_pass_deep_candidates.json"
THIRD_CAPTURE = ROOT / "benchmarks/raw/sources/v7_third_pass_source_snippet_candidates.json"
PACKETS = ROOT / "benchmarks/raw/sources/v7_semantic_review_packets.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_fourth_pass_targeted_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_fourth_pass_targeted_candidates_report.json"

MAX_REMAINING_PAIRS_PER_FAMILY = 5
MAX_CHANGED_TEST_GROUPS_PER_FAMILY = 10
MAX_LEXICAL_TERMS = 3
MAX_CODE_RESULTS_PER_TERM = 8
MAX_CURRENT_TEST_FILES_PER_FAMILY = 8
SEARCH_SLEEP_SECONDS = 1.8
TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,}")
STOP = {
    "with", "without", "from", "that", "this", "request", "response", "control",
    "condition", "signal", "value", "user", "data", "object", "input", "output",
    "missing", "present", "allowed", "observed", "expected", "should", "must",
}


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


def lexical_terms(packet: Mapping[str, Any], family: str) -> list[str]:
    values: list[str] = []
    for key in ("blocking_controls_vocabulary", "condition_signals_vocabulary", "override_signals_vocabulary"):
        values.extend(text(x) for x in packet.get(key) or [] if text(x))
    values.append(family.replace("_", " "))
    tokens: list[str] = []
    for value in values:
        for token in TOKEN_RE.findall(value):
            normalized = token.casefold().strip("._-")
            if len(normalized) < 4 or normalized in STOP:
                continue
            if normalized not in tokens:
                tokens.append(normalized)
    return tokens[:10]


def default_branch(project: str, token: str) -> str:
    try:
        payload = api(f"https://api.github.com/repos/{project}", token)
    except Exception:
        return ""
    return text(payload.get("default_branch")) if isinstance(payload, Mapping) else ""


def changed_test_controls(project: str, candidate: Mapping[str, Any], token: str) -> list[dict[str, Any]]:
    sha = text(candidate.get("commit_sha"))
    if not sha or int(candidate.get("changed_test_file_count") or 0) <= 0:
        return []
    try:
        payload = api(f"https://api.github.com/repos/{project}/commits/{sha}", token)
    except Exception:
        return []
    groups = []
    for item in (payload.get("files") if isinstance(payload, Mapping) else []) or []:
        if not isinstance(item, Mapping) or len(groups) >= MAX_CHANGED_TEST_GROUPS_PER_FAMILY:
            continue
        path = text(item.get("filename"))
        if not path or not TEST_PATH.search(path):
            continue
        raw = file_bytes(project, path, sha, token)
        controls = test_controls(raw)
        if not controls:
            continue
        groups.append({
            "path": path,
            "commit_sha": sha,
            "html_url": text(item.get("blob_url")),
            "file_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
            "controls": controls,
            "discovery_basis": "changed_test_file_in_frozen_same_source_candidate",
            "semantic_role": "unadjudicated_fourth_pass_upstream_test_control_candidate",
        })
    return groups


def lexical_code_controls(project: str, branch: str, terms: list[str], token: str) -> list[dict[str, Any]]:
    if not branch:
        return []
    results = []
    seen_paths = set()
    for term in terms[:MAX_LEXICAL_TERMS]:
        query = urllib.parse.quote(f"{term} repo:{project}", safe="")
        try:
            payload = api(f"https://api.github.com/search/code?q={query}&per_page={MAX_CODE_RESULTS_PER_TERM}", token)
        except Exception:
            time.sleep(SEARCH_SLEEP_SECONDS)
            continue
        for item in (payload.get("items") if isinstance(payload, Mapping) else []) or []:
            if not isinstance(item, Mapping) or len(results) >= MAX_CURRENT_TEST_FILES_PER_FAMILY:
                continue
            path = text(item.get("path"))
            if not path or path in seen_paths or not TEST_PATH.search(path):
                continue
            raw = file_bytes(project, path, branch, token)
            if raw is None:
                continue
            source = raw.decode("utf-8", errors="replace")
            if term.casefold() not in source.casefold():
                continue
            controls = test_controls(raw)
            if not controls:
                continue
            seen_paths.add(path)
            results.append({
                "path": path,
                "ref": branch,
                "html_url": text(item.get("html_url")),
                "matched_term": term,
                "file_sha256": hashlib.sha256(raw).hexdigest(),
                "controls": controls,
                "discovery_basis": "lexical_current_test_search_in_frozen_same_source",
                "semantic_role": "unadjudicated_fourth_pass_upstream_test_control_candidate",
            })
        time.sleep(SEARCH_SLEEP_SECONDS)
    return results


def main() -> int:
    freeze = assert_capture_source_freeze()
    resolution = load(RESOLUTION)
    deep = load(THIRD_DEEP)
    capture = load(THIRD_CAPTURE)
    packets = load(PACKETS)
    for doc in (resolution, deep, capture, packets):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 fourth-pass input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 fourth-pass requires unconsumed pre-scoring inputs")
    if resolution.get("still_unresolved_count") != 21 or resolution.get("families_still_unresolved") != 17:
        raise RuntimeError("V7 fourth-pass unresolved input coverage drift")
    if resolution.get("candidate_semantics_adjudicated") is not False or resolution.get("evidence_published") is not False:
        raise RuntimeError("V7 fourth-pass input unexpectedly adjudicated/published")

    unresolved = [
        x for x in resolution.get("items") or []
        if isinstance(x, Mapping) and x.get("resolution_status") == "still_unresolved_after_third_pass"
    ]
    if len(unresolved) != 21:
        raise RuntimeError("V7 fourth-pass unresolved row count drift")
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in unresolved:
        grouped[text(item.get("family"))].append(item)
    if len(grouped) != 17:
        raise RuntimeError("V7 fourth-pass unresolved family grouping drift")

    deep_by = {text(x.get("family")): x for x in deep.get("families") or [] if isinstance(x, Mapping)}
    capture_by = {text(x.get("family")): x for x in capture.get("families") or [] if isinstance(x, Mapping)}
    packet_by = {text(x.get("family")): x for x in packets.get("packets") or [] if isinstance(x, Mapping)}
    token = os.environ.get("GITHUB_TOKEN", "")
    families = []

    for family in sorted(grouped):
        items = grouped[family]
        root = text(items[0].get("source_root"))
        project = text(items[0].get("source_project"))
        if any(text(x.get("source_root")) != root or text(x.get("source_project")).casefold() != project.casefold() for x in items):
            raise RuntimeError(f"{family}: frozen source identity drift")
        deep_row = deep_by.get(family, {})
        capture_row = capture_by.get(family, {})
        packet = packet_by.get(family, {})
        kinds = sorted({text(x.get("case_kind")) for x in items})

        captured_shas = {
            text(x.get("fix_sha"))
            for x in capture_row.get("literal_pair_candidates") or []
            if isinstance(x, Mapping) and text(x.get("fix_sha"))
        }
        remaining = [
            x for x in deep_row.get("revision_candidates") or []
            if isinstance(x, Mapping) and text(x.get("commit_sha")) not in captured_shas
        ]
        remaining = sorted(remaining, key=priority)

        literal_pairs = []
        if "positive" in kinds or "secure_negative" in kinds:
            literal_pairs = [
                capture_pair(project, candidate, token)
                for candidate in remaining[:MAX_REMAINING_PAIRS_PER_FAMILY]
            ]

        control_groups: list[dict[str, Any]] = []
        if "near_miss" in kinds:
            for candidate in remaining + [x for x in deep_row.get("revision_candidates") or [] if isinstance(x, Mapping)]:
                for group in changed_test_controls(project, candidate, token):
                    key = (text(group.get("path")), text(group.get("commit_sha")))
                    if key not in {(text(x.get("path")), text(x.get("commit_sha"))) for x in control_groups}:
                        control_groups.append(group)
                    if len(control_groups) >= MAX_CHANGED_TEST_GROUPS_PER_FAMILY:
                        break
                if len(control_groups) >= MAX_CHANGED_TEST_GROUPS_PER_FAMILY:
                    break
            if len(control_groups) < MAX_CHANGED_TEST_GROUPS_PER_FAMILY:
                branch = default_branch(project, token)
                terms = lexical_terms(packet, family)
                for group in lexical_code_controls(project, branch, terms, token):
                    key = (text(group.get("path")), text(group.get("ref")))
                    if key not in {(text(x.get("path")), text(x.get("ref"))) for x in control_groups}:
                        control_groups.append(group)
                    if len(control_groups) >= MAX_CHANGED_TEST_GROUPS_PER_FAMILY:
                        break
            else:
                branch = None
                terms = lexical_terms(packet, family)
        else:
            branch = None
            terms = []

        families.append({
            "family": family,
            "source_root": root,
            "source_project": project,
            "unresolved_case_kinds": kinds,
            "remaining_revision_candidate_count": len(remaining),
            "literal_pair_candidates": literal_pairs,
            "literal_pair_candidate_count": len(literal_pairs),
            "two_sided_literal_pair_count": sum(bool(x.get("two_sided_literal_pair")) for x in literal_pairs),
            "near_miss_search_terms": terms,
            "near_miss_default_branch": branch,
            "test_control_candidates": control_groups,
            "test_control_candidate_group_count": len(control_groups),
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
        "evaluation_kind": "fresh_blind_v7_engine_unseen_fourth_pass_targeted_candidate_inventory_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "unresolved_input_count": 21,
        "unresolved_family_count": 17,
        "family_result_count": len(families),
        "literal_pair_candidate_count": sum(x["literal_pair_candidate_count"] for x in families),
        "two_sided_literal_pair_count": sum(x["two_sided_literal_pair_count"] for x in families),
        "families_with_two_sided_literal_pairs": sum(x["two_sided_literal_pair_count"] > 0 for x in families),
        "test_control_candidate_group_count": sum(x["test_control_candidate_group_count"] for x in families),
        "families_with_test_control_candidates": sum(x["test_control_candidate_group_count"] > 0 for x in families),
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
