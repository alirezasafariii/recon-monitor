from __future__ import annotations

"""Source-specific fifth-pass acquisition for the 18 remaining V7 gaps.

Two families without direct revision candidates get same-repo release/tag boundary
research. Near-miss gaps get adjacent upstream test-case candidates linked to the
security-change module or source-specific advisory identifiers. Everything remains
candidate-only, source-locked, and pre-scoring.
"""

import hashlib
import json
import os
import re
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze
from v7_second_pass_source_capture import capture_compare_pair
from v7_third_pass_source_capture import TEST_PATH
from v7_unseen_source_snippet_capture import TEST_DEF, api, file_bytes

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.fifth-pass.source-specific.1"
RESIDUAL = ROOT / "benchmarks/raw/sources/v7_residual_unresolved_worklist.json"
BOUNDARY = ROOT / "benchmarks/raw/sources/v7_boundary_evidence.json"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
THIRD_DEEP = ROOT / "benchmarks/raw/sources/v7_third_pass_deep_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_fifth_pass_source_specific_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_fifth_pass_source_specific_candidates_report.json"

MAX_TAG_PAGES = 2
MAX_TAGS_PER_PAGE = 100
MAX_RELEASE_BOUNDARIES_PER_FAMILY = 3
MAX_SEARCH_TERMS = 4
MAX_CODE_RESULTS = 8
MAX_TEST_FILES_PER_FAMILY = 10
MAX_TEST_CASES_PER_FILE = 8
MAX_FILE_BYTES = 1_500_000
SEARCH_SLEEP_SECONDS = 1.6
SEMVER_RE = re.compile(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?(?!\d)")
BACKTICK_RE = re.compile(r"`([^`\n]{3,100})`")
IDENT_RE = re.compile(r"\b(?:[A-Z][A-Za-z0-9]{5,}|[A-Za-z][A-Za-z0-9]+(?:_[A-Za-z0-9]+){1,}|[A-Za-z][A-Za-z0-9]+(?:\.[A-Za-z0-9]+){1,})\b")
TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{3,}")
STOP = {
    "security", "vulnerability", "affected", "version", "versions", "patched", "package",
    "request", "response", "allows", "could", "would", "user", "users", "data", "access",
    "issue", "advisory", "github", "attack", "attacker", "application", "function", "method",
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


def semver(value: str) -> tuple[int, int, int] | None:
    match = SEMVER_RE.search(text(value))
    return tuple(int(match.group(i)) for i in (1, 2, 3)) if match else None


def list_tags(project: str, token: str) -> list[dict[str, Any]]:
    rows = []
    for page in range(1, MAX_TAG_PAGES + 1):
        try:
            payload = api(
                f"https://api.github.com/repos/{project}/tags?per_page={MAX_TAGS_PER_PAGE}&page={page}",
                token,
            )
        except Exception:
            break
        if not isinstance(payload, list):
            break
        for item in payload:
            if not isinstance(item, Mapping):
                continue
            commit = item.get("commit") if isinstance(item.get("commit"), Mapping) else {}
            name = text(item.get("name"))
            sha = text(commit.get("sha"))
            if name and sha:
                rows.append({"name": name, "sha": sha})
        if len(payload) < MAX_TAGS_PER_PAGE:
            break
    return rows


def release_tag_pairs(project: str, version_boundaries: list[Mapping[str, Any]], token: str) -> list[dict[str, Any]]:
    tags = list_tags(project, token)
    results = []
    for boundary in version_boundaries:
        patched = text(boundary.get("patched_version"))
        pv = semver(patched)
        if pv is None:
            continue
        candidates = [x for x in tags if semver(text(x.get("name"))) == pv]
        for patched_tag in candidates[:MAX_RELEASE_BOUNDARIES_PER_FAMILY]:
            name = text(patched_tag.get("name"))
            match = SEMVER_RE.search(name)
            prefix = name[: match.start()] if match else ""
            older = []
            for row in tags:
                rv = semver(text(row.get("name")))
                if rv is None or rv >= pv:
                    continue
                row_name = text(row.get("name"))
                row_match = SEMVER_RE.search(row_name)
                row_prefix = row_name[: row_match.start()] if row_match else ""
                if row_prefix == prefix:
                    older.append((rv, row))
            if not older:
                continue
            older.sort(reverse=True, key=lambda x: x[0])
            old = older[0][1]
            pair = capture_compare_pair(project, text(old.get("sha")), text(patched_tag.get("sha")), token)
            pair["patched_tag"] = name
            pair["adjacent_older_tag"] = old.get("name")
            pair["patched_version"] = patched
            pair["vulnerable_version_range"] = boundary.get("vulnerable_version_range")
            pair["semantic_role"] = "unadjudicated_fifth_pass_release_boundary_candidate"
            results.append(pair)
            if len(results) >= MAX_RELEASE_BOUNDARIES_PER_FAMILY:
                break
    return results


def source_specific_terms(research: Mapping[str, Any], deep: Mapping[str, Any], family: str) -> list[str]:
    values: list[str] = []
    snapshot = research.get("snapshot_payload") if isinstance(research.get("snapshot_payload"), Mapping) else {}
    blob = "\n".join(
        text(snapshot.get(key)) for key in ("summary", "description", "body") if text(snapshot.get(key))
    )
    values.extend(BACKTICK_RE.findall(blob))
    values.extend(IDENT_RE.findall(blob))
    for candidate in deep.get("revision_candidates") or []:
        if not isinstance(candidate, Mapping):
            continue
        for file_row in candidate.get("files") or []:
            if not isinstance(file_row, Mapping):
                continue
            path = text(file_row.get("filename"))
            stem = PurePosixPath(path).stem
            if stem:
                values.append(stem)
    values.extend(family.replace("_", " ").split())

    out: list[str] = []
    for value in values:
        for token in TOKEN_RE.findall(value):
            normalized = token.casefold().strip("_-")
            if len(normalized) < 4 or normalized in STOP:
                continue
            if normalized not in out:
                out.append(normalized)
    return out[:12]


def default_branch(project: str, token: str) -> str:
    try:
        payload = api(f"https://api.github.com/repos/{project}", token)
    except Exception:
        return ""
    return text(payload.get("default_branch")) if isinstance(payload, Mapping) else ""


def extract_test_cases(raw: bytes | None) -> list[dict[str, Any]]:
    if raw is None or len(raw) > MAX_FILE_BYTES:
        return []
    source = raw.decode("utf-8", errors="replace")
    lines = source.splitlines()
    results = []
    for match in TEST_DEF.finditer(source):
        line_no = source[: match.start()].count("\n")
        lo = max(0, line_no - 1)
        hi = min(len(lines), lo + 34)
        body = "\n".join(lines[lo:hi])[:2600]
        results.append({
            "line_start": lo + 1,
            "line_end": hi,
            "text": body,
            "text_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "semantic_role": "unadjudicated_adjacent_upstream_test_case_candidate",
        })
        if len(results) >= MAX_TEST_CASES_PER_FILE:
            break
    return results


def search_test_cases(project: str, branch: str, terms: list[str], token: str) -> list[dict[str, Any]]:
    if not branch:
        return []
    rows = []
    seen = set()
    for term in terms[:MAX_SEARCH_TERMS]:
        query = urllib.parse.quote(f"{term} repo:{project}", safe="")
        try:
            payload = api(f"https://api.github.com/search/code?q={query}&per_page={MAX_CODE_RESULTS}", token)
        except Exception:
            time.sleep(SEARCH_SLEEP_SECONDS)
            continue
        for item in (payload.get("items") if isinstance(payload, Mapping) else []) or []:
            if not isinstance(item, Mapping) or len(rows) >= MAX_TEST_FILES_PER_FAMILY:
                continue
            path = text(item.get("path"))
            if not path or path in seen or not TEST_PATH.search(path):
                continue
            raw = file_bytes(project, path, branch, token)
            if raw is None:
                continue
            source = raw.decode("utf-8", errors="replace")
            if term.casefold() not in source.casefold():
                continue
            cases = extract_test_cases(raw)
            if len(cases) < 2:
                continue
            seen.add(path)
            rows.append({
                "path": path,
                "ref": branch,
                "html_url": text(item.get("html_url")),
                "matched_term": term,
                "file_sha256": hashlib.sha256(raw).hexdigest(),
                "test_cases": cases,
                "test_case_count": len(cases),
                "discovery_basis": "source_specific_same_project_test_case_search",
                "semantic_role": "unadjudicated_fifth_pass_adjacent_test_file_candidate",
            })
        time.sleep(SEARCH_SLEEP_SECONDS)
    return rows


def main() -> int:
    freeze = assert_capture_source_freeze()
    residual = load(RESIDUAL)
    boundary = load(BOUNDARY)
    research = load(RESEARCH)
    deep = load(THIRD_DEEP)
    for doc in (residual, boundary, research, deep):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 fifth-pass input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 fifth-pass requires unconsumed pre-scoring inputs")
    if residual.get("unresolved_item_count") != 18 or residual.get("unresolved_family_count") != 14:
        raise RuntimeError("V7 fifth-pass residual coverage drift")

    boundary_by = {text(x.get("family")): x for x in boundary.get("sources") or [] if isinstance(x, Mapping)}
    research_by = {text(x.get("family")): x for x in research.get("entries") or [] if isinstance(x, Mapping)}
    deep_by = {text(x.get("family")): x for x in deep.get("families") or [] if isinstance(x, Mapping)}
    token = os.environ.get("GITHUB_TOKEN", "")
    families = []

    for row in residual.get("families") or []:
        if not isinstance(row, Mapping):
            continue
        family = text(row.get("family"))
        project = text(row.get("source_project"))
        root = text(row.get("source_root"))
        kinds = list(row.get("unresolved_case_kinds") or [])
        boundary_row = boundary_by.get(family, {})
        research_row = research_by.get(family, {})
        deep_row = deep_by.get(family, {})

        release_pairs = []
        if "positive" in kinds or "secure_negative" in kinds:
            release_pairs = release_tag_pairs(project, list(boundary_row.get("version_boundaries") or []), token)

        test_files = []
        terms = []
        branch = None
        if "near_miss" in kinds:
            branch = default_branch(project, token)
            terms = source_specific_terms(research_row, deep_row, family)
            test_files = search_test_cases(project, branch, terms, token)

        families.append({
            "family": family,
            "source_root": root,
            "source_project": project,
            "unresolved_case_kinds": kinds,
            "release_boundary_candidates": release_pairs,
            "release_boundary_candidate_count": len(release_pairs),
            "two_sided_release_boundary_count": sum(
                int(x.get("source_code_parent_snippet_count") or 0) > 0
                and int(x.get("source_code_fix_snippet_count") or 0) > 0
                for x in release_pairs
            ),
            "source_specific_search_terms": terms,
            "default_branch": branch,
            "adjacent_test_file_candidates": test_files,
            "adjacent_test_file_candidate_count": len(test_files),
            "adjacent_test_case_candidate_count": sum(int(x.get("test_case_count") or 0) for x in test_files),
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
        "evaluation_kind": "fresh_blind_v7_engine_unseen_fifth_pass_source_specific_candidates_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "residual_input_count": 18,
        "residual_family_count": 14,
        "family_result_count": len(families),
        "release_boundary_candidate_count": sum(x["release_boundary_candidate_count"] for x in families),
        "families_with_two_sided_release_boundaries": sum(x["two_sided_release_boundary_count"] > 0 for x in families),
        "two_sided_release_boundary_count": sum(x["two_sided_release_boundary_count"] for x in families),
        "adjacent_test_file_candidate_count": sum(x["adjacent_test_file_candidate_count"] for x in families),
        "adjacent_test_case_candidate_count": sum(x["adjacent_test_case_candidate_count"] for x in families),
        "families_with_adjacent_test_candidates": sum(x["adjacent_test_file_candidate_count"] > 0 for x in families),
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
