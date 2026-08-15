from __future__ import annotations

"""Capture bounded public-source neighborhoods for exact Fresh Blind V7 revision pairs.

This collector is evidence-only. It reads public GitHub repository content for the
already frozen 36-source assignment, never executes third-party code, never contacts
a target, never runs Analysis, and never creates a benchmark label.
"""

import base64
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "2.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.snippet.1"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
BOUNDARY = ROOT / "benchmarks/raw/sources/v7_boundary_evidence.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_unseen_source_snippet_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_unseen_source_snippet_candidates_report.json"
HUNK_RE = re.compile(r"@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")
TEST_PATH = re.compile(r"(^|/)(tests?|specs?|__tests__)(/|$)|[^/]*(test|spec)[._-]", re.I)
TEST_DEF = re.compile(r"(?m)^\s*(?:def\s+test_[A-Za-z0-9_]+|(?:it|test|describe)\s*\([^\n]{0,180}|func\s+Test[A-Za-z0-9_]+|#\[test\]|(?:async\s+)?function\s+test[A-Za-z0-9_]+)")
CONTROL_WORDS = re.compile(r"\b(valid|safe|normal|benign|reject|deny|block|invalid|unauthori[sz]ed|forbid|without|missing|empty|allowed|legitimate|patched|escape|sanitize)\b", re.I)
MAX_FILE = 2_000_000
MAX_SNIPPET = 1800


def text(v: Any) -> str:
    return str(v or "").strip()


def sha_bytes(v: bytes) -> str:
    return hashlib.sha256(v).hexdigest()


def sha_json(v: Any) -> str:
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def api(url: str, token: str) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-v7-unseen-snippet",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        return json.loads(response.read().decode())


def file_bytes(project: str, path: str, ref: str, token: str) -> bytes | None:
    encoded_path = urllib.parse.quote(path, safe="/")
    encoded_ref = urllib.parse.quote(ref, safe="")
    try:
        payload = api(f"https://api.github.com/repos/{project}/contents/{encoded_path}?ref={encoded_ref}", token)
    except Exception:
        return None
    if not isinstance(payload, Mapping) or text(payload.get("type")) != "file":
        return None
    try:
        raw = base64.b64decode(text(payload.get("content")).replace("\n", ""))
    except Exception:
        return None
    return raw if len(raw) <= MAX_FILE else None


def commit(project: str, sha: str, token: str) -> Mapping[str, Any]:
    payload = api(f"https://api.github.com/repos/{project}/commits/{sha}", token)
    if not isinstance(payload, Mapping):
        raise RuntimeError("unexpected commit payload")
    return payload


def line_snippet(raw: bytes | None, start: int, count: int = 8) -> dict[str, Any] | None:
    if raw is None:
        return None
    lines = raw.decode("utf-8", errors="replace").splitlines()
    lo = max(0, start - 4)
    hi = min(len(lines), start + max(count, 1) + 4)
    body = "\n".join(lines[lo:hi])[:MAX_SNIPPET]
    return {
        "line_start": lo + 1,
        "line_end": min(hi, len(lines)),
        "text": body,
        "text_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "file_sha256": sha_bytes(raw),
    }


def hunk_ranges(patch: str) -> list[tuple[int, int, int, int]]:
    result = []
    for match in HUNK_RE.finditer(patch or ""):
        result.append((int(match.group(1)), int(match.group(2) or 1), int(match.group(3)), int(match.group(4) or 1)))
    return result[:12]


def test_controls(raw: bytes | None) -> list[dict[str, Any]]:
    if raw is None:
        return []
    source = raw.decode("utf-8", errors="replace")
    lines = source.splitlines()
    results = []
    for match in TEST_DEF.finditer(source):
        before = source[: match.start()].count("\n")
        start = max(0, before - 1)
        body = "\n".join(lines[start : start + 28])[:MAX_SNIPPET]
        if not CONTROL_WORDS.search(body):
            continue
        results.append(
            {
                "line_start": start + 1,
                "text": body,
                "text_sha256": hashlib.sha256(body.encode()).hexdigest(),
                "control_keyword_match": sorted({x.casefold() for x in CONTROL_WORDS.findall(body)}),
            }
        )
        if len(results) >= 8:
            break
    return results


def capture_source(row: Mapping[str, Any], token: str) -> dict[str, Any]:
    family = text(row.get("family"))
    project = text(row.get("source_project"))
    root = text(row.get("source_root"))
    fix = row.get("candidate_fix_commit") if isinstance(row.get("candidate_fix_commit"), Mapping) else {}
    parent = row.get("candidate_parent_commit") if isinstance(row.get("candidate_parent_commit"), Mapping) else {}
    fix_sha = text(fix.get("sha"))
    parent_sha = text(parent.get("sha"))
    files: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    if bool(row.get("exact_revision_pair_available")) != bool(fix_sha and parent_sha):
        raise RuntimeError(f"{family}: exact revision pair flag/sha drift")

    if fix_sha and parent_sha:
        try:
            commit_payload = commit(project, fix_sha, token)
        except Exception as exc:
            commit_payload = {}
            failures.append({"stage": "fix_commit", "error": type(exc).__name__})
        for item in commit_payload.get("files") or []:
            if not isinstance(item, Mapping):
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
                parent_snippet = line_snippet(parent_raw, old_start, old_count)
                fix_snippet = line_snippet(fix_raw, new_start, new_count)
                if parent_snippet:
                    parent_snippets.append(parent_snippet)
                if fix_snippet:
                    fix_snippets.append(fix_snippet)
            controls = test_controls(fix_raw) if TEST_PATH.search(path) else []
            files.append(
                {
                    "filename": path,
                    "previous_filename": previous,
                    "status": text(item.get("status")),
                    "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
                    "parent_present": parent_raw is not None,
                    "fix_present": fix_raw is not None,
                    "parent_snippets": parent_snippets,
                    "fix_snippets": fix_snippets,
                    "upstream_test_control_candidates": controls,
                    "is_test_path": bool(TEST_PATH.search(path)),
                }
            )

    result = {
        "family": family,
        "source_root": root,
        "source_project": project,
        "fix_sha": fix_sha or None,
        "parent_sha": parent_sha or None,
        "exact_pair_available": bool(fix_sha and parent_sha),
        "files": files,
        "changed_file_count": len(files),
        "parent_snippet_count": sum(len(x["parent_snippets"]) for x in files),
        "fix_snippet_count": sum(len(x["fix_snippets"]) for x in files),
        "test_control_candidate_count": sum(len(x["upstream_test_control_candidates"]) for x in files),
        "family_literal_adjudication_required": bool(row.get("family_literal_adjudication_required")),
        "failures": failures,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "third_party_code_executed": False,
        "target_contact_performed": False,
    }
    result["source_snippet_pack_sha256"] = sha_json(result)
    return result


def main() -> int:
    freeze = assert_capture_source_freeze()
    research = json.loads(RESEARCH.read_text())
    boundary = json.loads(BOUNDARY.read_text())
    if research.get("version") != "2.2.0":
        raise RuntimeError("V7 exact-identity research version required")
    if research.get("successful_snapshot_count") != 36 or research.get("unresolved_snapshot_count") != 0:
        raise RuntimeError("V7 source research incomplete")
    if research.get("exact_frozen_root_match_count") != 36 or research.get("ghsa_alias_resolution_count") != 0:
        raise RuntimeError("V7 source identity freeze not exact")
    if research.get("source_assignment_commit") != freeze["source_assignment_commit"]:
        raise RuntimeError("V7 source research assignment drift")
    if boundary.get("source_count") != 36 or boundary.get("source_assignment_commit") != freeze["source_assignment_commit"]:
        raise RuntimeError("V7 boundary assignment drift")
    for field in ("scoring_executed", "first_blind_consumed", "target_contact_performed"):
        if boundary.get(field) is not False:
            raise RuntimeError(f"V7 boundary pre-scoring contract violated: {field}")

    rows = [x for x in boundary.get("sources") or [] if isinstance(x, Mapping)]
    if len(rows) != 36:
        raise RuntimeError(f"boundary source count {len(rows)} != 36")
    token = os.environ.get("GITHUB_TOKEN", "")
    packs = [capture_source(x, token) for x in rows]
    exact_pairs = sum(bool(x["exact_pair_available"]) for x in packs)
    if exact_pairs != int(boundary.get("exact_revision_pair_count") or -1):
        raise RuntimeError("exact pair count drift between boundary and snippet capture")

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_exact_source_snippet_candidate_capture",
        "source_count": 36,
        "exact_pair_source_count": exact_pairs,
        "sources_with_parent_snippets": sum(x["parent_snippet_count"] > 0 for x in packs),
        "sources_with_fix_snippets": sum(x["fix_snippet_count"] > 0 for x in packs),
        "sources_with_test_control_candidates": sum(x["test_control_candidate_count"] > 0 for x in packs),
        "parent_snippet_count": sum(x["parent_snippet_count"] for x in packs),
        "fix_snippet_count": sum(x["fix_snippet_count"] for x in packs),
        "test_control_candidate_count": sum(x["test_control_candidate_count"] for x in packs),
        "literal_adjudication_required_count": sum(bool(x["family_literal_adjudication_required"]) for x in packs),
        "failure_count": sum(len(x["failures"]) for x in packs),
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
        "scoring_executed": False,
        "first_blind_consumed": False,
        "third_party_code_executed": False,
        "target_contact_performed": False,
    }
    output = dict(report)
    output["sources"] = packs
    output["capture_set_sha256"] = sha_json(packs)
    OUTPUT.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
