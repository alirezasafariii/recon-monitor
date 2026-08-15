from __future__ import annotations

"""Bounded third-pass acquisition for only the still-unresolved Fresh Blind V7 items.

The collector is candidate-only and pre-scoring. It may inspect only public GitHub
material from the already frozen project/root. It never replaces sources, mutates a
variant, executes third-party code, contacts a target, publishes evidence, or assigns
semantic labels.
"""

import base64
import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.third-pass.deep.1"
RESOLUTION = ROOT / "benchmarks/raw/sources/v7_second_pass_resolution_queue.json"
SECOND = ROOT / "benchmarks/raw/sources/v7_second_pass_literal_candidates.json"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
PACKETS = ROOT / "benchmarks/raw/sources/v7_semantic_review_packets.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_third_pass_deep_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_third_pass_deep_candidates_report.json"

TEST_PATH = re.compile(r"(^|/)(tests?|specs?|__tests__)(/|$)|[^/]*(test|spec)[._-]", re.I)
DOC_PATH = re.compile(r"(^|/)(docs?|documentation)(/|$)|(^|/)(readme|changelog|changes|upgrade|history)([._-]|$)|\.(md|rst|txt)$", re.I)
SECURITY_WORDS = re.compile(r"\b(security|vuln|vulnerability|auth|authorization|permission|sanitize|validate|escape|reject|deny|forbid|csrf|xss|sqli|injection|traversal|redirect|ssrf|idor|secret|token|upload)\b", re.I)
MAX_BODY = 2_000_000
MAX_WINDOW_COMMITS = 50
MAX_COMPARE_COMMITS = 24
MAX_COMMIT_CANDIDATES_PER_FAMILY = 14
MAX_CODE_SEARCH_TERMS = 2
MAX_CODE_RESULTS_PER_TERM = 6
MAX_TEST_BYTES = 1_500_000
MAX_TEST_SNIPPETS_PER_FILE = 4
MAX_TEST_FILES_PER_FAMILY = 8
SEARCH_SLEEP_SECONDS = 2.1


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def api(url: str, token: str) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-633-v7-third-pass",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise RuntimeError("GitHub response exceeds bounded third-pass limit")
        return json.loads(raw.decode("utf-8"))


def repo_api(project: str, suffix: str, token: str) -> Any:
    return api(f"https://api.github.com/repos/{project}/{suffix.lstrip('/')}", token)


def parse_time(value: Any) -> datetime | None:
    value = text(value)
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def significant_terms(packet: Mapping[str, Any], family: str) -> list[str]:
    values: list[str] = []
    for key in ("blocking_controls_vocabulary", "condition_signals_vocabulary", "override_signals_vocabulary"):
        for value in packet.get(key) or []:
            value = text(value).strip('"\'')
            if value:
                values.append(value)
    values.extend(part for part in family.replace("_", " ").split() if len(part) >= 4)
    stop = {"with", "without", "from", "that", "this", "request", "response", "control", "condition", "signal", "value", "user", "data"}
    out: list[str] = []
    for raw in values:
        words = [x for x in re.findall(r"[A-Za-z0-9_.-]+", raw) if len(x) >= 4 and x.casefold() not in stop]
        candidate = " ".join(words[:4]).strip()
        if not candidate:
            continue
        if candidate.casefold() not in {x.casefold() for x in out}:
            out.append(candidate)
    return out[:8]


def identifiers(research: Mapping[str, Any], root: str) -> list[str]:
    snapshot = research.get("snapshot_payload") if isinstance(research.get("snapshot_payload"), Mapping) else {}
    values = [root, text(snapshot.get("ghsa_id")), text(snapshot.get("cve_id"))]
    for item in snapshot.get("identifiers") or []:
        if isinstance(item, Mapping):
            values.append(text(item.get("value")))
    out = []
    for value in values:
        value = value.upper()
        if (value.startswith("GHSA-") or value.startswith("CVE-")) and value not in out:
            out.append(value)
    return out[:4]


def commit_detail(project: str, sha: str, token: str, basis: str, terms: list[str], ids: list[str]) -> dict[str, Any] | None:
    try:
        payload = repo_api(project, f"commits/{sha}", token)
    except Exception:
        return None
    if not isinstance(payload, Mapping) or not text(payload.get("sha")):
        return None
    parents = [text(x.get("sha")) for x in payload.get("parents") or [] if isinstance(x, Mapping) and text(x.get("sha"))]
    message = text((payload.get("commit") or {}).get("message") if isinstance(payload.get("commit"), Mapping) else "")[:1200]
    files = []
    for item in payload.get("files") or []:
        if not isinstance(item, Mapping):
            continue
        path = text(item.get("filename"))
        patch = text(item.get("patch"))
        files.append({
            "filename": path,
            "status": text(item.get("status")),
            "documentation_path": bool(DOC_PATH.search(path)),
            "test_path": bool(TEST_PATH.search(path)),
            "patch_sha256": hashlib.sha256(patch.encode()).hexdigest() if patch else None,
        })
    source_files = [x for x in files if not x["documentation_path"]]
    haystack = message.casefold()
    matched_terms = [term for term in terms if term.casefold() in haystack]
    matched_ids = [ident for ident in ids if ident.casefold() in haystack]
    return {
        "commit_sha": text(payload.get("sha")),
        "parent_shas": parents,
        "single_parent_pair_candidate": len(parents) == 1,
        "message": message,
        "html_url": text(payload.get("html_url")),
        "basis": basis,
        "file_count": len(files),
        "source_code_file_count": len(source_files),
        "changed_test_file_count": sum(bool(x["test_path"]) for x in files),
        "matched_terms": matched_terms,
        "matched_identifiers": matched_ids,
        "security_word_match": bool(SECURITY_WORDS.search(message)),
        "files": files,
        "semantic_role": "unadjudicated_third_pass_revision_candidate",
    }


def compare_commit_shas(project: str, old_sha: str, new_sha: str, token: str) -> list[str]:
    if not old_sha or not new_sha:
        return []
    comparison = urllib.parse.quote(f"{old_sha}...{new_sha}", safe=".-_~")
    try:
        payload = repo_api(project, f"compare/{comparison}", token)
    except Exception:
        return []
    if not isinstance(payload, Mapping):
        return []
    shas = [text(x.get("sha")) for x in payload.get("commits") or [] if isinstance(x, Mapping) and text(x.get("sha"))]
    return shas[:MAX_COMPARE_COMMITS]


def date_window_shas(project: str, research: Mapping[str, Any], token: str) -> list[str]:
    snapshot = research.get("snapshot_payload") if isinstance(research.get("snapshot_payload"), Mapping) else {}
    anchor = parse_time(snapshot.get("published_at")) or parse_time(snapshot.get("updated_at"))
    if anchor is None:
        return []
    since = (anchor - timedelta(days=120)).isoformat().replace("+00:00", "Z")
    until = (anchor + timedelta(days=30)).isoformat().replace("+00:00", "Z")
    suffix = f"commits?since={urllib.parse.quote(since)}&until={urllib.parse.quote(until)}&per_page={MAX_WINDOW_COMMITS}"
    try:
        payload = repo_api(project, suffix, token)
    except Exception:
        return []
    if not isinstance(payload, list):
        return []
    return [text(x.get("sha")) for x in payload if isinstance(x, Mapping) and text(x.get("sha"))][:MAX_WINDOW_COMMITS]


def default_branch(project: str, token: str) -> str:
    try:
        payload = api(f"https://api.github.com/repos/{project}", token)
        return text(payload.get("default_branch")) if isinstance(payload, Mapping) else ""
    except Exception:
        return ""


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


def matched_snippets(raw: bytes, term: str) -> list[dict[str, Any]]:
    source = raw.decode("utf-8", errors="replace")
    lines = source.splitlines()
    needle = term.casefold()
    results = []
    for index, line in enumerate(lines):
        if needle not in line.casefold():
            continue
        lo = max(0, index - 6)
        hi = min(len(lines), index + 9)
        body = "\n".join(lines[lo:hi])[:2200]
        results.append({
            "line_start": lo + 1,
            "line_end": hi,
            "matched_term": term,
            "text": body,
            "text_sha256": hashlib.sha256(body.encode()).hexdigest(),
        })
        if len(results) >= MAX_TEST_SNIPPETS_PER_FILE:
            break
    return results


def search_test_controls(project: str, branch: str, terms: list[str], token: str) -> list[dict[str, Any]]:
    if not branch:
        return []
    results = []
    seen_paths = set()
    for term in terms[:MAX_CODE_SEARCH_TERMS]:
        query = urllib.parse.quote(f'"{term}" repo:{project}', safe="")
        try:
            payload = api(f"https://api.github.com/search/code?q={query}&per_page={MAX_CODE_RESULTS_PER_TERM}", token)
        except Exception:
            time.sleep(SEARCH_SLEEP_SECONDS)
            continue
        for item in (payload.get("items") if isinstance(payload, Mapping) else []) or []:
            if not isinstance(item, Mapping):
                continue
            path = text(item.get("path"))
            if not path or path in seen_paths or not TEST_PATH.search(path) or len(results) >= MAX_TEST_FILES_PER_FAMILY:
                continue
            raw = file_bytes(project, path, branch, token)
            if raw is None:
                continue
            snippets = matched_snippets(raw, term)
            if not snippets:
                continue
            seen_paths.add(path)
            results.append({
                "path": path,
                "ref": branch,
                "html_url": text(item.get("html_url")),
                "search_term": term,
                "file_sha256": hashlib.sha256(raw).hexdigest(),
                "snippets": snippets,
                "semantic_role": "unadjudicated_same_project_test_control_candidate",
            })
        time.sleep(SEARCH_SLEEP_SECONDS)
    return results


def main() -> int:
    freeze = assert_capture_source_freeze()
    resolution = load(RESOLUTION)
    second = load(SECOND)
    research = load(RESEARCH)
    packets = load(PACKETS)
    for doc in (resolution, second, research, packets):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 third-pass input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 third-pass requires unconsumed pre-scoring inputs")
    if resolution.get("still_unresolved_count") != 39 or resolution.get("families_still_unresolved") != 21:
        raise RuntimeError("V7 third-pass unresolved input coverage drift")
    if resolution.get("candidate_semantics_adjudicated") is not False or resolution.get("evidence_published") is not False:
        raise RuntimeError("V7 third-pass input unexpectedly adjudicated/published")

    unresolved = [
        x for x in resolution.get("items") or []
        if isinstance(x, Mapping) and x.get("resolution_status") == "still_unresolved_after_second_pass"
    ]
    if len(unresolved) != 39:
        raise RuntimeError("V7 third-pass unresolved row count drift")
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in unresolved:
        grouped[text(item.get("family"))].append(item)
    if len(grouped) != 21:
        raise RuntimeError("V7 third-pass unresolved family count drift")

    second_by = {text(x.get("family")): x for x in second.get("families") or [] if isinstance(x, Mapping)}
    research_by = {text(x.get("family")): x for x in research.get("entries") or [] if isinstance(x, Mapping)}
    packet_by = {text(x.get("family")): x for x in packets.get("packets") or [] if isinstance(x, Mapping)}
    token = os.environ.get("GITHUB_TOKEN", "")
    family_rows = []

    for family in sorted(grouped):
        items = grouped[family]
        root = text(items[0].get("source_root"))
        project = text(items[0].get("source_project"))
        if any(text(x.get("source_root")) != root or text(x.get("source_project")).casefold() != project.casefold() for x in items):
            raise RuntimeError(f"{family}: frozen source identity drift across unresolved items")
        second_row = second_by.get(family, {})
        research_row = research_by.get(family, {})
        packet = packet_by.get(family, {})
        terms = significant_terms(packet, family)
        ids = identifiers(research_row, root)
        existing_shas = {
            text(x.get("commit_sha"))
            for x in second_row.get("revision_candidates") or []
            if isinstance(x, Mapping) and text(x.get("commit_sha"))
        }

        candidate_basis: dict[str, set[str]] = defaultdict(set)
        for boundary in second_row.get("version_tag_candidates") or []:
            if not isinstance(boundary, Mapping):
                continue
            old_sha = text(boundary.get("adjacent_older_tag_commit_sha"))
            new_sha = text(boundary.get("patched_tag_commit_sha"))
            for sha in compare_commit_shas(project, old_sha, new_sha, token):
                if sha not in existing_shas:
                    candidate_basis[sha].add("release_range_commit")

        for sha in date_window_shas(project, research_row, token):
            if sha not in existing_shas:
                candidate_basis[sha].add("advisory_date_window")

        revision_candidates = []
        for sha in list(candidate_basis)[:MAX_WINDOW_COMMITS]:
            row = commit_detail(project, sha, token, "+".join(sorted(candidate_basis[sha])), terms, ids)
            if row is None or not row.get("single_parent_pair_candidate") or int(row.get("source_code_file_count") or 0) <= 0:
                continue
            # Date-window candidates must have a semantic breadcrumb; release-range
            # candidates may remain broader because their ancestry is already bounded.
            if "advisory_date_window" in candidate_basis[sha] and "release_range_commit" not in candidate_basis[sha]:
                if not row.get("matched_terms") and not row.get("matched_identifiers") and not row.get("security_word_match"):
                    continue
            revision_candidates.append(row)
            if len(revision_candidates) >= MAX_COMMIT_CANDIDATES_PER_FAMILY:
                break

        unresolved_kinds = sorted({text(x.get("case_kind")) for x in items})
        branch = default_branch(project, token) if "near_miss" in unresolved_kinds else ""
        test_candidates = search_test_controls(project, branch, terms, token) if "near_miss" in unresolved_kinds else []

        family_rows.append({
            "family": family,
            "source_root": root,
            "source_project": project,
            "unresolved_case_kinds": unresolved_kinds,
            "unresolved_item_count": len(items),
            "search_terms": terms,
            "identifiers": ids,
            "default_branch": branch or None,
            "revision_candidates": revision_candidates,
            "revision_candidate_count": len(revision_candidates),
            "test_control_candidates": test_candidates,
            "test_control_candidate_count": len(test_candidates),
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
        "evaluation_kind": "fresh_blind_v7_engine_unseen_third_pass_deep_candidate_inventory_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "unresolved_input_count": 39,
        "unresolved_family_count": 21,
        "family_result_count": len(family_rows),
        "revision_candidate_count": sum(x["revision_candidate_count"] for x in family_rows),
        "families_with_revision_candidates": sum(x["revision_candidate_count"] > 0 for x in family_rows),
        "test_control_candidate_count": sum(x["test_control_candidate_count"] for x in family_rows),
        "families_with_test_control_candidates": sum(x["test_control_candidate_count"] > 0 for x in family_rows),
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
    document["families"] = family_rows
    document["candidate_inventory_sha256"] = sha_json(family_rows)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
