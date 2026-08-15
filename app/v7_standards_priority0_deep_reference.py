from __future__ import annotations

"""Passive deep-reference capture for unresolved Fresh Blind V7 priority-0 mappings.

The collector follows only public GitHub references that belong to the already-frozen
source project. It never changes source identity, never contacts a target, and never
executes third-party code. WSTG/OWASP/CWE and write-up lessons guide selection only;
all retained evidence is literal upstream project/advisory text or patch material.
"""

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from researcher_logic import researcher_logic_for_family
from v7_capture_guard import assert_capture_source_freeze
from v7_standards_priority0_role_pack import role_from_heading_and_text, signal_hits

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.priority0-deep-reference.1"
GAPS = ROOT / "benchmarks/raw/sources/v7_standards_gap_worklist.json"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_standards_priority0_deep_reference.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_standards_priority0_deep_reference_report.json"
MAX_BYTES = 2 * 1024 * 1024
MAX_URLS_PER_FAMILY = 48
MAX_RECORDS_PER_FAMILY = 140
MAX_FILES_PER_COMMIT = 12
MAX_CONTENT_FETCHES_PER_FAMILY = 12
MAX_TEXT = 7000
URL_RE = re.compile(r"https://[^\s)\]>'\"]+")
TOKEN_RE = re.compile(r"[a-z0-9]+", re.I)
ALLOWED_PATH_KINDS = {"commit", "pull", "issues", "releases", "compare", "blob", "security"}
VULNERABLE_ROLES = {"vulnerable_or_impact_state", "vulnerable_parent_state"}


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def sha_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _request(url: str, token: str | None, *, accept: str = "application/vnd.github+json") -> tuple[int, Any, str | None]:
    headers = {
        "Accept": accept,
        "User-Agent": "recon-monitor-analysis-633-v7-standards-deep-reference",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=35) as response:
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                return int(response.status), None, "response too large"
            ctype = response.headers.get("Content-Type", "")
            if "json" in ctype or raw[:1] in {b"{", b"["}:
                return int(response.status), json.loads(raw.decode("utf-8")), None
            return int(response.status), raw.decode("utf-8", errors="replace"), None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:1200]
        return int(exc.code), None, f"HTTP {exc.code}: {body}"
    except Exception as exc:
        return 0, None, f"{type(exc).__name__}: {exc}"


def _same_project_url(url: str, project: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    if parsed.scheme != "https" or parsed.netloc.casefold() != "github.com":
        return False
    parts = [urllib.parse.unquote(x) for x in parsed.path.split("/") if x]
    if len(parts) < 3 or "/".join(parts[:2]).casefold() != project.casefold():
        return False
    return parts[2].casefold() in ALLOWED_PATH_KINDS


def _urls(value: Any) -> list[str]:
    out: set[str] = set()
    if isinstance(value, Mapping):
        for child in value.values():
            out.update(_urls(child))
    elif isinstance(value, list):
        for child in value:
            out.update(_urls(child))
    elif isinstance(value, str):
        if value.startswith("https://"):
            out.add(value.rstrip(".,;:"))
        for match in URL_RE.findall(value):
            out.add(match.rstrip(".,;:"))
    return sorted(out)


def _github_api(url: str, project: str) -> tuple[str, str] | None:
    parsed = urllib.parse.urlparse(url)
    parts = [urllib.parse.unquote(x) for x in parsed.path.split("/") if x]
    if len(parts) < 3 or "/".join(parts[:2]).casefold() != project.casefold():
        return None
    owner, repo, kind = parts[0], parts[1], parts[2].casefold()
    prefix = f"https://api.github.com/repos/{owner}/{repo}"
    if kind == "commit" and len(parts) >= 4:
        return "commit", f"{prefix}/commits/{urllib.parse.quote(parts[3], safe='')}"
    if kind == "pull" and len(parts) >= 4 and parts[3].isdigit():
        return "pull", f"{prefix}/pulls/{parts[3]}"
    if kind == "issues" and len(parts) >= 4 and parts[3].isdigit():
        return "issue", f"{prefix}/issues/{parts[3]}"
    if kind == "releases" and len(parts) >= 5 and parts[3] == "tag":
        tag = "/".join(parts[4:])
        return "release", f"{prefix}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    if kind == "compare" and len(parts) >= 4:
        comparison = "/".join(parts[3:])
        return "compare", f"{prefix}/compare/{urllib.parse.quote(comparison, safe='...')}"
    if kind == "blob" and len(parts) >= 5:
        ref, path = parts[3], "/".join(parts[4:])
        return "blob", f"{prefix}/contents/{urllib.parse.quote(path, safe='/')}?ref={urllib.parse.quote(ref, safe='')}"
    if kind == "security" and len(parts) >= 5 and parts[3] == "advisories":
        return "repo_advisory", f"{prefix}/security-advisories/{urllib.parse.quote(parts[4], safe='')}"
    return None


def _family_query_tokens(family: str) -> set[str]:
    spec = DETECTOR_SPECS[family]
    logic = researcher_logic_for_family(family)
    values: list[str] = []
    values.extend(spec.identity_signals)
    values.extend(spec.surface_terms)
    values.extend(spec.condition_signals)
    values.extend(spec.blocking_controls)
    for lesson in logic.get("writeup_logic") or []:
        if isinstance(lesson, Mapping):
            values.extend(text(lesson.get(k)) for k in ("lesson", "pattern", "signal", "condition", "control", "title"))
        else:
            values.append(text(lesson))
    tokens = {x.casefold() for value in values for x in TOKEN_RE.findall(value) if len(x) >= 4}
    return tokens


def _relevant(family: str, value: str) -> bool:
    hay = {x.casefold() for x in TOKEN_RE.findall(value)}
    query = _family_query_tokens(family)
    hits = hay & query
    signal = signal_hits(family, value)
    explicit = any(signal.get(k) for k in ("identity", "surface", "condition", "control", "override"))
    return explicit or len(hits) >= 2


def _record(family: str, origin: str, role: str, body: str, *, url: str, metadata: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    body = text(body)[:MAX_TEXT]
    if not body or not _relevant(family, body):
        return None
    hits = signal_hits(family, body)
    return {
        "origin": origin,
        "source_state_role": role,
        "source_url": url,
        "text": body,
        "text_sha256": sha_text(body),
        "signal_hit_counts": {key: len(value) for key, value in hits.items()},
        "signal_hits": hits,
        "metadata": dict(metadata or {}),
    }


def _patch_records(family: str, patch: str, *, url: str, filename: str, origin: str, ref_metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    removed: list[str] = []
    added: list[str] = []
    context: list[str] = []
    for line in text(patch).splitlines():
        if line.startswith(("---", "+++", "@@")):
            continue
        if line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
        elif line.startswith(" "):
            context.append(line[1:])
    rows: list[dict[str, Any]] = []
    for suffix, role, lines in (
        ("removed", "vulnerable_parent_state", removed),
        ("added", "fixed_or_remediation_state", added),
        ("context", "unclassified_source_state", context),
    ):
        body = "\n".join(lines)
        row = _record(family, f"{origin}_{suffix}", role, body, url=url, metadata={**ref_metadata, "filename": filename})
        if row:
            rows.append(row)
    return rows


def _contents_text(project: str, path: str, ref: str, token: str | None) -> tuple[str | None, str | None]:
    owner, repo = project.split("/", 1)
    api = f"https://api.github.com/repos/{owner}/{repo}/contents/{urllib.parse.quote(path, safe='/')}?ref={urllib.parse.quote(ref, safe='')}"
    status, payload, error = _request(api, token)
    if status != 200 or not isinstance(payload, Mapping) or payload.get("type") != "file":
        return None, error or f"HTTP {status}"
    encoded = payload.get("content")
    if not isinstance(encoded, str) or payload.get("encoding") != "base64":
        return None, "unsupported content encoding"
    try:
        raw = base64.b64decode(encoded, validate=False)
    except Exception as exc:
        return None, f"base64 decode failed: {exc}"
    if len(raw) > MAX_BYTES:
        return None, "file too large"
    return raw.decode("utf-8", errors="replace"), None


def _windows(family: str, value: str, *, radius: int = 12) -> list[str]:
    lines = value.splitlines()
    hit_lines = [idx for idx, line in enumerate(lines) if _relevant(family, line)]
    if not hit_lines:
        return []
    windows: list[str] = []
    seen: set[tuple[int, int]] = set()
    for idx in hit_lines[:12]:
        start, end = max(0, idx - radius), min(len(lines), idx + radius + 1)
        key = (start, end)
        if key in seen:
            continue
        seen.add(key)
        windows.append("\n".join(lines[start:end])[:MAX_TEXT])
    return windows


def _fetch_comments(comments_url: str, token: str | None) -> list[Mapping[str, Any]]:
    if not comments_url.startswith("https://api.github.com/"):
        return []
    sep = "&" if "?" in comments_url else "?"
    status, payload, _ = _request(f"{comments_url}{sep}per_page=50", token)
    if status != 200 or not isinstance(payload, list):
        return []
    return [x for x in payload if isinstance(x, Mapping)]


def _extract_records(family: str, project: str, source_url: str, kind: str, payload: Any, token: str | None, content_budget: list[int]) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    discovered = [u for u in _urls(payload) if _same_project_url(u, project)]
    if not isinstance(payload, Mapping):
        if isinstance(payload, str):
            row = _record(family, f"deep_{kind}", role_from_heading_and_text("", payload), payload, url=source_url)
            if row:
                rows.append(row)
        return rows, discovered

    common = {"html_url": payload.get("html_url"), "api_url": payload.get("url")}
    if kind == "commit":
        commit = payload.get("commit") if isinstance(payload.get("commit"), Mapping) else {}
        message = text(commit.get("message"))
        row = _record(family, "deep_commit_message", role_from_heading_and_text("", message), message, url=source_url, metadata=common)
        if row:
            rows.append(row)
        sha = text(payload.get("sha"))
        parents = payload.get("parents") or []
        parent_sha = text(parents[0].get("sha")) if parents and isinstance(parents[0], Mapping) else ""
        for file_row in (payload.get("files") or [])[:MAX_FILES_PER_COMMIT]:
            if not isinstance(file_row, Mapping):
                continue
            filename = text(file_row.get("filename"))
            patch = text(file_row.get("patch"))
            meta = {**common, "commit_sha": sha, "parent_sha": parent_sha, "status": file_row.get("status")}
            if patch:
                rows.extend(_patch_records(family, patch, url=source_url, filename=filename, origin="deep_commit_patch", ref_metadata=meta))
            if filename and content_budget[0] < MAX_CONTENT_FETCHES_PER_FAMILY and (_relevant(family, filename) or _relevant(family, patch)):
                for ref, role, origin in ((parent_sha, "vulnerable_parent_state", "deep_parent_file_window"), (sha, "fixed_or_remediation_state", "deep_fix_file_window")):
                    if not ref or content_budget[0] >= MAX_CONTENT_FETCHES_PER_FAMILY:
                        continue
                    content_budget[0] += 1
                    file_text, _ = _contents_text(project, filename, ref, token)
                    if file_text:
                        for window in _windows(family, file_text):
                            rec = _record(family, origin, role, window, url=source_url, metadata={**meta, "filename": filename, "ref": ref})
                            if rec:
                                rows.append(rec)
    elif kind == "pull":
        for field in ("title", "body"):
            value = text(payload.get(field))
            rec = _record(family, f"deep_pull_{field}", role_from_heading_and_text(field, value), value, url=source_url, metadata=common)
            if rec:
                rows.append(rec)
        files_url = text(payload.get("url")) + "/files?per_page=100" if text(payload.get("url")) else ""
        if files_url:
            status, files, _ = _request(files_url, token)
            if status == 200 and isinstance(files, list):
                for file_row in files[:MAX_FILES_PER_COMMIT]:
                    if isinstance(file_row, Mapping) and text(file_row.get("patch")):
                        rows.extend(_patch_records(family, text(file_row.get("patch")), url=source_url, filename=text(file_row.get("filename")), origin="deep_pull_patch", ref_metadata=common))
    elif kind == "issue":
        for field in ("title", "body"):
            value = text(payload.get(field))
            rec = _record(family, f"deep_issue_{field}", role_from_heading_and_text(field, value), value, url=source_url, metadata=common)
            if rec:
                rows.append(rec)
        for comment in _fetch_comments(text(payload.get("comments_url")), token):
            value = text(comment.get("body"))
            rec = _record(family, "deep_issue_comment", role_from_heading_and_text("", value), value, url=source_url, metadata={"comment_url": comment.get("html_url")})
            if rec:
                rows.append(rec)
            discovered.extend(u for u in _urls(comment) if _same_project_url(u, project))
    elif kind == "release":
        for field in ("name", "body"):
            value = text(payload.get(field))
            rec = _record(family, f"deep_release_{field}", role_from_heading_and_text(field, value), value, url=source_url, metadata={**common, "tag_name": payload.get("tag_name")})
            if rec:
                rows.append(rec)
    elif kind == "compare":
        for commit_row in (payload.get("commits") or [])[:20]:
            if not isinstance(commit_row, Mapping):
                continue
            commit = commit_row.get("commit") if isinstance(commit_row.get("commit"), Mapping) else {}
            value = text(commit.get("message"))
            rec = _record(family, "deep_compare_commit_message", role_from_heading_and_text("", value), value, url=source_url, metadata={"sha": commit_row.get("sha")})
            if rec:
                rows.append(rec)
        for file_row in (payload.get("files") or [])[:MAX_FILES_PER_COMMIT]:
            if isinstance(file_row, Mapping) and text(file_row.get("patch")):
                rows.extend(_patch_records(family, text(file_row.get("patch")), url=source_url, filename=text(file_row.get("filename")), origin="deep_compare_patch", ref_metadata=common))
    elif kind == "blob":
        encoded = payload.get("content")
        if isinstance(encoded, str) and payload.get("encoding") == "base64":
            try:
                decoded = base64.b64decode(encoded, validate=False).decode("utf-8", errors="replace")
            except Exception:
                decoded = ""
            for window in _windows(family, decoded):
                rec = _record(family, "deep_blob_window", "unclassified_source_state", window, url=source_url, metadata=common)
                if rec:
                    rows.append(rec)
    elif kind == "repo_advisory":
        for field in ("summary", "description"):
            value = text(payload.get(field))
            rec = _record(family, f"deep_repo_advisory_{field}", role_from_heading_and_text(field, value), value, url=source_url, metadata=common)
            if rec:
                rows.append(rec)
    return rows, discovered


def _seed_urls(entry: Mapping[str, Any], project: str) -> list[str]:
    candidates: set[str] = set()
    for value in entry.get("discovered_upstream_links") or []:
        if isinstance(value, str):
            candidates.add(value)
    candidates.update(_urls(entry.get("snapshot_payload")))
    canonical = text(entry.get("canonical_reference"))
    if canonical:
        candidates.add(canonical)
    return sorted(u for u in candidates if _same_project_url(u, project))


def build(token: str | None = None) -> dict[str, Any]:
    freeze = assert_capture_source_freeze()
    gaps, research = load(GAPS), load(RESEARCH)
    for doc, name in ((gaps, "gaps"), (research, "research")):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError(f"V7 deep-reference {name} source assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError(f"V7 deep-reference requires unconsumed {name}")
    priority = [row for row in gaps.get("worklist") or [] if isinstance(row, Mapping) and row.get("priority") == 0]
    if not priority:
        raise RuntimeError("V7 deep-reference has no unresolved priority-0 mappings")
    research_by = {text(row.get("family")): row for row in research.get("entries") or [] if isinstance(row, Mapping)}

    families: list[dict[str, Any]] = []
    role_counts: Counter[str] = Counter()
    fetch_counts: Counter[str] = Counter()
    for gap in sorted(priority, key=lambda row: text(row.get("family"))):
        family = text(gap.get("family"))
        entry = research_by.get(family)
        if not entry:
            raise RuntimeError(f"{family}: missing frozen source research")
        project = text(entry.get("source_project"))
        if not re.fullmatch(r"[^/]+/[^/]+", project):
            raise RuntimeError(f"{family}: invalid frozen source project {project!r}")
        queue = deque((url, 0) for url in _seed_urls(entry, project))
        visited: set[str] = set()
        records: list[dict[str, Any]] = []
        fetches: list[dict[str, Any]] = []
        content_budget = [0]
        while queue and len(visited) < MAX_URLS_PER_FAMILY:
            url, depth = queue.popleft()
            if url in visited or not _same_project_url(url, project):
                continue
            visited.add(url)
            mapping = _github_api(url, project)
            if not mapping:
                continue
            kind, api = mapping
            status, payload, error = _request(api, token)
            if status == 403 and token:
                status, payload, error = _request(api, None)
            fetch_counts[str(status)] += 1
            fetches.append({"url": url, "kind": kind, "api": api, "status": status, "error": error, "payload_sha256": sha_json(payload) if payload is not None else None})
            if status != 200 or payload is None:
                continue
            new_records, discovered = _extract_records(family, project, url, kind, payload, token, content_budget)
            records.extend(new_records)
            if depth < 1:
                for candidate in discovered:
                    if candidate not in visited and _same_project_url(candidate, project):
                        queue.append((candidate, depth + 1))
        deduped = list({text(row.get("text_sha256")): row for row in records if text(row.get("text_sha256"))}.values())[:MAX_RECORDS_PER_FAMILY]
        vulnerable = [row for row in deduped if text(row.get("source_state_role")) in VULNERABLE_ROLES]
        condition_vulnerable = [row for row in vulnerable if int((row.get("signal_hit_counts") or {}).get("condition") or 0) > 0]
        aligned_vulnerable = [row for row in vulnerable if int((row.get("signal_hit_counts") or {}).get("identity") or 0) > 0 or int((row.get("signal_hit_counts") or {}).get("surface") or 0) > 0]
        for row in deduped:
            role_counts[text(row.get("source_state_role"))] += 1
        families.append({
            "family": family,
            "capture_id": gap.get("capture_id"),
            "source_root": entry.get("source_root"),
            "source_project": project,
            "canonical_reference": entry.get("canonical_reference"),
            "source_snapshot_sha256": entry.get("snapshot_sha256"),
            "seed_url_count": len(_seed_urls(entry, project)),
            "visited_reference_count": len(visited),
            "successful_fetch_count": sum(x["status"] == 200 for x in fetches),
            "failed_fetch_count": sum(x["status"] != 200 for x in fetches),
            "content_fetch_count": content_budget[0],
            "record_count": len(deduped),
            "vulnerable_state_record_count": len(vulnerable),
            "vulnerable_condition_record_count": len(condition_vulnerable),
            "vulnerable_identity_or_surface_record_count": len(aligned_vulnerable),
            "current_missing_requirements": list(gap.get("missing_requirements") or []),
            "fetches": fetches,
            "records": deduped,
            "source_replacement_used": False,
            "standards_count_as_target_evidence": False,
            "writeups_count_as_target_evidence": False,
            "engine_output_used": False,
            "human_adjudication_performed": False,
            "third_party_code_executed": False,
            "target_contact_performed": False,
            "scoring_executed": False,
            "first_blind_consumed": False,
        })

    result = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_priority0_same_source_deep_reference_capture_unscored",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "family_count": len(families),
        "families": families,
        "family_names": [row["family"] for row in families],
        "record_count": sum(row["record_count"] for row in families),
        "role_counts": dict(sorted(role_counts.items())),
        "fetch_status_counts": dict(sorted(fetch_counts.items())),
        "families_with_vulnerable_condition_records": sum(row["vulnerable_condition_record_count"] > 0 for row in families),
        "families_with_vulnerable_identity_or_surface_records": sum(row["vulnerable_identity_or_surface_record_count"] > 0 for row in families),
        "source_assignment_locked": True,
        "source_replacement_allowed": False,
        "source_replacement_used": False,
        "same_project_reference_only": True,
        "standards_count_as_target_evidence": False,
        "writeups_count_as_target_evidence": False,
        "engine_output_used": False,
        "human_review_required": False,
        "human_adjudication_performed": False,
        "third_party_code_executed": False,
        "target_contact_performed": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
        "gap_worklist_sha256": gaps.get("worklist_sha256"),
    }
    result["deep_reference_sha256"] = sha_json({k: v for k, v in result.items() if k != "deep_reference_sha256"})
    return result


def main() -> int:
    result = build(os.environ.get("GITHUB_TOKEN"))
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = {k: v for k, v in result.items() if k != "families"}
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
