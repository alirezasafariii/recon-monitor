from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from raw_recon_corpus import ROOT

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.1"
SHORTLIST = ROOT / "benchmarks/raw/sources/v6_shortlist.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_literal_source_research.json"
GHSA_RE = re.compile(r"^GHSA-[0-9a-z-]+$", re.I)


def _sha256_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _api_url(reference: str) -> str | None:
    parsed = urlparse(reference)
    if parsed.scheme != "https" or parsed.netloc.casefold() != "github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) == 2 and parts[0].casefold() == "advisories" and GHSA_RE.fullmatch(parts[1]):
        return f"https://api.github.com/advisories/{parts[1]}"
    if len(parts) >= 4:
        owner, repo = parts[0], parts[1]
        if parts[2] == "issues" and parts[3].isdigit():
            return f"https://api.github.com/repos/{owner}/{repo}/issues/{parts[3]}"
        if parts[2] == "pull" and parts[3].isdigit():
            return f"https://api.github.com/repos/{owner}/{repo}/pulls/{parts[3]}"
        if parts[2] == "commit" and parts[3]:
            return f"https://api.github.com/repos/{owner}/{repo}/commits/{parts[3]}"
        if len(parts) >= 5 and parts[2] == "security" and parts[3] == "advisories" and GHSA_RE.fullmatch(parts[4]):
            return f"https://api.github.com/repos/{owner}/{repo}/security-advisories/{parts[4]}"
    return None


def _request_json(url: str, token: str | None) -> tuple[int, dict[str, Any] | list[Any] | None, str | None]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-analysis-631-passive-source-research",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = int(response.status)
            final = urlparse(response.geturl())
            if final.scheme != "https" or final.netloc.casefold() != "api.github.com":
                return status, None, f"unexpected redirect host: {response.geturl()}"
            payload = json.loads(response.read().decode("utf-8"))
            return status, payload, None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:2000]
        return int(exc.code), None, f"HTTP {exc.code}: {body}"
    except Exception as exc:
        return 0, None, f"{type(exc).__name__}: {exc}"


def _links(payload: Mapping[str, Any]) -> list[str]:
    values: set[str] = set()
    for key in ("html_url", "repository_advisory_url", "source_code_location"):
        value = payload.get(key)
        if isinstance(value, str) and value.startswith("https://"):
            values.add(value)
    for value in payload.get("references") or []:
        if isinstance(value, str) and value.startswith("https://"):
            values.add(value)
    body = str(payload.get("body") or payload.get("description") or "")
    for match in re.findall(r"https://github\.com/[^\s)\]>'\"]+", body):
        values.add(match.rstrip(".,;:"))
    return sorted(values)


def build_research(*, token: str | None = None) -> dict[str, Any]:
    shortlist = json.loads(SHORTLIST.read_text(encoding="utf-8"))
    if shortlist.get("selection_executes_scoring") is not False:
        raise RuntimeError("source research requires an unscored shortlist")
    rows = [dict(row) for row in shortlist.get("selected") or [] if isinstance(row, Mapping)]
    if len(rows) != 36:
        raise RuntimeError(f"expected 36 shortlist rows, got {len(rows)}")

    entries: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: str(item.get("family") or "")):
        reference = str(
            row.get("canonical_advisory_url")
            or row.get("repository_advisory_url")
            or row.get("source_code_location")
            or row.get("source_url")
            or ""
        ).strip()
        api_url = _api_url(reference)
        status = 0
        payload: Any = None
        error: str | None = None
        if not api_url:
            error = "canonical source reference is not a supported GitHub advisory/issue/PR/commit URL"
        else:
            status, payload, error = _request_json(api_url, token)
        payload_map = payload if isinstance(payload, Mapping) else {}
        entries.append({
            "family": row.get("family"),
            "source_root": row.get("source_root"),
            "source_project": row.get("source_project"),
            "source_selection_track": row.get("source_selection_track"),
            "canonical_reference": reference,
            "github_api_reference": api_url,
            "fetch_status": status,
            "fetch_error": error,
            "snapshot_payload": payload,
            "snapshot_sha256": _sha256_json(payload) if payload is not None else None,
            "discovered_upstream_links": _links(payload_map),
            "has_body_or_description": bool(payload_map.get("body") or payload_map.get("description")),
            "scoring_executed": False,
        })

    fetched = sum(1 for row in entries if row["fetch_status"] == 200 and row["snapshot_payload"] is not None)
    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_passive_public_source_research_unscored",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "scoring_executed": False,
        "first_blind_consumed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "active_target_validation_performed": False,
        "network_scope": "public GitHub advisory/issue/PR/commit metadata only",
        "family_count": 36,
        "successful_snapshot_count": fetched,
        "unresolved_snapshot_count": 36 - fetched,
        "entries": entries,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect passive public source snapshots for Analysis 6.31 literal capture research")
    parser.add_argument("--require-all", action="store_true")
    args = parser.parse_args()
    report = build_research(token=os.environ.get("GITHUB_TOKEN"))
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_count": report["family_count"],
        "successful_snapshot_count": report["successful_snapshot_count"],
        "unresolved_snapshot_count": report["unresolved_snapshot_count"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    if args.require_all and report["successful_snapshot_count"] != 36:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
