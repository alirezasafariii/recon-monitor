from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from raw_recon_corpus import ROOT
from v6_literal_source_research import (
    EXTERNAL_SOURCE_HOSTS,
    _api_url,
    _request_allowlisted_external,
    _request_json,
    _sha256_json,
)

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.1"
SOURCE_RESEARCH = ROOT / "benchmarks/raw/sources/v6_literal_source_research.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_literal_linked_research.json"
MAX_LINKS_PER_FAMILY = 12


def _supported_link(url: str) -> tuple[str, str | None]:
    api = _api_url(url)
    if api:
        return "github_api", api
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.netloc.casefold() in EXTERNAL_SOURCE_HOSTS:
        return "allowlisted_external_source", url
    return "unsupported", None


def build_linked_research(*, token: str | None = None) -> dict[str, Any]:
    source = json.loads(SOURCE_RESEARCH.read_text(encoding="utf-8"))
    if source.get("scoring_executed") is not False or source.get("first_blind_consumed") is not False:
        raise RuntimeError("linked research requires an unscored source-research snapshot")
    if source.get("successful_snapshot_count") != 36 or source.get("unresolved_snapshot_count") != 0:
        raise RuntimeError("linked research requires complete 36/36 canonical source research")

    entries: list[dict[str, Any]] = []
    total_supported = 0
    total_fetched = 0
    families_with_links = 0

    for source_row in source.get("entries") or []:
        family = str(source_row.get("family") or "")
        canonical = str(source_row.get("canonical_reference") or "")
        links = []
        seen: set[str] = set()
        for raw in source_row.get("discovered_upstream_links") or []:
            url = str(raw or "").strip()
            if not url or url == canonical or url in seen:
                continue
            seen.add(url)
            route, fetch_url = _supported_link(url)
            if route == "unsupported" or fetch_url is None:
                continue
            links.append((url, route, fetch_url))
            if len(links) >= MAX_LINKS_PER_FAMILY:
                break

        if links:
            families_with_links += 1
        linked_rows: list[dict[str, Any]] = []
        for url, route, fetch_url in links:
            total_supported += 1
            if route == "github_api":
                status, payload, error = _request_json(fetch_url, token)
            else:
                status, payload, error = _request_allowlisted_external(fetch_url)
            if status == 200 and payload is not None:
                total_fetched += 1
            payload_map = payload if isinstance(payload, Mapping) else {}
            linked_rows.append({
                "reference": url,
                "acquisition_route": route,
                "fetch_reference": fetch_url,
                "fetch_status": status,
                "fetch_error": error,
                "snapshot_payload": payload,
                "snapshot_sha256": _sha256_json(payload) if payload is not None else None,
                "resource_type": (
                    "pull_request" if "/pull/" in url
                    else "issue" if "/issues/" in url
                    else "commit" if "/commit/" in url
                    else "security_advisory" if "/advisories/" in url or "/security/advisories/" in url
                    else "external_source"
                ),
                "has_body_or_message": bool(
                    payload_map.get("body")
                    or payload_map.get("message")
                    or payload_map.get("description")
                    or payload_map.get("body_text")
                    or (isinstance(payload_map.get("commit"), Mapping) and payload_map["commit"].get("message"))
                ),
                "scoring_executed": False,
            })

        entries.append({
            "family": family,
            "source_root": source_row.get("source_root"),
            "source_project": source_row.get("source_project"),
            "canonical_reference": canonical,
            "linked_reference_count": len(linked_rows),
            "linked_fetch_success_count": sum(1 for row in linked_rows if row["fetch_status"] == 200 and row["snapshot_payload"] is not None),
            "linked_resources": linked_rows,
            "scoring_executed": False,
        })

    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_passive_linked_evidence_research_unscored",
        "scoring_executed": False,
        "first_blind_consumed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "active_target_validation_performed": False,
        "network_scope": "passive upstream GitHub/advisory/issue/PR/commit and allowlisted canonical-source references only",
        "family_count": 36,
        "max_links_per_family": MAX_LINKS_PER_FAMILY,
        "families_with_supported_linked_references": families_with_links,
        "supported_link_count": total_supported,
        "successful_link_snapshot_count": total_fetched,
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect passive linked upstream evidence research for Analysis 6.31")
    parser.add_argument("--require-some", action="store_true")
    args = parser.parse_args()
    report = build_linked_research(token=os.environ.get("GITHUB_TOKEN"))
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_count": report["family_count"],
        "families_with_supported_linked_references": report["families_with_supported_linked_references"],
        "supported_link_count": report["supported_link_count"],
        "successful_link_snapshot_count": report["successful_link_snapshot_count"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    if args.require_some and report["successful_link_snapshot_count"] == 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
