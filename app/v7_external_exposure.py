from __future__ import annotations

"""Build the pinned external-exposure firewall for Fresh Blind V7.

This module fetches only source-identity metadata from the separately collected
Real-World Corpus V1. It does not import labels, evidence, scores, or reviewer
metadata. The source is pinned to an immutable commit so the V7 firewall is
reproducible.
"""

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.33.v7.unseen.1"
CORPUS_V1_COMMIT = "a6f02912343bc0ab9b2da4e5b9d2724108541f75"
CORPUS_V1_PATH = "benchmarks/real_world/v1/source_shortlist_final.json"
CORPUS_V1_RAW_URL = (
    "https://raw.githubusercontent.com/alirezasafariii/recon-monitor/"
    f"{CORPUS_V1_COMMIT}/{CORPUS_V1_PATH}"
)
DEFAULT_OUT = ROOT / "benchmarks/raw/sources/v7_external_exclusions.json"
EXPECTED_SOURCE_COUNT = 100


def _text(value: Any) -> str:
    return str(value or "").strip()


def _fetch_json(url: str) -> Mapping[str, Any]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "recon-monitor-v7-unseen-firewall/1.0"},
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("corpus_v1_payload_must_be_mapping")
    return payload


def _identity_row(row: Mapping[str, Any]) -> dict[str, Any]:
    references = sorted({_text(v) for v in (row.get("references") or []) if _text(v)})
    identifiers = sorted({_text(v).upper() for v in (row.get("identifiers") or []) if _text(v)})
    return {
        "source_root": _text(row.get("source_root")).upper(),
        "source_project": _text(row.get("source_project")).lower(),
        "canonical_advisory_url": _text(row.get("canonical_advisory_url")),
        "repository_advisory_url": _text(row.get("repository_advisory_url")),
        "source_code_location": _text(row.get("source_code_location")),
        "references": references,
        "identifiers": identifiers,
    }


def build_registry(payload: Mapping[str, Any]) -> dict[str, Any]:
    raw_sources = payload.get("sources")
    if not isinstance(raw_sources, list):
        raise ValueError("corpus_v1_sources_missing")
    rows = [_identity_row(row) for row in raw_sources if isinstance(row, Mapping)]
    rows = [row for row in rows if row["source_root"] and row["source_project"]]
    rows.sort(key=lambda row: (row["source_root"], row["source_project"]))
    roots = {row["source_root"] for row in rows}
    projects = {row["source_project"] for row in rows}
    if len(rows) != EXPECTED_SOURCE_COUNT:
        raise ValueError(f"corpus_v1_source_count:{len(rows)}!={EXPECTED_SOURCE_COUNT}")
    if len(roots) != EXPECTED_SOURCE_COUNT:
        raise ValueError(f"corpus_v1_unique_root_count:{len(roots)}!={EXPECTED_SOURCE_COUNT}")
    if len(projects) != EXPECTED_SOURCE_COUNT:
        raise ValueError(f"corpus_v1_unique_project_count:{len(projects)}!={EXPECTED_SOURCE_COUNT}")
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_external_exposure_exclusion_registry",
        "source": {
            "name": "real_world_corpus_v1",
            "commit_sha": CORPUS_V1_COMMIT,
            "path": CORPUS_V1_PATH,
        },
        "source_count": len(rows),
        "unique_root_count": len(roots),
        "unique_project_count": len(projects),
        "identity_only": True,
        "labels_imported": False,
        "evidence_imported": False,
        "scores_imported": False,
        "scoring_executed": False,
        "sources": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(DEFAULT_OUT))
    args = parser.parse_args()
    registry = build_registry(_fetch_json(CORPUS_V1_RAW_URL))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "source_count": registry["source_count"],
        "unique_root_count": registry["unique_root_count"],
        "unique_project_count": registry["unique_project_count"],
        "identity_only": registry["identity_only"],
        "scoring_executed": registry["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
