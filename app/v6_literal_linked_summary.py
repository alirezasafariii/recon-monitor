from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.1"
SOURCE = ROOT / "benchmarks/raw/sources/v6_literal_linked_research.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_literal_linked_summary.json"


def build() -> dict[str, Any]:
    doc = json.loads(SOURCE.read_text(encoding="utf-8"))
    if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
        raise RuntimeError("linked summary requires unscored linked research")
    families: dict[str, Any] = {}
    success_count = 0
    for entry in doc.get("entries") or []:
        family = str(entry.get("family") or "")
        resources = []
        for row in entry.get("linked_resources") or []:
            if row.get("fetch_status") != 200 or row.get("snapshot_payload") is None:
                continue
            payload = row.get("snapshot_payload") if isinstance(row.get("snapshot_payload"), Mapping) else {}
            resource = {
                "reference": row.get("reference"),
                "fetch_reference": row.get("fetch_reference"),
                "resource_type": row.get("resource_type"),
                "snapshot_sha256": row.get("snapshot_sha256"),
                "has_body_or_message": row.get("has_body_or_message"),
                "payload_identity": {
                    "html_url": payload.get("html_url"),
                    "sha": payload.get("sha"),
                    "number": payload.get("number"),
                    "title": payload.get("title"),
                    "message": payload.get("message") or (payload.get("commit") or {}).get("message") if isinstance(payload.get("commit") or {}, Mapping) else payload.get("message"),
                },
            }
            resources.append(resource)
            success_count += 1
        families[family] = {
            "source_root": entry.get("source_root"),
            "source_project": entry.get("source_project"),
            "canonical_reference": entry.get("canonical_reference"),
            "successful_resources": resources,
            "successful_resource_count": len(resources),
        }
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_passive_linked_research_summary_unscored",
        "scoring_executed": False,
        "first_blind_consumed": False,
        "family_count": len(families),
        "successful_resource_count": success_count,
        "families": families,
    }


def main() -> int:
    report = build()
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"family_count": report["family_count"], "successful_resource_count": report["successful_resource_count"], "scoring_executed": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
