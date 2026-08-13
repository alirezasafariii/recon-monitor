from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
import raw_recon_v4_source_discovery as v4
from raw_recon_v5_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION, audit_row
from raw_recon_v5_source_discovery import exposure_index

VERSION = "1.0.0"
RULE_VERSION = "2026.08.13.6.29"
FAMILY = "business_logic"
GHSA = "GHSA-f83j-v8r3-vfhv"
PROJECT = "pretix/pretix"
EXPECTED_CWE = "CWE-841"
ADVISORY_API = f"https://api.github.com/advisories/{GHSA}"
REPO_API = f"https://api.github.com/repos/{PROJECT}"
OUTPUT = ROOT / "benchmarks/raw/sources/v5_business_logic_supplement.json"


def _fetch(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=v4._headers())
    with urllib.request.urlopen(request, timeout=45) as response:
        payload = json.load(response)
    if not isinstance(payload, Mapping):
        raise RuntimeError(f"unexpected JSON from {url}")
    return dict(payload)


def discover() -> dict[str, Any]:
    advisory = _fetch(ADVISORY_API)
    repo = _fetch(REPO_API)
    if str(advisory.get("ghsa_id") or "") != GHSA:
        raise RuntimeError("business-logic supplement GHSA mismatch")
    cwes = {
        str(item.get("cwe_id") or "").strip()
        for item in advisory.get("cwes") or []
        if isinstance(item, Mapping)
    }
    if EXPECTED_CWE not in cwes:
        raise RuntimeError(f"business-logic supplement missing {EXPECTED_CWE}: {sorted(cwes)}")
    if str(repo.get("full_name") or "") != PROJECT:
        raise RuntimeError("business-logic supplement official repository mismatch")
    if bool(repo.get("archived")):
        raise RuntimeError("business-logic supplement official repository is archived")

    references = [str(value).strip() for value in advisory.get("references") or [] if str(value).strip()]
    grounding = v4._grounding_writeup_urls()
    reference_urls = {v4._canonical_url(value) for value in references if v4._canonical_url(value)}
    if reference_urls & grounding:
        raise RuntimeError("business-logic supplement overlaps detector grounding writeup")

    advisory_url = str(advisory.get("html_url") or "").strip()
    excluded = exposure_index()
    if GHSA in excluded["roots"]:
        raise RuntimeError("business-logic supplement root was previously exposed")
    if PROJECT in excluded["projects"]:
        raise RuntimeError("business-logic supplement project was previously exposed")
    canonical = v4._canonical_url(advisory_url)
    if not canonical or canonical in excluded["urls"]:
        raise RuntimeError("business-logic supplement advisory URL was previously exposed")

    row = {
        "source_root": GHSA,
        "source_project": PROJECT,
        "family": FAMILY,
        "matched_cwes": [EXPECTED_CWE],
        "published_at": str(advisory.get("published_at") or "").strip(),
        "updated_at": str(advisory.get("updated_at") or "").strip(),
        "severity": str(advisory.get("severity") or "").strip(),
        "summary": str(advisory.get("summary") or "").strip(),
        "description": str(advisory.get("description") or "").strip(),
        "repository_advisory_url": "",
        "source_code_location": f"https://github.com/{PROJECT}",
        "canonical_advisory_url": advisory_url,
        "references": references,
        "source_kind": "github_unreviewed_advisory_correlated_to_verified_official_repository",
        "advisory_source_type": str(advisory.get("type") or "unreviewed"),
        "freshness_validated": True,
        "freshness_scope": "complete golden/raw v1-v4 exposure index plus grounding writeups",
        "selection_basis": "exact CWE-841 workflow advisory with independently verified official repository before scoring",
        "official_repository_verified": True,
        "official_repository_id": str(repo.get("id") or ""),
        "official_repository_default_branch": str(repo.get("default_branch") or ""),
    }
    passed, hits, score = audit_row(FAMILY, row)
    if not passed:
        raise RuntimeError(f"business-logic supplement failed v5 semantic audit: {hits}")
    row["source_family_audit_version"] = AUDIT_VERSION
    row["source_family_audit_rule_version"] = AUDIT_RULE_VERSION
    row["source_family_audit_score"] = score
    row["source_family_audit_group_hits"] = hits
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "scoring_executed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "selected": row,
    }


def main() -> int:
    report = discover()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"family": FAMILY, "root": GHSA, "project": PROJECT, "semantic_score": report["selected"]["source_family_audit_score"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
