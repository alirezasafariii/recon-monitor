from __future__ import annotations

"""Capture the final two source-grounded V7 near-miss control candidates.

These candidates are family-specific because the public upstream projects expose no
independent committed regression test for these exact cases. The capture is still
non-adjudicating: it binds stable source/commit/hash/snippet material for human review,
never synthesizes a request, never labels a case, and never scores the engine.
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze
from v7_unseen_source_snippet_capture import file_bytes

VERSION = "1.0.0"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.final-residual-control.1"
SIXTH_RESOLUTION = ROOT / "benchmarks/raw/sources/v7_sixth_pass_resolution_queue.json"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_final_residual_control_candidates.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_final_residual_control_candidates_report.json"

EXPECTED = {
    "command_injection": {
        "source_root": "GHSA-5xpp-75jx-m839",
        "source_project": "sebhildebrandt/systeminformation",
        "file": "lib/network.js",
        "commit": "da1cbf5eb09907cf5c3431f4c9ea441b7a227617",
        "anchor": "const connectionNameSanitized = util.sanitizeString(connectionName, false);",
        "required_context": ["function getLinuxIfaceConnectionName", "execFileSync('nmcli'"],
        "candidate_role": "sibling_shell_input_with_explicit_sanitization_control",
    },
    "cors_misconfiguration": {
        "source_root": "GHSA-xqhv-chqm-fhcc",
        "source_project": "BishopFox/joro",
        "file": "internal/api/originguard.go",
        "commit": "5c0ca35db8283e2515fa7b3ab2899e2ba9c9dad5",
        "anchor": 'case "", "same-origin", "none":',
        "required_context": ["func sameOrigin", 'default: // "cross-site", "same-site"', "return false"],
        "candidate_role": "same_origin_or_non_browser_path_with_cross_origin_guard_control",
    },
}
MAX_SNIPPET_LINES = 34


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


def snippet(raw: bytes, anchor: str) -> dict[str, Any]:
    source = raw.decode("utf-8", errors="replace")
    lines = source.splitlines()
    index = next((i for i, line in enumerate(lines) if anchor in line), None)
    if index is None:
        raise RuntimeError(f"required literal anchor missing: {anchor}")
    lo = max(0, index - 10)
    hi = min(len(lines), lo + MAX_SNIPPET_LINES)
    body = "\n".join(lines[lo:hi])
    return {
        "line_start": lo + 1,
        "line_end": hi,
        "text": body,
        "text_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> int:
    freeze = assert_capture_source_freeze()
    resolution = load(SIXTH_RESOLUTION)
    research = load(RESEARCH)
    for doc in (resolution, research):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError("V7 final residual input assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError("V7 final residual capture requires unconsumed inputs")
    if resolution.get("still_unresolved_count") != 2 or resolution.get("families_still_unresolved") != 2:
        raise RuntimeError("V7 final residual expected exactly two unresolved items")

    unresolved = [
        row for row in resolution.get("items") or []
        if isinstance(row, Mapping) and row.get("resolution_status") == "still_unresolved_after_sixth_pass"
    ]
    if {text(x.get("family")) for x in unresolved} != set(EXPECTED):
        raise RuntimeError("V7 final residual family identity drift")
    research_by = {text(x.get("family")): x for x in research.get("entries") or [] if isinstance(x, Mapping)}
    token = os.environ.get("GITHUB_TOKEN", "")
    candidates = []

    for row in sorted(unresolved, key=lambda x: text(x.get("family"))):
        family = text(row.get("family"))
        cfg = EXPECTED[family]
        if text(row.get("case_kind")) != "near_miss":
            raise RuntimeError(f"{family}: final residual is not near_miss")
        if text(row.get("source_root")) != cfg["source_root"]:
            raise RuntimeError(f"{family}: frozen source_root drift")
        if text(row.get("source_project")).casefold() != cfg["source_project"].casefold():
            raise RuntimeError(f"{family}: frozen source_project drift")
        research_row = research_by.get(family, {})
        if text(research_row.get("source_root")) != cfg["source_root"]:
            raise RuntimeError(f"{family}: research source_root drift")

        raw = file_bytes(cfg["source_project"], cfg["file"], cfg["commit"], token)
        if raw is None:
            raise RuntimeError(f"{family}: required upstream source file unavailable")
        captured = snippet(raw, cfg["anchor"])
        for required in cfg["required_context"]:
            if required not in captured["text"]:
                raise RuntimeError(f"{family}: required sibling-control context missing: {required}")

        candidate = {
            "family": family,
            "case_kind": "near_miss",
            "capture_id": row.get("capture_id"),
            "source_root": cfg["source_root"],
            "source_project": cfg["source_project"],
            "source_commit": cfg["commit"],
            "source_file": cfg["file"],
            "literal_anchor": cfg["anchor"],
            "candidate_role": cfg["candidate_role"],
            "source_snapshot": captured,
            "required_evidence_path": row.get("required_evidence_path"),
            "semantic_role": "unadjudicated_final_residual_sibling_control_candidate",
            "human_semantic_decision": None,
            "human_semantic_notes": None,
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
        }
        candidate["candidate_sha256"] = sha_json(candidate)
        candidates.append(candidate)

    report = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_engine_unseen_final_residual_sibling_control_candidates_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "residual_input_count": 2,
        "candidate_count": len(candidates),
        "families": [x["family"] for x in candidates],
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
    document["candidates"] = candidates
    document["capture_set_sha256"] = sha_json(candidates)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
