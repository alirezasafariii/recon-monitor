from __future__ import annotations

"""Build role-aware source material for the 11 V7 priority-0 positive mappings.

Only material from the immutable V7 source identity is eligible. Historical exact-pair
captures with a different root/project are audited and skipped rather than coerced.
WSTG/OWASP/CWE and write-up lessons are interpretation rubrics, never target evidence.
"""

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from researcher_logic import researcher_logic_for_family
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.1"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.priority0-role-pack.2"
GAPS = ROOT / "benchmarks/raw/sources/v7_standards_gap_worklist.json"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
SOURCE_SNIPPETS = ROOT / "benchmarks/raw/sources/v7_unseen_source_snippet_candidates.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_standards_priority0_role_pack.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_standards_priority0_role_pack_report.json"

HEADING_RE = re.compile(r"(?m)^\s{0,3}#{1,6}\s+(.+?)\s*$")
TOKEN_RE = re.compile(r"[a-z0-9]+", re.I)
MAX_SECTION_CHARS = 6000
MAX_RECORDS_PER_FAMILY = 90

FIX_HEADINGS = (
    "fix", "fixed", "patch", "patched", "mitigation", "workaround", "remediation",
    "recommendation", "recommended", "resolution", "solution", "upgrade",
)
VULN_HEADINGS = (
    "summary", "description", "details", "vulnerability", "root cause", "poc",
    "proof of concept", "reproduction", "impact", "attack", "exploit", "affected",
)
FIX_TEXT_MARKERS = (
    "recommended fix", "recommended mitigation", "to fix", "the fix", "patched in",
    "upgrade to", "workaround", "mitigation", "remediation", "we fixed", "was fixed",
)
VULN_TEXT_MARKERS = (
    "vulnerable", "allows an attacker", "allows attacker", "can exploit", "could exploit",
    "proof of concept", "poc", "impact", "unauthorized", "bypass", "injection", "exposure",
    "leak", "execute", "execution", "accepted", "reachable", "without authentication",
)


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
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def tokens(value: str) -> set[str]:
    return {x.casefold() for x in TOKEN_RE.findall(value)}


def term_tokens(term: str) -> set[str]:
    return {x.casefold() for x in TOKEN_RE.findall(term.replace("_", " ")) if len(x) > 2}


def term_match(term: str, haystack: set[str]) -> bool:
    wanted = term_tokens(term)
    return bool(wanted) and len(wanted & haystack) >= min(len(wanted), 2)


def family_terms(family: str) -> dict[str, list[str]]:
    spec = DETECTOR_SPECS[family]
    logic = researcher_logic_for_family(family)
    writeups: list[str] = []
    for lesson in logic.get("writeup_logic") or []:
        if isinstance(lesson, Mapping):
            for key in ("lesson", "pattern", "signal", "condition", "control", "title"):
                value = text(lesson.get(key))
                if value:
                    writeups.append(value)
        elif text(lesson):
            writeups.append(text(lesson))
    return {
        "identity": sorted(spec.identity_signals),
        "surface": sorted(spec.surface_terms),
        "condition": sorted(spec.condition_signals),
        "control": sorted(spec.blocking_controls),
        "override": sorted(spec.override_signals),
        "writeup": writeups,
    }


def signal_hits(family: str, body: str) -> dict[str, list[str]]:
    haystack = tokens(body)
    return {
        key: [term for term in values if term_match(term, haystack)]
        for key, values in family_terms(family).items()
        if key != "writeup"
    }


def role_from_heading_and_text(heading: str, body: str) -> str:
    h, b = heading.casefold(), body.casefold()
    if any(marker in h for marker in FIX_HEADINGS):
        return "fixed_or_remediation_state"
    if any(marker in h for marker in VULN_HEADINGS):
        return "vulnerable_or_impact_state"
    if any(marker in b for marker in FIX_TEXT_MARKERS) and not any(marker in b for marker in VULN_TEXT_MARKERS):
        return "fixed_or_remediation_state"
    if any(marker in b for marker in VULN_TEXT_MARKERS):
        return "vulnerable_or_impact_state"
    return "unclassified_source_state"


def markdown_sections(value: str) -> list[dict[str, str]]:
    source = text(value)
    if not source:
        return []
    matches = list(HEADING_RE.finditer(source))
    if not matches:
        return [
            {"heading": "", "text": chunk.strip()[:MAX_SECTION_CHARS]}
            for chunk in re.split(r"\n\s*\n", source)
            if chunk.strip()
        ]
    rows: list[dict[str, str]] = []
    prefix = source[: matches[0].start()].strip()
    if prefix:
        rows.append({"heading": "", "text": prefix[:MAX_SECTION_CHARS]})
    for idx, match in enumerate(matches):
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(source)
        body = source[match.end():end].strip()
        if body:
            rows.append({"heading": match.group(1).strip(), "text": body[:MAX_SECTION_CHARS]})
    return rows


def source_record(family: str, origin: str, role: str, body: str, *, heading: str = "", metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
    hits = signal_hits(family, body)
    return {
        "origin": origin,
        "source_state_role": role,
        "heading": heading or None,
        "text": body,
        "text_sha256": sha_text(body),
        "signal_hit_counts": {key: len(value) for key, value in hits.items()},
        "signal_hits": hits,
        "metadata": dict(metadata or {}),
    }


def useful(row: Mapping[str, Any]) -> bool:
    hits = row.get("signal_hit_counts") if isinstance(row.get("signal_hit_counts"), Mapping) else {}
    return any(int(hits.get(key) or 0) > 0 for key in ("identity", "surface", "condition", "control", "override"))


def advisory_records(family: str, entry: Mapping[str, Any]) -> list[dict[str, Any]]:
    snapshot = entry.get("snapshot_payload") if isinstance(entry.get("snapshot_payload"), Mapping) else {}
    rows: list[dict[str, Any]] = []
    for field in ("summary", "description", "body"):
        for section in markdown_sections(text(snapshot.get(field))):
            body, heading = text(section.get("text")), text(section.get("heading"))
            if not body:
                continue
            row = source_record(
                family,
                f"authoritative_advisory_{field}",
                role_from_heading_and_text(heading, body),
                body,
                heading=heading,
                metadata={
                    "source_root": entry.get("source_root"),
                    "canonical_reference": entry.get("canonical_reference"),
                    "snapshot_sha256": entry.get("snapshot_sha256"),
                },
            )
            if useful(row):
                rows.append(row)
    return list({text(row["text_sha256"]): row for row in rows}.values())[:MAX_RECORDS_PER_FAMILY]


def pair_records(family: str, pack: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for file_row in pack.get("files") or []:
        if not isinstance(file_row, Mapping):
            continue
        filename = text(file_row.get("filename"))
        previous = text(file_row.get("previous_filename")) or filename
        for item in file_row.get("parent_snippets") or []:
            if isinstance(item, Mapping) and text(item.get("text")):
                row = source_record(
                    family, "exact_revision_parent", "vulnerable_parent_state", text(item.get("text")),
                    metadata={"filename": previous, "parent_sha": pack.get("parent_sha"), "file_sha256": item.get("file_sha256"), "line_start": item.get("line_start"), "line_end": item.get("line_end")},
                )
                if useful(row):
                    rows.append(row)
        for item in file_row.get("fix_snippets") or []:
            if isinstance(item, Mapping) and text(item.get("text")):
                row = source_record(
                    family, "exact_revision_fix", "fixed_or_remediation_state", text(item.get("text")),
                    metadata={"filename": filename, "fix_sha": pack.get("fix_sha"), "file_sha256": item.get("file_sha256"), "line_start": item.get("line_start"), "line_end": item.get("line_end")},
                )
                if useful(row):
                    rows.append(row)
        for item in file_row.get("upstream_test_control_candidates") or []:
            if isinstance(item, Mapping) and text(item.get("text")):
                row = source_record(
                    family, "exact_revision_upstream_test_control", "fixed_test_control_state", text(item.get("text")),
                    metadata={"filename": filename, "fix_sha": pack.get("fix_sha"), "line_start": item.get("line_start")},
                )
                if useful(row):
                    rows.append(row)
    return list({text(row["text_sha256"]): row for row in rows}.values())[:MAX_RECORDS_PER_FAMILY]


def build() -> dict[str, Any]:
    freeze = assert_capture_source_freeze()
    gaps, research, snippets = load(GAPS), load(RESEARCH), load(SOURCE_SNIPPETS)
    for doc, name in ((gaps, "gaps"), (research, "research"), (snippets, "snippets")):
        if doc.get("source_assignment_commit") != freeze["source_assignment_commit"]:
            raise RuntimeError(f"V7 priority0 role-pack {name} assignment drift")
        if doc.get("scoring_executed") is not False or doc.get("first_blind_consumed") is not False:
            raise RuntimeError(f"V7 priority0 role-pack requires unconsumed {name}")
    if gaps.get("unresolved_variant_count") != 118:
        raise RuntimeError("V7 priority0 role-pack expects frozen 118-gap worklist")
    if research.get("successful_snapshot_count") != 36 or research.get("unresolved_snapshot_count") != 0:
        raise RuntimeError("V7 priority0 role-pack requires complete authoritative source research")

    priority = [
        row for row in gaps.get("worklist") or []
        if isinstance(row, Mapping) and row.get("priority") == 0 and text(row.get("case_kind")) == "positive"
    ]
    if len(priority) != 11:
        raise RuntimeError(f"expected 11 priority-0 positive mappings, got {len(priority)}")

    research_by = {text(x.get("family")): x for x in research.get("entries") or [] if isinstance(x, Mapping)}
    snippet_by = {text(x.get("family")): x for x in snippets.get("sources") or [] if isinstance(x, Mapping)}
    families: list[dict[str, Any]] = []
    role_counts: Counter[str] = Counter()
    identity_mismatches: list[str] = []

    for gap in sorted(priority, key=lambda row: text(row.get("family"))):
        family = text(gap.get("family"))
        entry = research_by.get(family)
        if not entry:
            raise RuntimeError(f"{family}: missing authoritative research row")
        source_root, source_project = text(entry.get("source_root")), text(entry.get("source_project"))
        if not source_root or not source_project:
            raise RuntimeError(f"{family}: incomplete frozen source identity")

        records = advisory_records(family, entry)
        exact_pack = snippet_by.get(family, {})
        exact_identity_match: bool | None = None
        if exact_pack:
            exact_identity_match = (
                text(exact_pack.get("source_root")) == source_root
                and text(exact_pack.get("source_project")) == source_project
            )
            if exact_identity_match:
                records.extend(pair_records(family, exact_pack))
            else:
                identity_mismatches.append(family)

        records = list({text(row["text_sha256"]): row for row in records}.values())[:MAX_RECORDS_PER_FAMILY]
        vulnerable_roles = {"vulnerable_or_impact_state", "vulnerable_parent_state"}
        fixed_roles = {"fixed_or_remediation_state", "fixed_test_control_state"}
        vulnerable = [row for row in records if text(row.get("source_state_role")) in vulnerable_roles]
        fixed = [row for row in records if text(row.get("source_state_role")) in fixed_roles]
        unclassified = [row for row in records if text(row.get("source_state_role")) == "unclassified_source_state"]
        condition_vulnerable = [row for row in vulnerable if int((row.get("signal_hit_counts") or {}).get("condition") or 0) > 0]
        identity_vulnerable = [row for row in vulnerable if int((row.get("signal_hit_counts") or {}).get("identity") or 0) > 0 or int((row.get("signal_hit_counts") or {}).get("surface") or 0) > 0]
        for row in records:
            role_counts[text(row.get("source_state_role"))] += 1

        standards = gap.get("standards_rubric") if isinstance(gap.get("standards_rubric"), Mapping) else {}
        families.append({
            "family": family,
            "capture_id": gap.get("capture_id"),
            "source_root": source_root,
            "source_project": source_project,
            "canonical_reference": entry.get("canonical_reference"),
            "source_snapshot_sha256": entry.get("snapshot_sha256"),
            "exact_revision_pair_present_in_historical_pack": bool(exact_pack),
            "exact_revision_pair_identity_match": exact_identity_match,
            "exact_revision_pair_used": bool(exact_pack and exact_identity_match and exact_pack.get("exact_pair_available")),
            "exact_revision_pair_skipped_due_identity_mismatch": exact_identity_match is False,
            "record_count": len(records),
            "vulnerable_state_record_count": len(vulnerable),
            "fixed_state_record_count": len(fixed),
            "unclassified_record_count": len(unclassified),
            "vulnerable_condition_record_count": len(condition_vulnerable),
            "vulnerable_identity_or_surface_record_count": len(identity_vulnerable),
            "current_missing_requirements": list(gap.get("missing_requirements") or []),
            "standards_rubric": {
                "wstg_ids": list(standards.get("wstg_ids") or []),
                "owasp_ids": list(standards.get("owasp_ids") or []),
                "cwe_ids": list(standards.get("cwe_ids") or []),
                "principle": standards.get("principle"),
                "counts_as_target_evidence": False,
            },
            "writeup_rubric_sha256": sha_json(family_terms(family)["writeup"]),
            "writeups_count_as_target_evidence": False,
            "records": records,
            "source_replacement_used": False,
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
        "evaluation_kind": "fresh_blind_v7_priority0_role_aware_source_pack_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "family_count": len(families),
        "capture_count": len(families),
        "record_count": sum(x["record_count"] for x in families),
        "role_counts": dict(sorted(role_counts.items())),
        "families_with_vulnerable_condition_records": sum(x["vulnerable_condition_record_count"] > 0 for x in families),
        "families_with_vulnerable_identity_or_surface_records": sum(x["vulnerable_identity_or_surface_record_count"] > 0 for x in families),
        "families_with_exact_revision_pairs_used": sum(x["exact_revision_pair_used"] for x in families),
        "historical_exact_pair_identity_mismatch_count": len(identity_mismatches),
        "historical_exact_pair_identity_mismatch_families": sorted(identity_mismatches),
        "source_assignment_locked": True,
        "source_replacement_allowed": False,
        "source_replacement_used": False,
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
        "families": families,
    }
    result["role_pack_sha256"] = sha_json({k: v for k, v in result.items() if k != "role_pack_sha256"})
    return result


def main() -> int:
    result = build()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = {k: v for k, v in result.items() if k != "families"}
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
