from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_pre_score_condition_audit import audit_conditions

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.32.v7.13"
SHORTLIST = ROOT / "benchmarks/raw/sources/v7_shortlist.json"
LINKED = ROOT / "benchmarks/raw/sources/v7_literal_linked_research.json"
PLAN = ROOT / "benchmarks/raw/sources/v7_literal_capture_plan.json"
VARIANTS = ("positive", "near_miss", "secure_negative", "sparse_noisy")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _patch_lines(payload: Any) -> tuple[list[str], list[str], list[str], list[str]]:
    primary = payload.get("primary") if isinstance(payload, Mapping) else payload
    files = payload.get("files") if isinstance(payload, Mapping) else None
    if not isinstance(files, list):
        if isinstance(primary, Mapping):
            files = primary.get("files")
    file_rows = [dict(row) for row in files or [] if isinstance(row, Mapping)]
    added: list[str] = []
    removed: list[str] = []
    context: list[str] = []
    filenames: list[str] = []
    for row in file_rows[:100]:
        filename = str(row.get("filename") or "").strip()
        if filename:
            filenames.append(filename)
        patch = str(row.get("patch") or "")
        for line in patch.splitlines():
            if line.startswith(("+++", "---", "@@")):
                continue
            if line.startswith("+"):
                text = line[1:].strip()
                if text:
                    added.append(text)
            elif line.startswith("-"):
                text = line[1:].strip()
                if text:
                    removed.append(text)
            elif line.startswith(" "):
                text = line[1:].strip()
                if text:
                    context.append(text)
    return added, removed, context, filenames


def _source_text(row: Mapping[str, Any]) -> str:
    return "\n".join(
        part for part in (
            str(row.get("summary") or "").strip(),
            str(row.get("description") or "").strip(),
        ) if part
    )


def _non_decisive_context(family: str, lines: list[str]) -> list[str]:
    selected: list[str] = []
    for line in lines:
        candidate = {"summary": "", "description": line}
        signals, _ = audit_conditions(family, candidate)
        if not signals:
            selected.append(line)
        if len(selected) >= 24:
            break
    return selected


def _raw(*, target: str, endpoint: str, details: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "target": target,
        "endpoint": endpoint,
        "method": "UNKNOWN",
        "endpoint_schema": {},
        "details": dict(details),
    }


def _capture(
    *,
    family: str,
    kind: str,
    source: Mapping[str, Any],
    linked: Mapping[str, Any],
    details: Mapping[str, Any],
    signals: list[str],
    basis: str,
    notes: str,
    captured_at: str,
) -> dict[str, Any]:
    reference = str(linked.get("reference") or source.get("upstream_repository_reference") or "").strip()
    payload = linked.get("snapshot_payload")
    if not reference.startswith("https://github.com/") or payload is None:
        raise RuntimeError(f"{family}/{kind}: linked upstream snapshot is incomplete")
    raw = _raw(
        target=str(source.get("source_project") or "upstream_project"),
        endpoint=reference,
        details=details,
    )
    return {
        "family": family,
        "case_kind": kind,
        "source_root": source.get("source_root"),
        "source_project": source.get("source_project"),
        "captured_at": captured_at,
        "capture_reference": reference,
        "capture_method": "passive_source_snapshot",
        "collector": {
            "name": "analysis-632-v7-literal-patch-capture",
            "version": VERSION,
            "rule_version": RULE_VERSION,
            "network_scope": "passive public upstream PR/commit metadata and diff snapshot only; no target validation",
        },
        "source_snapshot": {
            "reference": reference,
            "retrieved_at": str(linked.get("collected_at") or captured_at),
            "payload": payload,
            "snapshot_role": "linked_upstream_observation" if kind != "secure_negative" else "patched_or_unaffected_control",
        },
        "adjudication": {
            "basis": basis,
            "notes": notes,
            "expected_condition_signals": list(signals),
            "detector_output_used": False,
            "admission_output_used": False,
            "ranking_output_used": False,
            "v6_first_blind_score_used": False,
            "v6_first_blind_case_errors_used": False,
        },
        "raw": raw,
    }


def collect(output_dir: Path) -> dict[str, Any]:
    shortlist = json.loads(SHORTLIST.read_text(encoding="utf-8"))
    linked_doc = json.loads(LINKED.read_text(encoding="utf-8"))
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    selected = {
        str(row.get("family") or ""): dict(row)
        for row in shortlist.get("selected") or []
        if isinstance(row, Mapping)
    }
    linked = {
        str(row.get("family") or ""): dict(row)
        for row in linked_doc.get("entries") or []
        if isinstance(row, Mapping)
    }
    if len(selected) != 36 or len(linked) != 36:
        raise RuntimeError("v7 literal patch capture requires 36 selected and 36 linked sources")
    if plan.get("required_capture_count") != 144 or plan.get("scoring_executed") is not False:
        raise RuntimeError("v7 literal capture plan is not a clean 144-capture unscored plan")
    if shortlist.get("scoring_executed") is not False or shortlist.get("first_blind_consumed") is not False:
        raise RuntimeError("v7 shortlist is no longer an unscored pre-blind shortlist")

    output_dir.mkdir(parents=True, exist_ok=True)
    produced: list[str] = []
    diagnostics: dict[str, Any] = {}
    captured_at = _now()

    for family in sorted(selected):
        source = selected[family]
        link = linked.get(family) or {}
        payload = link.get("snapshot_payload")
        if payload is None or link.get("successful") is not True:
            raise RuntimeError(f"{family}: linked upstream snapshot missing")
        added, removed, context, filenames = _patch_lines(payload)
        source_text = _source_text(source)
        expected = [str(x) for x in source.get("pre_score_expected_condition_signals") or [] if str(x)]
        if not expected:
            raise RuntimeError(f"{family}: pre-score condition label missing")
        source_signals, source_hits = audit_conditions(family, source)
        if not set(expected).issubset(set(source_signals)):
            raise RuntimeError(f"{family}: selected condition label is not reproducible from source text")
        if not added:
            raise RuntimeError(f"{family}: upstream merged patch has no added fix implementation")
        near = _non_decisive_context(family, context)
        if not near:
            # A near miss must be a genuine adjacent upstream observation that does
            # not satisfy the decisive condition. Do not mutate the positive row.
            raise RuntimeError(f"{family}: patch has no independent non-decisive context for near_miss")

        common = {
            "upstream_reference": source.get("upstream_repository_reference"),
            "changed_files": filenames[:40],
        }
        variants = {
            "positive": _capture(
                family=family,
                kind="positive",
                source=source,
                linked=link,
                details={
                    **common,
                    "source_security_narrative": source_text[:30000],
                    "vulnerable_or_removed_patch_lines": removed[:80],
                    "positive_source_basis": "Fresh upstream security narrative is the positive proof; removed patch lines are supplemental when the fix replaces existing code.",
                    "source_condition_phrase_hits": source_hits,
                },
                signals=expected,
                basis="source_observation",
                notes="Fresh upstream source narrative plus the removed side of the real merged patch independently support the preregistered positive condition label.",
                captured_at=captured_at,
            ),
            "near_miss": _capture(
                family=family,
                kind="near_miss",
                source=source,
                linked=link,
                details={
                    **common,
                    "adjacent_unchanged_patch_context": near,
                    "context_observation": "Adjacent upstream patch context was retained only after the pre-score condition audit found no decisive condition phrase in these lines.",
                },
                signals=[],
                basis="source_observation",
                notes="Independent unchanged upstream context is similar/adjacent to the fix but contains no preregistered decisive condition phrase; it is not derived by deleting fields from the positive observation.",
                captured_at=captured_at,
            ),
            "secure_negative": _capture(
                family=family,
                kind="secure_negative",
                source=source,
                linked=link,
                details={
                    **common,
                    "merged_fix_implementation": "The upstream merged PR/commit contains the following added implementation lines after the vulnerable behavior was changed.",
                    "added_fix_patch_lines": added[:80],
                    "patch_status": "implemented in the selected upstream merged patch",
                },
                signals=[],
                basis="patched_control",
                notes="The secure-negative observation is the actual added side of the real upstream merged fix. Recommendation/remediation prose alone is not used as proof of a control.",
                captured_at=captured_at,
            ),
            "sparse_noisy": _capture(
                family=family,
                kind="sparse_noisy",
                source=source,
                linked=link,
                details={
                    "upstream_reference": source.get("upstream_repository_reference"),
                    "changed_file_count": len(filenames),
                    "added_line_observation_count": len(added),
                    "removed_line_observation_count": len(removed),
                    "context_line_observation_count": len(context),
                    "changed_file_sample": filenames[:5],
                },
                signals=[],
                basis="source_observation",
                notes="Only sparse upstream change metadata is retained; it is insufficient to prove the vulnerability condition and is independent of the positive narrative payload.",
                captured_at=captured_at,
            ),
        }

        raw_hashes = {_sha(row["raw"]) for row in variants.values()}
        if len(raw_hashes) != 4:
            raise RuntimeError(f"{family}: four independently captured raw observations are not distinct")
        diagnostics[family] = {
            "added_line_count": len(added),
            "removed_line_count": len(removed),
            "context_line_count": len(context),
            "near_miss_non_decisive_context_count": len(near),
            "expected_condition_signals": expected,
        }
        for kind in VARIANTS:
            dest = output_dir / f"{family}--{kind}.json"
            dest.write_text(json.dumps(variants[kind], indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
            produced.append(dest.as_posix())

    if len(produced) != 144:
        raise RuntimeError(f"v7 literal patch capture must produce 144 observations, got {len(produced)}")
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "capture_count": len(produced),
        "family_count": len(diagnostics),
        "diagnostics": diagnostics,
        "capture_files": produced,
        "active_target_validation_performed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "v6_first_blind_score_used": False,
        "v6_first_blind_case_errors_used": False,
        "scoring_executed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    report = collect(args.output_dir)
    print(json.dumps({
        "capture_count": report["capture_count"],
        "family_count": report["family_count"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
