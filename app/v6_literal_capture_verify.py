from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.1"
SHORTLIST = ROOT / "benchmarks/raw/sources/v6_shortlist.json"
CAPTURES = ROOT / "benchmarks/raw/sources/v6_literal_captures.jsonl"
EVIDENCE_ROOT = ROOT / "benchmarks/raw/sources/v6_capture_evidence"
REPORT = ROOT / "benchmarks/raw/sources/v6_literal_capture_verification.json"
SINGLE_VARIANTS = {"positive", "near_miss", "secure_negative", "sparse_noisy"}
ALLOWED_CAPTURE_METHODS = {
    "http_exchange",
    "cli_output",
    "packet_or_log_capture",
    "regression_test_output",
    "repository_test_fixture",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical(value).encode("utf-8"))


def _identity(value: Any) -> str:
    return str(value or "").strip().casefold()


def _valid_timestamp(value: Any) -> bool:
    raw = str(value or "").strip()
    if not raw or "T" not in raw:
        return False
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _load_shortlist(path: Path) -> dict[str, dict[str, Any]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    rows = [dict(row) for row in doc.get("selected") or [] if isinstance(row, Mapping)]
    selected = {str(row.get("family") or ""): row for row in rows}
    if len(rows) != 36 or set(selected) != set(DETECTOR_SPECS):
        raise RuntimeError("v6 shortlist must contain exactly one source for all 36 detector families")
    if doc.get("selection_executes_scoring") is not False:
        raise RuntimeError("v6 shortlist must remain unscored")
    return selected


def _safe_evidence_path(value: Any, evidence_root: Path) -> Path | None:
    rel = str(value or "").strip()
    if not rel:
        return None
    candidate = (ROOT / rel).resolve()
    root = evidence_root.resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if candidate.suffix.lower() != ".json":
        return None
    return candidate


def _snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    if "payload" not in snapshot:
        return ""
    return _sha256_json(snapshot.get("payload"))


def verify_capture_set(
    *,
    captures_path: Path = CAPTURES,
    shortlist_path: Path = SHORTLIST,
    evidence_root: Path = EVIDENCE_ROOT,
    require_complete: bool = True,
    write_report: bool = False,
) -> dict[str, Any]:
    captures_path = Path(captures_path)
    shortlist_path = Path(shortlist_path)
    evidence_root = Path(evidence_root)
    errors: list[str] = []
    if not captures_path.exists():
        if require_complete:
            errors.append("v6 literal capture set is required but missing")
        result = {
            "verifier_version": VERSION,
            "verifier_rule_version": RULE_VERSION,
            "passed": not errors,
            "errors": errors,
            "capture_file_present": False,
            "capture_count": 0,
            "evidence_count": 0,
            "family_count": 0,
            "scoring_executed": False,
        }
        if write_report:
            REPORT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result

    selected = _load_shortlist(shortlist_path)
    rows = [json.loads(line) for line in captures_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    variants: dict[str, set[str]] = defaultdict(set)
    raw_hashes: dict[str, set[str]] = defaultdict(set)
    evidence_paths: set[str] = set()
    evidence_hashes: set[str] = set()
    evidence_manifest: dict[str, str] = {}

    for pos, row in enumerate(rows, start=1):
        cid = f"capture-line-{pos}"
        if not isinstance(row, Mapping):
            errors.append(f"{cid}: capture row must be an object")
            continue
        family = str(row.get("family") or "")
        kind = str(row.get("case_kind") or "")
        cid = f"{family or 'unknown'}/{kind or 'unknown'}"
        if family not in selected:
            errors.append(f"{cid}: family is not in the sealed shortlist")
            continue
        if kind not in SINGLE_VARIANTS:
            errors.append(f"{cid}: invalid single variant")
            continue
        if kind in variants[family]:
            errors.append(f"{cid}: duplicate family/variant capture")
        variants[family].add(kind)

        source = selected[family]
        if _identity(row.get("source_root")) != _identity(source.get("source_root")):
            errors.append(f"{cid}: source_root does not match shortlist")
        if _identity(row.get("source_project")) != _identity(source.get("source_project")):
            errors.append(f"{cid}: source_project does not match shortlist")

        raw = row.get("raw") if isinstance(row.get("raw"), Mapping) else None
        if not raw:
            errors.append(f"{cid}: raw observation object is missing")
            continue
        raw_sha = _sha256_json(raw)
        raw_hashes[family].add(raw_sha)

        provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
        if provenance.get("literal_capture") is not True:
            errors.append(f"{cid}: provenance.literal_capture must be true")
        capture_reference = str(provenance.get("capture_reference") or "").strip()
        if not capture_reference.startswith("https://"):
            errors.append(f"{cid}: capture_reference must be an https source reference")
        captured_at = str(provenance.get("captured_at") or "").strip()
        if not _valid_timestamp(captured_at):
            errors.append(f"{cid}: captured_at must be an ISO-8601 timestamp with timezone")
        capture_method = str(provenance.get("capture_method") or "").strip()
        if capture_method not in ALLOWED_CAPTURE_METHODS:
            errors.append(f"{cid}: capture_method is not an allowed literal acquisition method")

        declared_raw_sha = str(provenance.get("raw_sha256") or "").strip().lower()
        if not SHA256_RE.fullmatch(declared_raw_sha) or declared_raw_sha != raw_sha:
            errors.append(f"{cid}: provenance.raw_sha256 does not match canonical raw observation")

        evidence_path = _safe_evidence_path(provenance.get("evidence_path"), evidence_root)
        if evidence_path is None:
            errors.append(f"{cid}: evidence_path must point to a JSON file inside v6_capture_evidence")
            continue
        rel = evidence_path.relative_to(ROOT).as_posix()
        if rel in evidence_paths:
            errors.append(f"{cid}: evidence artifact is reused by more than one capture")
        evidence_paths.add(rel)
        if not evidence_path.exists():
            errors.append(f"{cid}: evidence artifact is missing: {rel}")
            continue

        actual_evidence_sha = _sha256_bytes(evidence_path.read_bytes())
        declared_evidence_sha = str(provenance.get("evidence_sha256") or "").strip().lower()
        if not SHA256_RE.fullmatch(declared_evidence_sha) or declared_evidence_sha != actual_evidence_sha:
            errors.append(f"{cid}: provenance.evidence_sha256 does not match evidence artifact")
        if actual_evidence_sha in evidence_hashes:
            errors.append(f"{cid}: duplicate evidence artifact content")
        evidence_hashes.add(actual_evidence_sha)
        evidence_manifest[rel] = actual_evidence_sha

        try:
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"{cid}: evidence artifact is not valid JSON: {exc}")
            continue
        if not isinstance(evidence, Mapping):
            errors.append(f"{cid}: evidence artifact must be a JSON object")
            continue
        if str(evidence.get("schema_version") or "") != "1.0":
            errors.append(f"{cid}: unsupported evidence schema_version")
        for key, expected in (
            ("family", family),
            ("case_kind", kind),
            ("source_root", row.get("source_root")),
            ("source_project", row.get("source_project")),
            ("captured_at", captured_at),
            ("capture_reference", capture_reference),
            ("capture_method", capture_method),
        ):
            if _identity(evidence.get(key)) != _identity(expected):
                errors.append(f"{cid}: evidence.{key} does not match capture metadata")

        evidence_raw = evidence.get("raw") if isinstance(evidence.get("raw"), Mapping) else None
        if evidence_raw is None or _canonical(evidence_raw) != _canonical(raw):
            errors.append(f"{cid}: benchmark raw does not exactly match evidence raw")
        evidence_raw_sha = str(evidence.get("raw_sha256") or "").strip().lower()
        if evidence_raw_sha != raw_sha:
            errors.append(f"{cid}: evidence.raw_sha256 does not match evidence raw")

        collector = evidence.get("collector") if isinstance(evidence.get("collector"), Mapping) else {}
        if not str(collector.get("tool") or "").strip():
            errors.append(f"{cid}: evidence collector.tool is required")
        if not any(str(collector.get(key) or "").strip() for key in ("command", "request", "source_file")):
            errors.append(f"{cid}: evidence collector must record command, request, or source_file")

        snapshot = evidence.get("source_snapshot") if isinstance(evidence.get("source_snapshot"), Mapping) else {}
        if _identity(snapshot.get("reference")) != _identity(capture_reference):
            errors.append(f"{cid}: source_snapshot.reference must match capture_reference")
        if not _valid_timestamp(snapshot.get("retrieved_at")):
            errors.append(f"{cid}: source_snapshot.retrieved_at must be timezone-qualified")
        snapshot_sha = str(snapshot.get("content_sha256") or "").strip().lower()
        computed_snapshot_sha = _snapshot_digest(snapshot)
        if not SHA256_RE.fullmatch(snapshot_sha) or not computed_snapshot_sha or snapshot_sha != computed_snapshot_sha:
            errors.append(f"{cid}: source_snapshot content hash is missing or invalid")

    if require_complete:
        if len(rows) != 144:
            errors.append(f"literal capture set must contain exactly 144 rows: {len(rows)}")
        if set(variants) != set(DETECTOR_SPECS):
            missing = sorted(set(DETECTOR_SPECS) - set(variants))
            extra = sorted(set(variants) - set(DETECTOR_SPECS))
            errors.append(f"literal capture family coverage mismatch missing={missing} extra={extra}")
        for family in sorted(DETECTOR_SPECS):
            if variants.get(family, set()) != SINGLE_VARIANTS:
                errors.append(f"{family}: literal capture variant coverage mismatch")
            if len(raw_hashes.get(family, set())) != 4:
                errors.append(f"{family}: four distinct literal raw observations are required")
        if len(evidence_paths) != 144:
            errors.append(f"literal capture evidence path count must be 144: {len(evidence_paths)}")
        if len(evidence_hashes) != 144:
            errors.append(f"literal capture evidence content count must be 144: {len(evidence_hashes)}")

    result = {
        "verifier_version": VERSION,
        "verifier_rule_version": RULE_VERSION,
        "passed": not errors,
        "errors": errors,
        "capture_file_present": True,
        "capture_count": len(rows),
        "evidence_count": len(evidence_paths),
        "unique_evidence_hash_count": len(evidence_hashes),
        "family_count": len(variants),
        "complete_capture_set_required": require_complete,
        "capture_input_sha256": _sha256_bytes(captures_path.read_bytes()),
        "evidence_manifest": dict(sorted(evidence_manifest.items())),
        "scoring_executed": False,
    }
    if write_report:
        REPORT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Analysis 6.31 literal capture evidence integrity")
    parser.add_argument("--allow-missing", action="store_true", help="pass when capture collection has not started")
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    result = verify_capture_set(require_complete=not args.allow_missing, write_report=args.write_report)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
