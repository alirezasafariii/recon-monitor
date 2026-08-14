from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v4_corpus import V4_VALID_METHODS

PLAN = ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json"
EVIDENCE_ROOT = ROOT / "benchmarks/raw/sources/v6_capture_evidence"
VARIANTS = {"positive", "near_miss", "secure_negative", "sparse_noisy"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _load_plan(path: Path = PLAN) -> dict[tuple[str, str], dict[str, Any]]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for requirement in doc.get("requirements") or []:
        if not isinstance(requirement, Mapping):
            continue
        family = str(requirement.get("family") or "")
        kind = str(requirement.get("case_kind") or "")
        if family and kind:
            rows[(family, kind)] = dict(requirement)
    if len(rows) != 144:
        raise RuntimeError(f"v6 capture plan must contain 144 family/variant requirements: {len(rows)}")
    return rows


def _load_capture(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise RuntimeError(f"capture must be an object: {path}")
    return dict(value)


def _required_object(capture: Mapping[str, Any], key: str, source: Path) -> dict[str, Any]:
    value = capture.get(key)
    if not isinstance(value, Mapping) or not value:
        raise RuntimeError(f"{source}: {key} object is required")
    return dict(value)


def publish_capture_files(capture_dir: Path, *, plan_path: Path = PLAN, evidence_root: Path = EVIDENCE_ROOT) -> dict[str, Any]:
    capture_dir = Path(capture_dir)
    evidence_root = Path(evidence_root)
    plan = _load_plan(plan_path)
    files = sorted(capture_dir.rglob("*.json"))
    if not files:
        raise RuntimeError(f"no capture JSON files found under {capture_dir}")

    written: list[str] = []
    families: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for source in files:
        capture = _load_capture(source)
        family = str(capture.get("family") or "").strip()
        kind = str(capture.get("case_kind") or "").strip()
        key = (family, kind)
        if not family or kind not in VARIANTS or key not in plan:
            raise RuntimeError(f"{source}: unknown v6 family/variant {family}/{kind}")
        if key in seen:
            raise RuntimeError(f"duplicate capture in input: {family}/{kind}")
        seen.add(key)
        families.add(family)

        requirement = plan[key]
        capture_reference = str(capture.get("capture_reference") or "").strip()
        capture_method = str(capture.get("capture_method") or "").strip()
        captured_at = str(capture.get("captured_at") or "").strip()
        raw = _required_object(capture, "raw", source)
        collector = _required_object(capture, "collector", source)
        snapshot = _required_object(capture, "source_snapshot", source)
        adjudication = _required_object(capture, "adjudication", source)

        raw_method = str(raw.get("method") or "").strip().upper()
        if raw_method not in V4_VALID_METHODS:
            raise RuntimeError(f"{source}: raw.method must be one of {sorted(V4_VALID_METHODS)}")
        if "endpoint_schema" in raw and not isinstance(raw.get("endpoint_schema"), Mapping):
            raise RuntimeError(f"{source}: raw.endpoint_schema must be an object when supplied")
        if "details" in raw and not isinstance(raw.get("details"), Mapping):
            raise RuntimeError(f"{source}: raw.details must be an object")
        if not capture_reference.startswith("https://"):
            raise RuntimeError(f"{source}: capture_reference must be https")
        if str(snapshot.get("reference") or "").strip() != capture_reference:
            raise RuntimeError(f"{source}: source_snapshot.reference must equal capture_reference")
        if "payload" not in snapshot:
            raise RuntimeError(f"{source}: source_snapshot.payload is required")
        if kind == "positive" and not list(adjudication.get("expected_condition_signals") or []):
            raise RuntimeError(f"{source}: positive capture requires expected_condition_signals")
        if kind != "positive" and list(adjudication.get("expected_condition_signals") or []):
            raise RuntimeError(f"{source}: non-positive capture cannot carry expected_condition_signals")
        for field in ("detector_output_used", "admission_output_used", "ranking_output_used"):
            if adjudication.get(field) is not False:
                raise RuntimeError(f"{source}: adjudication.{field} must be false")

        raw_sha = _sha256_json(raw)
        snapshot_sha = _sha256_json(snapshot.get("payload"))
        evidence = {
            "schema_version": "1.0",
            "family": family,
            "case_kind": kind,
            "source_root": requirement["source_root"],
            "source_project": requirement["source_project"],
            "captured_at": captured_at,
            "capture_reference": capture_reference,
            "capture_method": capture_method,
            "collector": collector,
            "source_snapshot": {
                "reference": capture_reference,
                "retrieved_at": str(snapshot.get("retrieved_at") or captured_at),
                "payload": snapshot.get("payload"),
                "content_sha256": snapshot_sha,
            },
            "adjudication": adjudication,
            "raw": raw,
            "raw_sha256": raw_sha,
        }

        rel = Path(str(requirement["required_evidence_path"]))
        destination = (ROOT / rel).resolve()
        destination.relative_to(evidence_root.resolve())
        destination.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if destination.exists():
            existing = destination.read_text(encoding="utf-8")
            if existing != rendered:
                raise RuntimeError(f"refusing to overwrite existing non-identical evidence: {rel.as_posix()}")
        else:
            destination.write_text(rendered, encoding="utf-8")
        written.append(rel.as_posix())

    return {
        "published_capture_count": len(written),
        "families": sorted(families),
        "evidence_paths": sorted(written),
        "scoring_executed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish independently acquired Analysis 6.31 capture JSON into strict evidence artifacts")
    parser.add_argument("capture_dir", type=Path)
    args = parser.parse_args()
    result = publish_capture_files(args.capture_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
