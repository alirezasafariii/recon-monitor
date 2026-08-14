from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v6_benchmark_validate import _validate_observation

EVIDENCE_ROOT = ROOT / "benchmarks/raw/sources/v6_capture_evidence"
VARIANTS = {"positive", "near_miss", "secure_negative", "sparse_noisy"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def precheck(evidence_root: Path = EVIDENCE_ROOT) -> dict[str, Any]:
    evidence_root = Path(evidence_root)
    errors: list[str] = []
    leakage: dict[str, list[str]] = {}
    variants: dict[str, set[str]] = defaultdict(set)
    raw_hashes: dict[str, set[str]] = defaultdict(set)
    count = 0

    for path in sorted(evidence_root.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        if not isinstance(doc, Mapping):
            errors.append(f"{path.name}: evidence must be an object")
            continue
        family = str(doc.get("family") or "").strip()
        kind = str(doc.get("case_kind") or "").strip()
        cid = f"{family}/{kind}"
        raw = doc.get("raw") if isinstance(doc.get("raw"), Mapping) else None
        if not family or kind not in VARIANTS or raw is None:
            errors.append(f"{path.name}: family/case_kind/raw contract invalid")
            continue
        adjudication = doc.get("adjudication") if isinstance(doc.get("adjudication"), Mapping) else {}
        expected_conditions = {
            str(value)
            for value in adjudication.get("expected_condition_signals") or []
            if str(value)
        }
        if kind != "positive" and expected_conditions:
            errors.append(f"{cid}: non-positive evidence cannot carry expected condition signals")
        _validate_observation(raw, cid, expected_conditions, errors, leakage)
        variants[family].add(kind)
        raw_hashes[family].add(hashlib.sha256(_canonical(raw).encode("utf-8")).hexdigest())
        count += 1

    for family, kinds in sorted(variants.items()):
        if kinds == VARIANTS and len(raw_hashes[family]) != 4:
            errors.append(f"{family}: completed family must have four distinct raw observations")

    return {
        "evaluation_kind": "fresh_blind_v6_partial_raw_precheck_unscored",
        "passed": not errors,
        "errors": errors,
        "label_leakage": leakage,
        "evidence_count": count,
        "family_count": len(variants),
        "complete_family_count": sum(1 for kinds in variants.values() if kinds == VARIANTS),
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def main() -> int:
    result = precheck()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
