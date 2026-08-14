from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from raw_recon_corpus import ROOT

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.1"
DEFAULT_FREEZE = ROOT / "benchmarks/raw/sources/v6_corpus_freeze.json"
DEFAULT_MANIFEST = ROOT / "benchmarks/raw/sources/v6_freeze_manifest.sha256"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_freeze(
    freeze_path: Path = DEFAULT_FREEZE,
    *,
    require_freeze: bool = False,
    require_evaluator_frozen: bool = False,
) -> dict[str, Any]:
    errors: list[str] = []
    if not freeze_path.exists():
        if require_freeze:
            errors.append("v6 corpus freeze is required but missing")
        return {
            "verifier_version": VERSION,
            "verifier_rule_version": RULE_VERSION,
            "freeze_present": False,
            "passed": not errors,
            "errors": errors,
        }

    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    if freeze.get("scoring_executed") is not False:
        errors.append("freeze must be unscored")
    if freeze.get("first_blind_consumed") is not False:
        errors.append("first blind must be unconsumed before score authorization")
    if require_evaluator_frozen and freeze.get("first_blind_evaluator_frozen") is not True:
        errors.append("first blind evaluator is not frozen")

    protected = freeze.get("protected_sha256") if isinstance(freeze.get("protected_sha256"), dict) else {}
    if not protected:
        errors.append("freeze protected_sha256 is empty")

    actual: dict[str, str] = {}
    for rel, expected in sorted(protected.items()):
        path = ROOT / rel
        if not path.exists():
            errors.append(f"protected path missing: {rel}")
            continue
        digest = _sha256(path)
        actual[rel] = digest
        if digest != str(expected):
            errors.append(f"protected hash mismatch: {rel}")

    manifest_path = DEFAULT_MANIFEST
    if manifest_path.exists():
        manifest_entries: dict[str, str] = {}
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            digest, rel = line.split(None, 1)
            manifest_entries[rel.strip()] = digest.strip()
        if manifest_entries != {str(k): str(v) for k, v in protected.items()}:
            errors.append("v6 freeze manifest does not match protected_sha256")

    return {
        "verifier_version": VERSION,
        "verifier_rule_version": RULE_VERSION,
        "freeze_present": True,
        "passed": not errors,
        "errors": errors,
        "protected_count": len(protected),
        "verified_count": len(actual),
        "first_blind_evaluator_frozen": freeze.get("first_blind_evaluator_frozen"),
        "first_blind_consumed": freeze.get("first_blind_consumed"),
        "scoring_executed": freeze.get("scoring_executed"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Analysis 6.31 freeze integrity")
    parser.add_argument("--require-freeze", action="store_true")
    parser.add_argument("--require-evaluator-frozen", action="store_true")
    args = parser.parse_args()
    result = verify_freeze(
        require_freeze=args.require_freeze,
        require_evaluator_frozen=args.require_evaluator_frozen,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
