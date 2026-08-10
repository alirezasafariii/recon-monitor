from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from analysis_postfreeze import (
    DEFAULT_MANIFEST,
    PRIOR_CORPUS,
    ROOT,
    load_jsonl,
    load_manifest,
    sha256_file,
    validate_freeze,
    validate_postfreeze_corpus,
)
from analysis_postfreeze_build import DEFAULT_CORPUS, build_and_validate, corpus_bytes
from analysis_postfreeze_sources import DEFAULT_SOURCE_REGISTRY, load_source_registry, validate_source_registry

POSTFREEZE_SEALER_VERSION = "1.0.0"


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _deterministic_sha256(cases: list[Mapping[str, Any]]) -> str:
    return hashlib.sha256(corpus_bytes(cases)).hexdigest()


def prepare_sealed_manifest(
    manifest: Mapping[str, Any],
    *,
    corpus_sha256: str,
    source_roots: list[str],
) -> dict[str, Any]:
    result = json.loads(json.dumps(dict(manifest)))
    if _norm(result.get("evaluation_status")) != "corpus_materialized":
        raise RuntimeError("corpus must be materialized before sealing")

    corpus = result.get("corpus") if isinstance(result.get("corpus"), dict) else {}
    if bool(corpus.get("sealed")):
        raise RuntimeError("post-freeze corpus is already sealed")
    if corpus.get("sha256") not in (None, ""):
        raise RuntimeError("unsealed corpus unexpectedly already has a SHA256")

    manifest_roots = [_norm(value) for value in corpus.get("source_roots", []) if _norm(value)]
    if manifest_roots != source_roots:
        raise RuntimeError("manifest source-root order does not match verified source registry")

    corpus["sha256"] = corpus_sha256
    corpus["sealed"] = True
    result["corpus"] = corpus
    result["evaluation_status"] = "sealed_postfreeze"
    return result


def seal(
    *,
    manifest_path: str | Path = DEFAULT_MANIFEST,
    registry_path: str | Path = DEFAULT_SOURCE_REGISTRY,
    corpus_path: str | Path = DEFAULT_CORPUS,
    prior_corpus_path: str | Path = PRIOR_CORPUS,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    freeze = validate_freeze(manifest)
    if not freeze.get("passed"):
        raise RuntimeError("freeze validation failed: " + "; ".join(freeze.get("errors", [])))

    source_report = validate_source_registry(
        registry_path=registry_path,
        manifest_path=manifest_path,
        prior_corpus_path=prior_corpus_path,
    )
    if not source_report.get("passed") or not source_report.get("collection_complete"):
        raise RuntimeError("source registry is not complete/valid")

    cases = load_jsonl(corpus_path)
    prior_cases = load_jsonl(prior_corpus_path)
    corpus_validation = validate_postfreeze_corpus(cases, manifest, prior_cases)
    if not corpus_validation.get("passed"):
        raise RuntimeError(
            "materialized corpus validation failed: " + "; ".join(corpus_validation.get("errors", []))
        )
    if corpus_validation.get("case_count") != 200 or corpus_validation.get("source_root_count") != 50:
        raise RuntimeError("materialized corpus does not match preregistered 50-root / 200-case target")

    # Rebuild deterministically from the frozen source registry and require byte identity.
    build_report = build_and_validate(
        registry_path=registry_path,
        manifest_path=manifest_path,
        prior_corpus_path=prior_corpus_path,
    )
    materialized_bytes = Path(corpus_path).read_bytes()
    rebuilt_bytes = corpus_bytes(build_report["cases"])
    if materialized_bytes != rebuilt_bytes:
        raise RuntimeError("materialized corpus differs from deterministic frozen-registry rebuild")

    actual_sha = sha256_file(corpus_path)
    rebuilt_sha = _deterministic_sha256(build_report["cases"])
    if actual_sha != rebuilt_sha or actual_sha != build_report["sha256"]:
        raise RuntimeError("corpus SHA256 disagrees with deterministic rebuild")

    roots = [_norm(row.get("source_root")) for row in load_source_registry(registry_path)]
    sealed_manifest = prepare_sealed_manifest(
        manifest,
        corpus_sha256=actual_sha,
        source_roots=roots,
    )
    Path(manifest_path).write_text(json.dumps(sealed_manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    return {
        "postfreeze_sealer_version": POSTFREEZE_SEALER_VERSION,
        "evaluation_status": sealed_manifest["evaluation_status"],
        "frozen_head_sha": sealed_manifest["frozen_head_sha"],
        "corpus_sha256": actual_sha,
        "sealed": True,
        "source_root_count": corpus_validation["source_root_count"],
        "case_count": corpus_validation["case_count"],
        "source_root_leakage_count": corpus_validation["source_root_leakage_count"],
        "source_url_leakage_count": corpus_validation["source_url_leakage_count"],
        "source_reference_leakage_count": corpus_validation["source_reference_leakage_count"],
        "scored": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal Analysis 6.6 corpus without scoring it")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--registry", default=str(DEFAULT_SOURCE_REGISTRY))
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    try:
        result = seal(
            manifest_path=args.manifest,
            registry_path=args.registry,
            corpus_path=args.corpus,
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        result = {"passed": False, "error": str(exc), "scored": False}
        print(json.dumps(result, indent=2, sort_keys=True) if args.as_json else result["error"])
        return 2

    result["passed"] = True
    print(json.dumps(result, indent=2, sort_keys=True) if args.as_json else json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
