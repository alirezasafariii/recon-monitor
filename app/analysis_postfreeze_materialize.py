from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from analysis_postfreeze import DEFAULT_MANIFEST, ROOT, load_manifest
from analysis_postfreeze_build import DEFAULT_CORPUS, write_corpus
from analysis_postfreeze_sources import DEFAULT_SOURCE_REGISTRY, load_source_registry, validate_source_registry

POSTFREEZE_MATERIALIZER_VERSION = "1.0.0"


def _norm(value: Any) -> str:
    return str(value or "").strip()


def prepare_manifest(manifest: Mapping[str, Any], roots: list[Mapping[str, Any]]) -> dict[str, Any]:
    result = json.loads(json.dumps(dict(manifest)))
    corpus = result.get("corpus") if isinstance(result.get("corpus"), dict) else {}
    if bool(corpus.get("sealed")):
        raise RuntimeError("refusing to materialize over a sealed post-freeze corpus")
    if _norm(result.get("evaluation_status")) not in {"collection_open", "corpus_materialized"}:
        raise RuntimeError(f"unexpected pre-evaluation status: {_norm(result.get('evaluation_status'))}")

    source_roots = [_norm(root.get("source_root")) for root in roots if _norm(root.get("source_root"))]
    if len(source_roots) != len(set(source_roots)):
        raise RuntimeError("source registry contains duplicate roots")

    corpus["path"] = "benchmarks/golden/analysis_golden_v4.jsonl"
    corpus["source_roots"] = source_roots
    corpus["sha256"] = None
    corpus["sealed"] = False
    result["corpus"] = corpus
    result["evaluation_status"] = "corpus_materialized"
    return result


def materialize(
    *,
    manifest_path: str | Path = DEFAULT_MANIFEST,
    registry_path: str | Path = DEFAULT_SOURCE_REGISTRY,
    corpus_path: str | Path = DEFAULT_CORPUS,
) -> dict[str, Any]:
    source_report = validate_source_registry(registry_path=registry_path, manifest_path=manifest_path)
    if not source_report.get("passed") or not source_report.get("collection_complete"):
        raise RuntimeError(
            "source registry is not complete: "
            + "; ".join(source_report.get("errors", []) + source_report.get("warnings", []))
        )

    roots = load_source_registry(registry_path)
    manifest = load_manifest(manifest_path)
    prepared = prepare_manifest(manifest, roots)

    manifest_target = Path(manifest_path)
    original = manifest_target.read_text(encoding="utf-8")
    try:
        manifest_target.write_text(json.dumps(prepared, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        build_report = write_corpus(
            corpus_path,
            registry_path=registry_path,
            manifest_path=manifest_path,
        )
    except Exception:
        manifest_target.write_text(original, encoding="utf-8")
        raise

    return {
        "postfreeze_materializer_version": POSTFREEZE_MATERIALIZER_VERSION,
        "evaluation_status": prepared["evaluation_status"],
        "sealed": prepared["corpus"]["sealed"],
        "manifest_sha256": prepared["corpus"]["sha256"],
        "source_root_count": len(prepared["corpus"]["source_roots"]),
        "case_count": build_report["case_count"],
        "generated_corpus_sha256": build_report["sha256"],
        "corpus": str(Path(corpus_path)),
        "manifest": str(manifest_target),
        "scored": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize Analysis 6.6 corpus without sealing or scoring")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--registry", default=str(DEFAULT_SOURCE_REGISTRY))
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    try:
        result = materialize(
            manifest_path=args.manifest,
            registry_path=args.registry,
            corpus_path=args.corpus,
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        result = {"passed": False, "error": str(exc)}
        print(json.dumps(result, indent=2, sort_keys=True) if args.as_json else result["error"])
        return 2

    result["passed"] = True
    print(json.dumps(result, indent=2, sort_keys=True) if args.as_json else json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
