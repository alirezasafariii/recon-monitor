from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from analysis_postfreeze import DEFAULT_MANIFEST, PRIOR_CORPUS, ROOT, load_jsonl, load_manifest, validate_postfreeze_corpus
from analysis_postfreeze_sources import DEFAULT_SOURCE_REGISTRY, load_source_registry, validate_source_registry

POSTFREEZE_BUILDER_VERSION = "1.0.0"
DEFAULT_CORPUS = ROOT / "benchmarks" / "golden" / "analysis_golden_v4.jsonl"

_GENERIC_SURFACE_TYPES = {
    "input_parameter",
    "query_parameter",
    "body_parameter",
    "path_parameter",
    "file_operation",
    "download_operation",
    "archive_operation",
    "upload_operation",
    "import_operation",
    "state_change",
    "stateful_operation",
    "redirect_response",
    "client_navigation",
}


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _evidence(signal: str, *, source: str, source_group: str, role: str) -> dict[str, str]:
    return {
        "type": signal,
        "source": source,
        "source_group": source_group,
        "text": f"post-freeze target observation: {signal}",
        "evidence_role": role,
    }


def _surface_evidence(signals: Iterable[str]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    clean = [_norm(value) for value in signals if _norm(value)]
    for index, signal in enumerate(clean):
        if index == 0:
            source, group = "recon_surface", "request_surface"
        elif index == 1:
            source, group = "semantic_analysis", "semantic_surface"
        else:
            source, group = "endpoint_contract", f"surface_contract_{index + 1}"
        items.append(_evidence(signal, source=source, source_group=group, role="surface"))

    # Near-miss and secure-negative cases should fail because the condition is
    # missing/blocked, not merely because a single observation source exists.
    if len(clean) == 1:
        items.append(
            _evidence(
                clean[0],
                source="endpoint_contract",
                source_group="surface_corroboration",
                role="surface_corroboration",
            )
        )
    return items


def _decisive_evidence(signals: Iterable[str]) -> list[dict[str, str]]:
    return [
        _evidence(
            _norm(signal),
            source="stored_behavior",
            source_group=f"vulnerability_condition_{index + 1}",
            role="condition",
        )
        for index, signal in enumerate(signals)
        if _norm(signal)
    ]


def _control_evidence(signal: str) -> list[dict[str, str]]:
    clean = _norm(signal)
    if not clean:
        return []
    return [
        _evidence(
            clean,
            source="source_review",
            source_group="security_control",
            role="blocking_control",
        )
    ]


def _sparse_signal(surface: Iterable[str]) -> str:
    clean = [_norm(value) for value in surface if _norm(value)]
    if not clean:
        return ""
    specific = [value for value in clean if value not in _GENERIC_SURFACE_TYPES]
    return specific[-1] if specific else clean[0]


def _provenance(root: Mapping[str, Any]) -> dict[str, Any]:
    raw = root.get("provenance") if isinstance(root.get("provenance"), Mapping) else {}
    return {
        "source_kind": _norm(raw.get("source_kind")),
        "url": _norm(raw.get("url")),
        "reference": _norm(raw.get("reference")),
        "basis": _norm(root.get("basis")),
    }


def _base_case(root: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "family": _norm(root.get("family")),
        "source_root": _norm(root.get("source_root")),
        "source_project": _norm(root.get("source_project")),
        "source_date": _norm(root.get("source_date")),
        "split": "postfreeze_holdout",
        "provenance": _provenance(root),
        "standards": root.get("standards") if isinstance(root.get("standards"), Mapping) else {},
    }


def build_root_cases(root: Mapping[str, Any]) -> list[dict[str, Any]]:
    base = _base_case(root)
    family = base["family"]
    root_id = base["source_root"]
    adjudication = root.get("adjudication") if isinstance(root.get("adjudication"), Mapping) else {}
    surface = [_norm(value) for value in adjudication.get("surface", []) if _norm(value)]
    decisive = [_norm(value) for value in adjudication.get("decisive", []) if _norm(value)]
    control = _norm(adjudication.get("secure_control"))

    surface_support = _surface_evidence(surface)
    positive_id = f"{family}:postfreeze:{root_id}:positive"
    positive = {
        **base,
        "id": positive_id,
        "case_kind": "positive",
        "difficulty": "real_world",
        "evidence_completeness": "complete",
        "noise_level": "low",
        "rank_required": True,
        "expected": {"family": family, "admitted": True},
        "support": [*surface_support, *_decisive_evidence(decisive)],
        "contradict": [],
    }

    near_miss = {
        **base,
        "id": f"{family}:postfreeze:{root_id}:near_miss",
        "case_kind": "near_miss",
        "difficulty": "hard",
        "evidence_completeness": "partial",
        "noise_level": "low",
        "rank_required": True,
        "derived_from": positive_id,
        "expected": {"family": family, "admitted": False},
        "support": list(surface_support),
        "contradict": [],
    }

    secure_negative = {
        **base,
        "id": f"{family}:postfreeze:{root_id}:secure_negative",
        "case_kind": "secure_negative",
        "difficulty": "hard",
        "evidence_completeness": "partial",
        "noise_level": "low",
        "rank_required": True,
        "derived_from": positive_id,
        "expected": {"family": family, "admitted": False},
        "support": list(surface_support),
        "contradict": _control_evidence(control),
    }

    sparse = _sparse_signal(surface)
    sparse_support = []
    if sparse:
        sparse_support.append(
            _evidence(
                sparse,
                source="recon_surface",
                source_group="sparse_surface",
                role="sparse_surface",
            )
        )
    sparse_support.append(
        _evidence(
            "route_shape_noise",
            source="recon_noise",
            source_group="non_decisive_noise",
            role="noise",
        )
    )
    sparse_noisy = {
        **base,
        "id": f"{family}:postfreeze:{root_id}:sparse_noisy",
        "case_kind": "sparse_noisy",
        "difficulty": "hard",
        "evidence_completeness": "sparse",
        "noise_level": "medium",
        "rank_required": False,
        "derived_from": positive_id,
        "expected": {"family": family, "admitted": False},
        "support": sparse_support,
        "contradict": [],
    }

    return [positive, near_miss, secure_negative, sparse_noisy]


def build_cases(roots: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for root in roots:
        cases.extend(build_root_cases(root))
    return cases


def corpus_bytes(cases: Iterable[Mapping[str, Any]]) -> bytes:
    lines = [json.dumps(dict(case), sort_keys=True, separators=(",", ":"), ensure_ascii=False) for case in cases]
    return ("\n".join(lines) + "\n").encode("utf-8")


def corpus_sha256(cases: Iterable[Mapping[str, Any]]) -> str:
    return hashlib.sha256(corpus_bytes(cases)).hexdigest()


def build_and_validate(
    *,
    registry_path: str | Path = DEFAULT_SOURCE_REGISTRY,
    manifest_path: str | Path = DEFAULT_MANIFEST,
    prior_corpus_path: str | Path = PRIOR_CORPUS,
) -> dict[str, Any]:
    registry_validation = validate_source_registry(
        registry_path=registry_path,
        manifest_path=manifest_path,
        prior_corpus_path=prior_corpus_path,
    )
    if not registry_validation.get("passed") or not registry_validation.get("collection_complete"):
        raise RuntimeError(
            "source registry is not complete/valid: "
            + "; ".join(registry_validation.get("errors", []) + registry_validation.get("warnings", []))
        )

    roots = load_source_registry(registry_path)
    cases = build_cases(roots)
    manifest = load_manifest(manifest_path)
    prior_cases = load_jsonl(prior_corpus_path)
    corpus_validation = validate_postfreeze_corpus(cases, manifest, prior_cases)
    if not corpus_validation.get("passed"):
        raise RuntimeError(
            "generated corpus validation failed: " + "; ".join(corpus_validation.get("errors", []))
        )

    return {
        "postfreeze_builder_version": POSTFREEZE_BUILDER_VERSION,
        "source_registry": registry_validation,
        "corpus_validation": corpus_validation,
        "case_count": len(cases),
        "positive_count": sum(1 for case in cases if case["case_kind"] == "positive"),
        "near_miss_count": sum(1 for case in cases if case["case_kind"] == "near_miss"),
        "secure_negative_count": sum(1 for case in cases if case["case_kind"] == "secure_negative"),
        "sparse_noisy_count": sum(1 for case in cases if case["case_kind"] == "sparse_noisy"),
        "rank_required_count": sum(1 for case in cases if case.get("rank_required")),
        "source_root_count": len(roots),
        "sha256": corpus_sha256(cases),
        "cases": cases,
    }


def write_corpus(
    output: str | Path = DEFAULT_CORPUS,
    *,
    registry_path: str | Path = DEFAULT_SOURCE_REGISTRY,
    manifest_path: str | Path = DEFAULT_MANIFEST,
    prior_corpus_path: str | Path = PRIOR_CORPUS,
) -> dict[str, Any]:
    report = build_and_validate(
        registry_path=registry_path,
        manifest_path=manifest_path,
        prior_corpus_path=prior_corpus_path,
    )
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(corpus_bytes(report["cases"]))
    return {key: value for key, value in report.items() if key != "cases"} | {"output": str(target)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Analysis 6.6 post-freeze cases without scoring them")
    parser.add_argument("--output", default=str(DEFAULT_CORPUS))
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    try:
        if args.write:
            result = write_corpus(args.output)
        else:
            built = build_and_validate()
            result = {key: value for key, value in built.items() if key != "cases"}
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        result = {"passed": False, "error": str(exc)}
        print(json.dumps(result, indent=2, sort_keys=True) if args.as_json else result["error"])
        return 2

    result["passed"] = True
    print(json.dumps(result, indent=2, sort_keys=True) if args.as_json else json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
