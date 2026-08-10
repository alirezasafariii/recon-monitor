from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from analysis_benchmark import run_benchmark
from analysis_standards import standards_for_family
from hypothesis_admission import FAMILY_ADMISSION_POLICIES

POSTFREEZE_EVALUATOR_VERSION = "1.1.0"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "benchmarks" / "golden" / "splits" / "v4.json"
PRIOR_CORPUS = ROOT / "benchmarks" / "golden" / "analysis_golden_v3.jsonl"

PREREGISTERED_GATES: dict[str, float] = {
    "precision_min": 0.93,
    "recall_min": 0.85,
    "top1_accuracy_min": 0.90,
    "top3_accuracy_min": 0.95,
    "abstention_accuracy_min": 0.90,
    "false_promotion_rate_max": 0.05,
    "brier_score_max": 0.15,
    "ece_max": 0.15,
    "standards_coverage_min": 1.0,
    "source_root_leakage_rate_max": 0.0,
}

VALID_VARIANTS = {"positive", "near_miss", "secure_negative", "sparse_noisy"}
FORBIDDEN_EVIDENCE_SOURCES = {
    "knowledge", "external_writeup", "owasp", "owasp_wstg", "wstg",
    "mitre_cwe", "cwe", "standards", "provenance",
}
FORBIDDEN_EVIDENCE_TYPES = {"knowledge_reference", "wstg_reference", "cwe_reference"}
LOW_MARGIN_THRESHOLD = 0.08


def _norm(value: Any) -> str:
    return str(value or "").strip()


def load_manifest(path: str | Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Post-freeze manifest must be a JSON object")
    return data


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        row = json.loads(text)
        if not isinstance(row, dict):
            raise ValueError(f"JSONL line {line_no} is not an object")
        case_id = _norm(row.get("id"))
        if not case_id:
            raise ValueError(f"JSONL line {line_no} has no id")
        if case_id in seen:
            raise ValueError(f"Duplicate case id: {case_id}")
        seen.add(case_id)
        rows.append(row)
    return rows


def git_blob_sha1(path: str | Path) -> str:
    data = Path(path).read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_freeze(manifest: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    protected = manifest.get("protected_files") if isinstance(manifest.get("protected_files"), Mapping) else {}
    if not protected:
        errors.append("manifest has no protected_files")

    checked: dict[str, dict[str, str]] = {}
    for rel_path, expected in sorted(protected.items()):
        path = ROOT / str(rel_path)
        if not path.is_file():
            errors.append(f"protected file missing: {rel_path}")
            continue
        actual = git_blob_sha1(path)
        checked[str(rel_path)] = {"expected": _norm(expected), "actual": actual}
        if actual != _norm(expected):
            errors.append(
                f"POST-FREEZE MODEL MUTATION DETECTED: {rel_path} "
                f"expected {_norm(expected)} got {actual}"
            )

    gates = manifest.get("acceptance_gates") if isinstance(manifest.get("acceptance_gates"), Mapping) else {}
    if dict(gates) != PREREGISTERED_GATES:
        errors.append("preregistered acceptance gates changed after freeze")

    frozen = manifest.get("frozen_engine") if isinstance(manifest.get("frozen_engine"), Mapping) else {}
    expected_versions = {
        "analysis_engine_version": "6.5.0",
        "ranking_engine_version": "1.0.0",
        "ranking_rule_version": "2026.08.10.6.5",
    }
    for key, expected in expected_versions.items():
        if _norm(frozen.get(key)) != expected:
            errors.append(f"frozen {key} changed")
    if _norm(manifest.get("frozen_head_sha")) != "de3d6f210a52c409a60f9ffb861bc283790ea8fe":
        errors.append("frozen head SHA changed")

    prior = manifest.get("prior_evaluations") if isinstance(manifest.get("prior_evaluations"), Mapping) else {}
    v3 = prior.get("analysis_golden_v3") if isinstance(prior.get("analysis_golden_v3"), Mapping) else {}
    if _norm(v3.get("evaluation_status")) != "consumed_diagnostic":
        errors.append("analysis_golden_v3 must remain marked consumed_diagnostic")

    return {
        "passed": not errors,
        "errors": errors,
        "checked_files": checked,
        "frozen_head_sha": _norm(manifest.get("frozen_head_sha")),
    }


def _evidence_is_external(item: Mapping[str, Any]) -> bool:
    source = _norm(item.get("source")).lower()
    group = _norm(item.get("source_group")).lower()
    kind = _norm(item.get("type")).lower()
    return (
        source in FORBIDDEN_EVIDENCE_SOURCES
        or group in FORBIDDEN_EVIDENCE_SOURCES
        or kind in FORBIDDEN_EVIDENCE_TYPES
    )


def _provenance(row: Mapping[str, Any]) -> Mapping[str, Any]:
    return row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}


def _root(row: Mapping[str, Any]) -> str:
    return _norm(row.get("source_root"))


def _url(row: Mapping[str, Any]) -> str:
    return _norm(_provenance(row).get("url"))


def _reference(row: Mapping[str, Any]) -> str:
    return _norm(_provenance(row).get("reference"))


def _prior_identity_sets(
    prior_cases: Iterable[Mapping[str, Any]],
) -> tuple[set[str], set[str], set[str]]:
    roots: set[str] = set()
    urls: set[str] = set()
    refs: set[str] = set()
    for row in prior_cases:
        root = _root(row)
        url = _url(row)
        ref = _reference(row)
        if root:
            roots.add(root.lower())
        if url:
            urls.add(url.lower().rstrip("/"))
        if ref:
            refs.add(ref.lower())
    return roots, urls, refs


def _canonical_standard_ids(family: str) -> tuple[set[str], set[str]]:
    canonical = standards_for_family(family)
    wstg = {str(item.get("id")) for item in canonical.get("wstg", []) if item.get("id")}
    cwe = {str(item.get("id")) for item in canonical.get("cwe", []) if item.get("id")}
    return wstg, cwe


def validate_postfreeze_corpus(
    cases: Iterable[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    prior_cases: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    rows = [dict(case) for case in cases]
    errors: list[str] = []
    prior_roots, prior_urls, prior_refs = _prior_identity_sets(prior_cases)
    by_root: dict[str, list[dict[str, Any]]] = defaultdict(list)
    source_projects: set[str] = set()
    urls: set[str] = set()
    refs: set[str] = set()
    ids: set[str] = set()

    source_policy = manifest.get("source_policy") if isinstance(manifest.get("source_policy"), Mapping) else {}
    allowed_source_kinds = {
        _norm(value) for value in source_policy.get("allowed_source_kinds", []) if _norm(value)
    }
    if not allowed_source_kinds:
        errors.append("manifest source_policy has no allowed_source_kinds")

    for row in rows:
        cid = _norm(row.get("id"))
        family = _norm(row.get("family"))
        variant = _norm(row.get("case_kind"))
        split = _norm(row.get("split"))
        root = _root(row)
        project = _norm(row.get("source_project"))
        source_date = _norm(row.get("source_date") or _provenance(row).get("source_date"))
        source_kind = _norm(_provenance(row).get("source_kind"))
        url = _url(row)
        ref = _reference(row)
        expected = row.get("expected") if isinstance(row.get("expected"), Mapping) else {}

        if not cid:
            errors.append("case missing id")
        elif cid in ids:
            errors.append(f"duplicate case id: {cid}")
        ids.add(cid)

        known_family = family in FAMILY_ADMISSION_POLICIES
        if not family:
            errors.append(f"{cid}: missing family")
        elif not known_family:
            errors.append(f"{cid}: unknown family {family}")

        if variant not in VALID_VARIANTS:
            errors.append(f"{cid}: invalid case_kind {variant!r}")
        if split != "postfreeze_holdout":
            errors.append(f"{cid}: split must be postfreeze_holdout")
        if not root:
            errors.append(f"{cid}: missing source_root")
        else:
            by_root[root].append(row)
        if not project:
            errors.append(f"{cid}: missing source_project")
        else:
            source_projects.add(project)
        if not source_date:
            errors.append(f"{cid}: missing source_date")
        if source_kind not in allowed_source_kinds:
            errors.append(f"{cid}: source_kind {source_kind!r} is not allowed")
        if not ref:
            errors.append(f"{cid}: missing provenance reference")

        if not url.startswith("https://"):
            errors.append(f"{cid}: provenance URL must be HTTPS")
        if url:
            normalized_url = url.lower().rstrip("/")
            urls.add(normalized_url)
            if normalized_url in prior_urls:
                errors.append(f"{cid}: provenance URL already exists in analysis_golden_v3")
        if ref:
            normalized_ref = ref.lower()
            refs.add(normalized_ref)
            if normalized_ref in prior_refs:
                errors.append(f"{cid}: provenance reference already exists in analysis_golden_v3")
        if root and root.lower() in prior_roots:
            errors.append(f"{cid}: source_root already exists in analysis_golden_v3")

        if _norm(expected.get("family")) != family:
            errors.append(f"{cid}: expected family must equal case family")
        if variant == "positive" and not bool(expected.get("admitted")):
            errors.append(f"{cid}: positive case must expect admission")
        if variant in {"near_miss", "secure_negative", "sparse_noisy"} and bool(expected.get("admitted")):
            errors.append(f"{cid}: {variant} must expect abstention under the 6.5 evidence contract")

        for bucket_name in ("support", "contradict"):
            bucket = row.get(bucket_name) if isinstance(row.get(bucket_name), list) else []
            for item in bucket:
                if isinstance(item, Mapping) and _evidence_is_external(item):
                    errors.append(f"{cid}: external knowledge leaked into target {bucket_name} evidence")

        standards = row.get("standards") if isinstance(row.get("standards"), Mapping) else {}
        row_wstg = {_norm(value) for value in standards.get("wstg", []) if _norm(value)}
        row_cwe = {_norm(value) for value in standards.get("cwe", []) if _norm(value)}
        if known_family:
            canonical_wstg, canonical_cwe = _canonical_standard_ids(family)
            if not row_wstg or not row_wstg.issubset(canonical_wstg):
                errors.append(f"{cid}: WSTG grounding missing or inconsistent")
            if not row_cwe or not row_cwe.issubset(canonical_cwe):
                errors.append(f"{cid}: CWE grounding missing or inconsistent")

    required_variants = set(
        manifest.get("collection_target", {}).get("required_case_variants", [])
        if isinstance(manifest.get("collection_target"), Mapping)
        else []
    )
    for root, root_rows in sorted(by_root.items()):
        variants = Counter(_norm(row.get("case_kind")) for row in root_rows)
        if set(variants) != required_variants:
            errors.append(
                f"{root}: root variants are {sorted(variants)}; expected {sorted(required_variants)}"
            )
        if any(count != 1 for count in variants.values()):
            errors.append(f"{root}: each root variant must appear exactly once")

        root_urls = {_url(row).lower().rstrip("/") for row in root_rows if _url(row)}
        root_refs = {_reference(row).lower() for row in root_rows if _reference(row)}
        root_projects = {
            _norm(row.get("source_project")) for row in root_rows if _norm(row.get("source_project"))
        }
        root_kinds = {_norm(_provenance(row).get("source_kind")) for row in root_rows}
        root_dates = {
            _norm(row.get("source_date") or _provenance(row).get("source_date")) for row in root_rows
        }
        root_families = {_norm(row.get("family")) for row in root_rows}
        if len(root_urls) != 1:
            errors.append(f"{root}: all variants must share one provenance URL")
        if len(root_refs) != 1:
            errors.append(f"{root}: all variants must share one provenance reference")
        if len(root_projects) != 1:
            errors.append(f"{root}: all variants must share one source_project")
        if len(root_kinds) != 1:
            errors.append(f"{root}: all variants must share one source_kind")
        if len(root_dates) != 1:
            errors.append(f"{root}: all variants must share one source_date")
        if len(root_families) != 1:
            errors.append(f"{root}: all variants must share one expected family")

    corpus_cfg = manifest.get("corpus") if isinstance(manifest.get("corpus"), Mapping) else {}
    manifest_roots = {_norm(value) for value in corpus_cfg.get("source_roots", []) if _norm(value)}
    case_roots = set(by_root)
    if manifest_roots and manifest_roots != case_roots:
        errors.append("manifest source_roots do not exactly match corpus roots")

    sealed = bool(corpus_cfg.get("sealed"))
    target = manifest.get("collection_target") if isinstance(manifest.get("collection_target"), Mapping) else {}
    if sealed:
        expected_roots = int(target.get("new_source_roots") or 0)
        expected_cases = int(target.get("target_cases") or 0)
        if len(case_roots) != expected_roots:
            errors.append(f"sealed corpus root count {len(case_roots)} != preregistered {expected_roots}")
        if len(rows) != expected_cases:
            errors.append(f"sealed corpus case count {len(rows)} != preregistered {expected_cases}")

    return {
        "passed": not errors,
        "errors": errors,
        "sealed": sealed,
        "case_count": len(rows),
        "source_root_count": len(by_root),
        "source_project_count": len(source_projects),
        "source_url_count": len(urls),
        "source_reference_count": len(refs),
        "source_root_leakage_count": sum(1 for root in by_root if root.lower() in prior_roots),
        "source_url_leakage_count": sum(1 for url in urls if url in prior_urls),
        "source_reference_leakage_count": sum(1 for ref in refs if ref in prior_refs),
    }


def verify_corpus_seal(manifest: Mapping[str, Any], corpus_path: str | Path) -> dict[str, Any]:
    corpus_cfg = manifest.get("corpus") if isinstance(manifest.get("corpus"), Mapping) else {}
    expected = _norm(corpus_cfg.get("sha256"))
    sealed = bool(corpus_cfg.get("sealed"))
    actual = sha256_file(corpus_path)
    errors: list[str] = []
    if not sealed:
        errors.append("post-freeze corpus is not sealed; evaluation is forbidden")
    if not expected:
        errors.append("sealed corpus has no SHA256 in manifest")
    elif actual != expected:
        errors.append(f"corpus SHA256 mismatch: expected {expected}, got {actual}")
    return {
        "passed": not errors,
        "errors": errors,
        "expected_sha256": expected,
        "actual_sha256": actual,
        "sealed": sealed,
    }


def _fresh_quality_gate(metrics: Mapping[str, Any], leakage_rate: float) -> dict[str, Any]:
    values = {
        "precision_min": float(metrics.get("precision", 0.0)),
        "recall_min": float(metrics.get("recall", 0.0)),
        "top1_accuracy_min": float(metrics.get("top1_accuracy", 0.0)),
        "top3_accuracy_min": float(metrics.get("top3_accuracy", 0.0)),
        "abstention_accuracy_min": float(metrics.get("abstention_accuracy", 0.0)),
        "false_promotion_rate_max": float(metrics.get("false_promotion_rate", 1.0)),
        "brier_score_max": float(metrics.get("brier_score", 1.0)),
        "ece_max": float(metrics.get("ece", 1.0)),
        "standards_coverage_min": float(metrics.get("standards_coverage", 0.0)),
        "source_root_leakage_rate_max": float(leakage_rate),
    }
    failures: list[dict[str, Any]] = []
    for gate, threshold in PREREGISTERED_GATES.items():
        value = values[gate]
        if gate.endswith("_max"):
            ok = value <= threshold
            direction = "max"
        else:
            ok = value >= threshold
            direction = "min"
        if not ok:
            failures.append(
                {"metric": gate, "value": value, "threshold": threshold, "direction": direction}
            )
    return {
        "passed": not failures,
        "thresholds": dict(PREREGISTERED_GATES),
        "values": values,
        "failures": failures,
    }


def _diagnostics(report: Mapping[str, Any]) -> dict[str, Any]:
    rows = report.get("cases") if isinstance(report.get("cases"), list) else []
    ranked = [row for row in rows if row.get("rank_required")]
    correct = [row for row in ranked if row.get("top1_correct")]
    low_margin_correct = [
        row for row in correct if float(row.get("top1_margin") or 0.0) < LOW_MARGIN_THRESHOLD
    ]
    wrong = [row for row in ranked if not row.get("top1_correct")]
    wrong_top3 = [row for row in wrong if row.get("top3_correct")]

    by_family: dict[str, dict[str, int]] = defaultdict(
        lambda: {"ranked": 0, "top1_correct": 0, "positive": 0, "admitted": 0}
    )
    for row in rows:
        family = _norm(row.get("family"))
        if row.get("rank_required"):
            by_family[family]["ranked"] += 1
            if row.get("top1_correct"):
                by_family[family]["top1_correct"] += 1
        if row.get("expected_admitted"):
            by_family[family]["positive"] += 1
            if family in set(row.get("admitted_families") or []):
                by_family[family]["admitted"] += 1

    family_metrics: dict[str, dict[str, float | int]] = {}
    for family, values in sorted(by_family.items()):
        ranked_count = values["ranked"]
        positive_count = values["positive"]
        family_metrics[family] = {
            **values,
            "top1_accuracy": round(values["top1_correct"] / ranked_count, 6) if ranked_count else 0.0,
            "positive_recall": round(values["admitted"] / positive_count, 6) if positive_count else 0.0,
        }

    return {
        "low_margin_threshold": LOW_MARGIN_THRESHOLD,
        "low_margin_correct_count": len(low_margin_correct),
        "low_margin_correct_rate": round(len(low_margin_correct) / len(correct), 6) if correct else 0.0,
        "wrong_top1_but_correct_top3_count": len(wrong_top3),
        "wrong_top1_but_correct_top3_rate": round(len(wrong_top3) / len(wrong), 6) if wrong else 0.0,
        "ranking_error_count": len(wrong),
        "ranking_errors": wrong,
        "family_metrics": family_metrics,
    }


def evaluate_postfreeze(
    manifest_path: str | Path = DEFAULT_MANIFEST,
    corpus_path: str | Path | None = None,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    freeze = validate_freeze(manifest)
    if not freeze["passed"]:
        raise RuntimeError("Post-freeze integrity failed: " + "; ".join(freeze["errors"]))

    corpus_cfg = manifest.get("corpus") if isinstance(manifest.get("corpus"), Mapping) else {}
    corpus = Path(corpus_path or ROOT / _norm(corpus_cfg.get("path")))
    prior_cases = load_jsonl(PRIOR_CORPUS)
    cases = load_jsonl(corpus)
    validation = validate_postfreeze_corpus(cases, manifest, prior_cases)
    if not validation["passed"]:
        raise RuntimeError(
            "Post-freeze corpus validation failed: " + "; ".join(validation["errors"])
        )

    seal = verify_corpus_seal(manifest, corpus)
    if not seal["passed"]:
        raise RuntimeError("Post-freeze evaluation refused: " + "; ".join(seal["errors"]))

    report = run_benchmark(cases)
    leakage_denominator = max(1, validation["source_root_count"])
    leakage_rate = round(validation["source_root_leakage_count"] / leakage_denominator, 6)
    gate = _fresh_quality_gate(report["metrics"], leakage_rate)
    return {
        "postfreeze_evaluator_version": POSTFREEZE_EVALUATOR_VERSION,
        "evaluation_status": "fresh_postfreeze",
        "frozen_head_sha": _norm(manifest.get("frozen_head_sha")),
        "frozen_engine": manifest.get("frozen_engine"),
        "corpus_sha256": seal["actual_sha256"],
        "corpus_validation": validation,
        "freeze_validation": freeze,
        "metrics": report["metrics"],
        "confusion_matrix": report.get("confusion_matrix", {}),
        "diagnostics": _diagnostics(report),
        "quality_gate": gate,
        "cases": report.get("cases", []),
    }


def collection_status(manifest_path: str | Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    freeze = validate_freeze(manifest)
    corpus_cfg = manifest.get("corpus") if isinstance(manifest.get("corpus"), Mapping) else {}
    path_text = _norm(corpus_cfg.get("path"))
    corpus_path = ROOT / path_text if path_text else None
    if not corpus_path or not corpus_path.is_file():
        return {
            "postfreeze_evaluator_version": POSTFREEZE_EVALUATOR_VERSION,
            "evaluation_status": _norm(manifest.get("evaluation_status")),
            "freeze_validation": freeze,
            "corpus_present": False,
            "sealed": bool(corpus_cfg.get("sealed")),
            "collection_target": manifest.get("collection_target"),
        }

    prior_cases = load_jsonl(PRIOR_CORPUS)
    cases = load_jsonl(corpus_path)
    validation = validate_postfreeze_corpus(cases, manifest, prior_cases)
    return {
        "postfreeze_evaluator_version": POSTFREEZE_EVALUATOR_VERSION,
        "evaluation_status": _norm(manifest.get("evaluation_status")),
        "freeze_validation": freeze,
        "corpus_present": True,
        "sealed": bool(corpus_cfg.get("sealed")),
        "corpus_validation": validation,
        "collection_target": manifest.get("collection_target"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analysis 6.6 fresh post-freeze blind evaluation"
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--corpus", default=None)
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Evaluate only after the corpus is sealed and hashed",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    try:
        result = (
            evaluate_postfreeze(args.manifest, args.corpus)
            if args.evaluate
            else collection_status(args.manifest)
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        result = {
            "passed": False,
            "error": str(exc),
            "evaluation_status": "refused" if args.evaluate else "invalid_collection",
        }
        print(json.dumps(result, indent=2, sort_keys=True) if args.as_json else result["error"])
        return 2

    passed = (
        bool(result.get("quality_gate", {}).get("passed"))
        if args.evaluate
        else bool(result.get("freeze_validation", {}).get("passed"))
        and bool(result.get("corpus_validation", {"passed": True}).get("passed"))
    )
    result["passed"] = passed
    print(
        json.dumps(result, indent=2, sort_keys=True)
        if args.as_json
        else json.dumps(result, sort_keys=True)
    )
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
