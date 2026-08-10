from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from family_detectors.registry import DETECTOR_SPECS
from hypothesis_admission import FAMILY_ADMISSION_POLICIES

RAW_CORPUS_VALIDATOR_VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parents[1]
PRIOR_CORPORA = (
    ROOT / "benchmarks" / "golden" / "analysis_golden_v3.jsonl",
    ROOT / "benchmarks" / "golden" / "analysis_golden_v4.jsonl",
)
VALID_CASE_KINDS = {"positive", "near_miss", "secure_negative", "sparse_noisy"}
REQUIRED_CASE_KINDS = frozenset(VALID_CASE_KINDS)
ALLOWED_SOURCE_KINDS = {
    "github_reviewed_advisory",
    "project_security_advisory",
    "vendor_advisory",
}
MIN_SOURCE_ROOTS = 24
MIN_SOURCE_PROJECTS = 18
MIN_POSITIVE_FAMILIES = 14
MIN_CASES_PER_ROOT = 4

# The blind raw corpus must not carry engine-native evidence labels inside raw input.
# Labels belong only in expected/provenance metadata. This prevents a benchmark case
# from simply telling the detector which vulnerability signal to emit.
ENGINE_SIGNAL_KEYS = frozenset(
    signal
    for spec in DETECTOR_SPECS.values()
    for signal in spec.target_signal_allowlist
)
FORBIDDEN_RAW_KEYS = ENGINE_SIGNAL_KEYS | {
    "family_scope",
    "evidence_namespace",
    "extractor_id",
    "extractor_version",
    "detector_signal_class",
    "detector_counts_as_target_evidence",
    "execution_family",
    "execution_strategy",
    "execution_basis",
    "admitted",
    "bug_family",
    "vulnerability_family",
    "cwe",
    "wstg",
    "writeup",
}


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            keys.add(_norm(key))
            keys.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_walk_keys(child))
    return keys


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        rows.append(json.loads(text))
    return rows


def prior_source_index(paths: Iterable[Path] = PRIOR_CORPORA) -> dict[str, set[str]]:
    roots: set[str] = set()
    urls: set[str] = set()
    projects: set[str] = set()
    for path in paths:
        for row in _load_jsonl(path):
            root = _norm(row.get("source_root"))
            project = _norm(row.get("source_project"))
            provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
            url = _norm(provenance.get("url"))
            if root:
                roots.add(root)
            if project:
                projects.add(project)
            if url:
                urls.add(url)
    return {"roots": roots, "urls": urls, "projects": projects}


def load_raw_cases(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    rows = _load_jsonl(source)
    if not rows:
        raise ValueError(f"Raw recon corpus is empty: {source}")
    seen: set[str] = set()
    for row in rows:
        cid = _norm(row.get("id"))
        if not cid:
            raise ValueError("Raw recon case is missing id")
        if cid in seen:
            raise ValueError(f"Duplicate raw recon case id: {cid}")
        seen.add(cid)
    return rows


def validate_raw_corpus(
    cases: Iterable[Mapping[str, Any]],
    *,
    require_collection_floor: bool = True,
    enforce_prior_independence: bool = True,
) -> dict[str, Any]:
    rows = [dict(row) for row in cases]
    errors: list[str] = []
    prior = prior_source_index() if enforce_prior_independence else {"roots": set(), "urls": set(), "projects": set()}
    roots: dict[str, list[dict[str, Any]]] = defaultdict(list)
    families = Counter()
    projects: set[str] = set()
    source_kinds = Counter()
    case_kinds = Counter()
    prior_root_overlap: set[str] = set()
    prior_url_overlap: set[str] = set()

    for row in rows:
        cid = _norm(row.get("id"))
        family = _norm(row.get("family"))
        kind = _norm(row.get("case_kind"))
        root = _norm(row.get("source_root"))
        project = _norm(row.get("source_project"))
        source_date = _norm(row.get("source_date"))
        split = _norm(row.get("split"))
        provenance = row.get("provenance") if isinstance(row.get("provenance"), Mapping) else {}
        source_kind = _norm(provenance.get("source_kind"))
        url = _norm(provenance.get("url"))
        raw = row.get("raw") if isinstance(row.get("raw"), Mapping) else {}
        expected = row.get("expected") if isinstance(row.get("expected"), Mapping) else {}

        if family not in FAMILY_ADMISSION_POLICIES:
            errors.append(f"{cid}: unknown family {family!r}")
        if kind not in VALID_CASE_KINDS:
            errors.append(f"{cid}: invalid case_kind {kind!r}")
        if split != "postfreeze_holdout":
            errors.append(f"{cid}: split must be postfreeze_holdout")
        if not root:
            errors.append(f"{cid}: missing source_root")
        if not project:
            errors.append(f"{cid}: missing source_project")
        if not source_date:
            errors.append(f"{cid}: missing source_date")
        if source_kind not in ALLOWED_SOURCE_KINDS:
            errors.append(f"{cid}: unsupported source_kind {source_kind!r}")
        if not url.startswith("https://"):
            errors.append(f"{cid}: provenance URL must be HTTPS")
        if provenance.get("primary_source") is not True:
            errors.append(f"{cid}: provenance.primary_source must be true")
        if _norm(expected.get("family")) != family:
            errors.append(f"{cid}: expected.family must equal family")
        expected_admitted = bool(expected.get("admitted"))
        if kind == "positive" and not expected_admitted:
            errors.append(f"{cid}: positive case must expect admission")
        if kind != "positive" and expected_admitted:
            errors.append(f"{cid}: non-positive case must expect abstention for target family")

        if not raw:
            errors.append(f"{cid}: missing raw artifact")
        else:
            target = _norm(raw.get("target"))
            endpoint = _norm(raw.get("endpoint"))
            method = _norm(raw.get("method")).upper()
            if not target:
                errors.append(f"{cid}: raw.target missing")
            if not endpoint:
                errors.append(f"{cid}: raw.endpoint missing")
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "UNKNOWN"}:
                errors.append(f"{cid}: invalid raw.method {method!r}")
            if not isinstance(raw.get("endpoint_schema", {}), Mapping):
                errors.append(f"{cid}: raw.endpoint_schema must be an object")
            if not isinstance(raw.get("details", {}), Mapping):
                errors.append(f"{cid}: raw.details must be an object")
            raw_keys = _walk_keys(raw)
            leaked = sorted(raw_keys & FORBIDDEN_RAW_KEYS)
            if leaked:
                errors.append(f"{cid}: engine-native labels leaked into raw artifact: {leaked}")
            if "evidence_for" in raw or "evidence_against" in raw:
                errors.append(f"{cid}: holdout raw artifact cannot provide typed evidence arrays")

        expected_conditions = expected.get("condition_signals") or []
        if not isinstance(expected_conditions, list):
            errors.append(f"{cid}: expected.condition_signals must be a list")
        elif family in DETECTOR_SPECS:
            allowed = DETECTOR_SPECS[family].condition_signals
            unknown = sorted({_norm(value) for value in expected_conditions if _norm(value)} - set(allowed))
            if unknown:
                errors.append(f"{cid}: expected condition signals are not canonical for {family}: {unknown}")

        roots[root].append(row)
        projects.add(project)
        source_kinds[source_kind] += 1
        case_kinds[kind] += 1
        if kind == "positive":
            families[family] += 1
        if root and root in prior["roots"]:
            prior_root_overlap.add(root)
        if url and url in prior["urls"]:
            prior_url_overlap.add(url)

    for root, group in sorted(roots.items()):
        if not root:
            continue
        kinds = {_norm(row.get("case_kind")) for row in group}
        group_projects = {_norm(row.get("source_project")) for row in group}
        group_families = {_norm(row.get("family")) for row in group}
        group_urls = {
            _norm((row.get("provenance") or {}).get("url"))
            for row in group
            if isinstance(row.get("provenance"), Mapping)
        }
        if kinds != REQUIRED_CASE_KINDS:
            errors.append(f"{root}: required variants mismatch got={sorted(kinds)}")
        if len(group) != MIN_CASES_PER_ROOT:
            errors.append(f"{root}: expected exactly {MIN_CASES_PER_ROOT} variants, got {len(group)}")
        if len(group_projects) != 1:
            errors.append(f"{root}: source root spans multiple projects {sorted(group_projects)}")
        if len(group_families) != 1:
            errors.append(f"{root}: source root spans multiple families {sorted(group_families)}")
        if len(group_urls) != 1:
            errors.append(f"{root}: source root must have one canonical provenance URL")

    if prior_root_overlap:
        errors.append(f"prior source_root overlap detected: {sorted(prior_root_overlap)}")
    if prior_url_overlap:
        errors.append(f"prior provenance URL overlap detected: {sorted(prior_url_overlap)}")

    if require_collection_floor:
        if len(roots) < MIN_SOURCE_ROOTS:
            errors.append(f"source roots below floor: {len(roots)}/{MIN_SOURCE_ROOTS}")
        if len(projects) < MIN_SOURCE_PROJECTS:
            errors.append(f"source projects below floor: {len(projects)}/{MIN_SOURCE_PROJECTS}")
        if len(families) < MIN_POSITIVE_FAMILIES:
            errors.append(f"positive families below floor: {len(families)}/{MIN_POSITIVE_FAMILIES}")

    return {
        "validator_version": RAW_CORPUS_VALIDATOR_VERSION,
        "passed": not errors,
        "errors": errors,
        "case_count": len(rows),
        "source_root_count": len([root for root in roots if root]),
        "source_project_count": len(projects),
        "positive_family_count": len(families),
        "positive_family_roots": dict(sorted(families.items())),
        "case_kind_counts": dict(case_kinds),
        "source_kind_counts": dict(source_kinds),
        "prior_source_root_overlap_count": len(prior_root_overlap),
        "prior_url_overlap_count": len(prior_url_overlap),
        "raw_label_leakage_forbidden_key_count": len(FORBIDDEN_RAW_KEYS),
    }
