from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from raw_recon_corpus import ROOT, prior_source_index
import raw_recon_v6_source_firewall as v6
from v7_external_exposure import CORPUS_V1_COMMIT, EXPECTED_SOURCE_COUNT

VERSION = "1.2.0"
RULE_VERSION = "2026.08.14.6.33.v7.unseen.3"

# Hard contamination means the source identity was actually materialized into a
# benchmark/calibration corpus that production Analysis could consume. Historical
# discovery candidate pools are intentionally *not* hard contamination: they are
# recorded separately as research pre-exposure and deprioritized during selection.
ENGINE_CORPUS_FILES = (
    ROOT / "benchmarks/golden/analysis_golden_v1.jsonl",
    ROOT / "benchmarks/golden/analysis_golden_v2.jsonl",
    ROOT / "benchmarks/golden/analysis_golden_v3.jsonl",
    ROOT / "benchmarks/golden/analysis_golden_v4.jsonl",
    ROOT / "benchmarks/raw/analysis_raw_v1.jsonl",
    ROOT / "benchmarks/raw/analysis_raw_v2.jsonl",
    ROOT / "benchmarks/raw/analysis_raw_v3.jsonl",
    ROOT / "benchmarks/raw/analysis_raw_v4.jsonl",
    ROOT / "benchmarks/raw/analysis_raw_v5.jsonl",
    ROOT / "benchmarks/raw/analysis_raw_v6.jsonl",
)
ENGINE_CALIBRATION_FILES = (
    ROOT / "benchmarks/calibration/analysis_630_open_redirect.json",
)

# These are metadata/research surfaces that may have been inspected by source
# discovery tooling but were never necessarily materialized or scored by Analysis.
# They are used only to annotate/deprioritize candidates, never to claim that the
# engine itself has seen a test.
V6_RESEARCH_FILES = (
    ROOT / "benchmarks/raw/sources/v6_candidates.json",
    ROOT / "benchmarks/raw/sources/v6_complement_overrides.json",
    ROOT / "benchmarks/raw/sources/v6_owasp_writeup_grounding.json",
    ROOT / "benchmarks/raw/sources/v6_owasp_writeup_candidates.json",
    ROOT / "benchmarks/raw/sources/v6_owasp_exact_overrides.json",
    ROOT / "benchmarks/raw/sources/v6_owasp_extension_grounding.json",
    ROOT / "benchmarks/raw/sources/v6_owasp_extension_candidates.json",
    ROOT / "benchmarks/raw/sources/v6_shortlist.json",
    ROOT / "benchmarks/raw/sources/v6_selection_final_report.json",
    ROOT / "benchmarks/raw/sources/v6_literal_source_research.json",
    ROOT / "benchmarks/raw/sources/v6_literal_linked_research.json",
    ROOT / "benchmarks/raw/sources/v6_literal_linked_summary.json",
    ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json",
    ROOT / "benchmarks/raw/sources/v6_literal_capture_verification.json",
)
V6_EVIDENCE_DIR = ROOT / "benchmarks/raw/sources/v6_capture_evidence"
EXTERNAL_EXCLUSIONS = ROOT / "benchmarks/raw/sources/v7_external_exclusions.json"

HARD_SCOPE = (
    "materialized_or_scored_golden_v1_v4_raw_v1_v6_and_calibration_plus_"
    f"real_world_corpus_v1@{CORPUS_V1_COMMIT}"
)
RESEARCH_SCOPE = "historical_unscored_candidate_and_source_research_metadata_v1_v6"
PRIOR_SCOPE = HARD_SCOPE


def _blank_index() -> dict[str, set[str]]:
    return {"roots": set(), "projects": set(), "urls": set(), "identifiers": set()}


def _require(path: Path) -> None:
    if not path.exists():
        raise RuntimeError(f"v7 engine exposure input missing; fail closed: {path.relative_to(ROOT)}")


def _add_corpus(index: dict[str, set[str]], path: Path, *, required: bool = False) -> None:
    if required:
        _require(path)
    if not path.exists():
        return
    corpus = prior_source_index((path,))
    roots = {v6._identity(value) for value in corpus["roots"] if v6._identity(value)}
    projects = {v6._identity(value) for value in corpus["projects"] if v6._identity(value)}
    urls = {v6.canonical_url(value) for value in corpus["urls"] if v6.canonical_url(value)}
    index["roots"].update(roots)
    index["projects"].update(projects)
    index["urls"].update(urls)
    for value in roots | urls:
        index["identifiers"].update(v6._identifiers(value))


def _add_json_rows(index: dict[str, set[str]], path: Path, *, required: bool = False) -> None:
    if required:
        _require(path)
    value = v6._read_json(path)
    if value is None:
        return
    for row in v6._walk_rows(value):
        v6._add_row(index, row)


def _add_external_exclusions(index: dict[str, set[str]]) -> None:
    value = v6._read_json(EXTERNAL_EXCLUSIONS)
    if not isinstance(value, Mapping):
        raise RuntimeError("v7 external exclusion registry missing; fail closed")
    source = value.get("source") if isinstance(value.get("source"), Mapping) else {}
    if str(source.get("commit_sha") or "") != CORPUS_V1_COMMIT:
        raise RuntimeError("v7 external exclusion registry commit pin mismatch")
    if int(value.get("source_count") or 0) != EXPECTED_SOURCE_COUNT:
        raise RuntimeError("v7 external exclusion registry must contain 100 Corpus V1 sources")
    if value.get("identity_only") is not True:
        raise RuntimeError("v7 external exclusion registry must be identity-only")
    if value.get("labels_imported") is not False or value.get("evidence_imported") is not False or value.get("scores_imported") is not False:
        raise RuntimeError("v7 external exclusion registry imported forbidden Corpus V1 data")
    rows = value.get("sources")
    if not isinstance(rows, list) or len(rows) != EXPECTED_SOURCE_COUNT:
        raise RuntimeError("v7 external exclusion registry source rows incomplete")
    for row in rows:
        if isinstance(row, Mapping):
            v6._add_row(index, row)
            for identifier in row.get("identifiers") or []:
                normalized = v6._identity(identifier)
                if normalized:
                    index["identifiers"].add(normalized)


def engine_exposure_index() -> dict[str, set[str]]:
    """Hard V7 contamination index: sources Analysis actually consumed.

    Corpus V1 is also hard-blocked by policy even though it has not been scored by
    production Analysis, because it is reserved for the independent calibration
    program and must not leak into this blind baseline.
    """
    index = _blank_index()
    for path in ENGINE_CORPUS_FILES:
        _add_corpus(index, path, required=True)
    for path in ENGINE_CALIBRATION_FILES:
        _add_json_rows(index, path, required=True)
    _add_external_exclusions(index)
    return index


def research_exposure_index() -> dict[str, set[str]]:
    """Broad metadata index used only to annotate research pre-exposure."""
    index = {key: set(values) for key, values in v6.exposure_index().items()}
    for path in V6_RESEARCH_FILES:
        _add_json_rows(index, path)
    if V6_EVIDENCE_DIR.exists():
        for path in sorted(V6_EVIDENCE_DIR.glob("*.json")):
            _add_json_rows(index, path)
    return index


def exposure_index() -> dict[str, set[str]]:
    """Compatibility alias used by discovery: only hard engine contamination."""
    return engine_exposure_index()


def _overlap(row: Mapping[str, Any], index: Mapping[str, set[str]]) -> dict[str, list[str]]:
    base = v6.check_candidate(row, index=index)
    return {
        "root": list(base["root_overlap"]),
        "project": list(base["project_overlap"]),
        "url": list(base["url_overlap"]),
        "identifier": list(base.get("identifier_overlap", [])),
    }


def check_candidate(
    row: Mapping[str, Any],
    *,
    index: Mapping[str, set[str]] | None = None,
    research_index: Mapping[str, set[str]] | None = None,
) -> dict[str, Any]:
    hard = index if index is not None else engine_exposure_index()
    hard_check = dict(v6.check_candidate(row, index=hard))
    engine_seen = not bool(hard_check["allowed"])

    research = research_index if research_index is not None else research_exposure_index()
    research_overlap = _overlap(row, research)
    research_preexposed = any(research_overlap.values())

    return {
        "allowed": not engine_seen,
        "engine_seen": engine_seen,
        "source_root": hard_check["source_root"],
        "source_project": hard_check["source_project"],
        "engine_root_overlap": list(hard_check["root_overlap"]),
        "engine_project_overlap": list(hard_check["project_overlap"]),
        "engine_url_overlap": list(hard_check["url_overlap"]),
        "engine_identifier_overlap": list(hard_check.get("identifier_overlap", [])),
        # Backward-compatible hard-overlap names.
        "root_overlap": list(hard_check["root_overlap"]),
        "project_overlap": list(hard_check["project_overlap"]),
        "url_overlap": list(hard_check["url_overlap"]),
        "identifier_overlap": list(hard_check.get("identifier_overlap", [])),
        "research_preexposed": research_preexposed,
        "research_root_overlap": research_overlap["root"],
        "research_project_overlap": research_overlap["project"],
        "research_url_overlap": research_overlap["url"],
        "research_identifier_overlap": research_overlap["identifier"],
        "checked_root_aliases": list(hard_check.get("checked_root_aliases", [])),
        "checked_project_aliases": list(hard_check.get("checked_project_aliases", [])),
        "firewall_version": VERSION,
        "firewall_rule_version": RULE_VERSION,
        "hard_scope": HARD_SCOPE,
        "research_scope": RESEARCH_SCOPE,
        "corpus_v1_commit_pin": CORPUS_V1_COMMIT,
        "scoring_executed": False,
    }


def validate_shortlist(rows: Iterable[Mapping[str, Any]], *, required_count: int = 36) -> dict[str, Any]:
    candidates = [dict(row) for row in rows]
    hard = engine_exposure_index()
    research = research_exposure_index()
    checks = [check_candidate(row, index=hard, research_index=research) for row in candidates]
    roots = {v6._identity(row.get("source_root")) for row in candidates if v6._identity(row.get("source_root"))}
    projects = {v6._identity(row.get("source_project")) for row in candidates if v6._identity(row.get("source_project"))}
    failed = [check for check in checks if not check["allowed"]]
    research_preexposed = [check for check in checks if check["research_preexposed"]]
    errors: list[str] = []
    if len(candidates) != required_count:
        errors.append(f"shortlist count must be {required_count}: {len(candidates)}")
    if len(roots) != required_count:
        errors.append(f"shortlist must contain {required_count} unique roots: {len(roots)}")
    if len(projects) != required_count:
        errors.append(f"shortlist must contain {required_count} unique projects: {len(projects)}")
    if failed:
        errors.append(f"v7 hard engine-exposure firewall rejected {len(failed)} candidate(s)")
    return {
        "passed": not errors,
        "errors": errors,
        "candidate_count": len(candidates),
        "unique_root_count": len(roots),
        "unique_project_count": len(projects),
        "engine_seen_count": len(failed),
        "research_preexposed_count": len(research_preexposed),
        "rejected": failed,
        "firewall_version": VERSION,
        "firewall_rule_version": RULE_VERSION,
        "hard_scope": HARD_SCOPE,
        "research_scope": RESEARCH_SCOPE,
        "corpus_v1_commit_pin": CORPUS_V1_COMMIT,
        "scoring_executed": False,
    }


__all__ = [
    "VERSION", "RULE_VERSION", "HARD_SCOPE", "RESEARCH_SCOPE", "PRIOR_SCOPE",
    "engine_exposure_index", "research_exposure_index", "exposure_index",
    "check_candidate", "validate_shortlist",
]
