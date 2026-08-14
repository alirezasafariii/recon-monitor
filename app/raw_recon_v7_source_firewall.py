from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from raw_recon_corpus import ROOT, prior_source_index
import raw_recon_v6_source_firewall as v6
from v7_external_exposure import CORPUS_V1_COMMIT, EXPECTED_SOURCE_COUNT

VERSION = "1.1.0"
RULE_VERSION = "2026.08.14.6.33.v7.unseen.1"
V6_CORPUS = ROOT / "benchmarks/raw/analysis_raw_v6.jsonl"
V6_SOURCE_FILES = (
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
PRIOR_SCOPE = (
    "all_exposed_sources_and_provenance_v1_through_consumed_v6_plus_"
    f"real_world_corpus_v1@{CORPUS_V1_COMMIT}"
)


def _add_corpus(index: dict[str, set[str]], path: Path) -> None:
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


def exposure_index() -> dict[str, set[str]]:
    index = {key: set(values) for key, values in v6.exposure_index().items()}
    _add_corpus(index, V6_CORPUS)
    for path in V6_SOURCE_FILES:
        value = v6._read_json(path)
        if value is None:
            continue
        for row in v6._walk_rows(value):
            v6._add_row(index, row)
    if V6_EVIDENCE_DIR.exists():
        for path in sorted(V6_EVIDENCE_DIR.glob("*.json")):
            value = v6._read_json(path)
            if value is None:
                continue
            for row in v6._walk_rows(value):
                v6._add_row(index, row)
    _add_external_exclusions(index)
    return index


def check_candidate(row: Mapping[str, Any], *, index: Mapping[str, set[str]] | None = None) -> dict[str, Any]:
    prior = index if index is not None else exposure_index()
    check = v6.check_candidate(row, index=prior)
    check = dict(check)
    check["firewall_version"] = VERSION
    check["firewall_rule_version"] = RULE_VERSION
    check["prior_scope"] = PRIOR_SCOPE
    check["corpus_v1_commit_pin"] = CORPUS_V1_COMMIT
    check["scoring_executed"] = False
    return check


def validate_shortlist(rows: Iterable[Mapping[str, Any]], *, required_count: int = 36) -> dict[str, Any]:
    candidates = [dict(row) for row in rows]
    prior = exposure_index()
    checks = [check_candidate(row, index=prior) for row in candidates]
    roots = {v6._identity(row.get("source_root")) for row in candidates if v6._identity(row.get("source_root"))}
    projects = {v6._identity(row.get("source_project")) for row in candidates if v6._identity(row.get("source_project"))}
    failed = [check for check in checks if not check["allowed"]]
    errors: list[str] = []
    if len(candidates) != required_count:
        errors.append(f"shortlist count must be {required_count}: {len(candidates)}")
    if len(roots) != required_count:
        errors.append(f"shortlist must contain {required_count} unique roots: {len(roots)}")
    if len(projects) != required_count:
        errors.append(f"shortlist must contain {required_count} unique projects: {len(projects)}")
    if failed:
        errors.append(f"v7 fresh-source firewall rejected {len(failed)} candidate(s)")
    return {
        "passed": not errors,
        "errors": errors,
        "candidate_count": len(candidates),
        "unique_root_count": len(roots),
        "unique_project_count": len(projects),
        "rejected": failed,
        "firewall_version": VERSION,
        "firewall_rule_version": RULE_VERSION,
        "prior_scope": PRIOR_SCOPE,
        "corpus_v1_commit_pin": CORPUS_V1_COMMIT,
        "scoring_executed": False,
    }


__all__ = ["VERSION", "RULE_VERSION", "PRIOR_SCOPE", "exposure_index", "check_candidate", "validate_shortlist"]
