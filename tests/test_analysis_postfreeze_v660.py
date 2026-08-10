from __future__ import annotations

import json
from pathlib import Path

import pytest

from analysis_postfreeze import (
    DEFAULT_MANIFEST,
    PREREGISTERED_GATES,
    collection_status,
    load_manifest,
    validate_freeze,
    validate_postfreeze_corpus,
)


def _evidence(kind: str, group: str, source: str = "stored_behavior") -> dict[str, str]:
    return {"type": kind, "source_group": group, "source": source, "text": kind}


def _root_cases(root: str = "BLIND-ROOT-001", url: str = "https://example.invalid/advisory/1") -> list[dict]:
    base = {
        "family": "ssrf",
        "source_root": root,
        "source_project": "blind-project",
        "source_date": "2026-08-10",
        "split": "postfreeze_holdout",
        "provenance": {
            "source_kind": "github_security_lab",
            "url": url,
            "reference": root,
        },
        "standards": {"wstg": ["WSTG-INPV-19"], "cwe": ["CWE-918"]},
    }
    return [
        {
            **base,
            "id": f"{root}:positive",
            "case_kind": "positive",
            "expected": {"family": "ssrf", "admitted": True},
            "support": [
                _evidence("url_parameter", "destination_surface", "endpoint_schema"),
                _evidence("backend_fetch", "server_behavior"),
            ],
            "contradict": [],
        },
        {
            **base,
            "id": f"{root}:near_miss",
            "case_kind": "near_miss",
            "expected": {"family": "ssrf", "admitted": False},
            "support": [_evidence("url_parameter", "destination_surface", "endpoint_schema")],
            "contradict": [],
        },
        {
            **base,
            "id": f"{root}:secure_negative",
            "case_kind": "secure_negative",
            "expected": {"family": "ssrf", "admitted": False},
            "support": [_evidence("url_parameter", "destination_surface", "endpoint_schema")],
            "contradict": [_evidence("host_allowlist", "destination_control", "source_review")],
        },
        {
            **base,
            "id": f"{root}:sparse_noisy",
            "case_kind": "sparse_noisy",
            "expected": {"family": "ssrf", "admitted": False},
            "support": [
                _evidence("remote_destination", "destination_surface", "endpoint_schema"),
                _evidence("query_parameter", "generic_input", "endpoint_schema"),
            ],
            "contradict": [],
        },
    ]


def test_v660_manifest_freezes_analysis_65_and_preregisters_gates() -> None:
    manifest = load_manifest(DEFAULT_MANIFEST)
    assert manifest["frozen_head_sha"] == "de3d6f210a52c409a60f9ffb861bc283790ea8fe"
    assert manifest["frozen_engine"]["analysis_engine_version"] == "6.5.0"
    assert manifest["frozen_engine"]["ranking_engine_version"] == "1.0.0"
    assert manifest["acceptance_gates"] == PREREGISTERED_GATES
    assert manifest["prior_evaluations"]["analysis_golden_v3"]["evaluation_status"] == "consumed_diagnostic"
    assert manifest["collection_target"]["new_source_roots"] == 50
    assert manifest["collection_target"]["target_cases"] == 200


def test_v660_protected_files_match_frozen_git_blobs() -> None:
    result = validate_freeze(load_manifest(DEFAULT_MANIFEST))
    assert result["passed"], result["errors"]
    assert len(result["checked_files"]) == 6


def test_v660_collection_mode_does_not_evaluate_unsealed_corpus() -> None:
    status = collection_status(DEFAULT_MANIFEST)
    assert status["freeze_validation"]["passed"]
    assert status["sealed"] is False
    assert status["evaluation_status"] == "collection_open"


def test_v660_requires_exactly_four_variants_per_source_root() -> None:
    manifest = load_manifest(DEFAULT_MANIFEST)
    result = validate_postfreeze_corpus(_root_cases(), manifest, [])
    assert result["passed"], result["errors"]
    assert result["source_root_count"] == 1
    assert result["case_count"] == 4

    incomplete = _root_cases()[:-1]
    result = validate_postfreeze_corpus(incomplete, manifest, [])
    assert not result["passed"]
    assert any("root variants" in error for error in result["errors"])


def test_v660_rejects_v3_root_url_or_reference_reuse() -> None:
    manifest = load_manifest(DEFAULT_MANIFEST)
    prior = [{
        "source_root": "OLD-ROOT",
        "provenance": {
            "url": "https://example.invalid/advisory/old",
            "reference": "OLD-REFERENCE",
        },
    }]

    reused_root = _root_cases(root="OLD-ROOT", url="https://example.invalid/advisory/new")
    result = validate_postfreeze_corpus(reused_root, manifest, prior)
    assert not result["passed"]
    assert any("source_root already exists" in error for error in result["errors"])

    reused_url = _root_cases(root="NEW-ROOT", url="https://example.invalid/advisory/old")
    result = validate_postfreeze_corpus(reused_url, manifest, prior)
    assert not result["passed"]
    assert any("provenance URL already exists" in error for error in result["errors"])


def test_v660_rejects_external_knowledge_as_target_evidence() -> None:
    manifest = load_manifest(DEFAULT_MANIFEST)
    cases = _root_cases()
    cases[0]["support"].append({
        "type": "wstg_reference",
        "source_group": "standards",
        "source": "owasp_wstg",
        "text": "must never count as target evidence",
    })
    result = validate_postfreeze_corpus(cases, manifest, [])
    assert not result["passed"]
    assert any("external knowledge leaked" in error for error in result["errors"])
