from __future__ import annotations

import copy
import unittest

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


class AnalysisPostFreeze660Tests(unittest.TestCase):
    def test_manifest_freezes_analysis_65_and_preregisters_gates(self) -> None:
        manifest = load_manifest(DEFAULT_MANIFEST)
        self.assertEqual(manifest["frozen_head_sha"], "de3d6f210a52c409a60f9ffb861bc283790ea8fe")
        self.assertEqual(manifest["frozen_engine"]["analysis_engine_version"], "6.5.0")
        self.assertEqual(manifest["frozen_engine"]["ranking_engine_version"], "1.0.0")
        self.assertEqual(manifest["acceptance_gates"], PREREGISTERED_GATES)
        self.assertEqual(manifest["prior_evaluations"]["analysis_golden_v3"]["evaluation_status"], "consumed_diagnostic")
        self.assertEqual(manifest["collection_target"]["new_source_roots"], 50)
        self.assertEqual(manifest["collection_target"]["target_cases"], 200)

    def test_protected_files_match_frozen_git_blobs(self) -> None:
        result = validate_freeze(load_manifest(DEFAULT_MANIFEST))
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(len(result["checked_files"]), 6)

    def test_collection_mode_does_not_evaluate_unsealed_corpus(self) -> None:
        status = collection_status(DEFAULT_MANIFEST)
        self.assertTrue(status["freeze_validation"]["passed"])
        self.assertFalse(status["sealed"])
        self.assertIn(status["evaluation_status"], {"collection_open", "corpus_materialized"})

    def test_requires_exactly_four_variants_per_source_root(self) -> None:
        manifest = load_manifest(DEFAULT_MANIFEST)
        result = validate_postfreeze_corpus(_root_cases(), manifest, [])
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(result["source_root_count"], 1)
        self.assertEqual(result["case_count"], 4)

        incomplete = _root_cases()[:-1]
        result = validate_postfreeze_corpus(incomplete, manifest, [])
        self.assertFalse(result["passed"])
        self.assertTrue(any("root variants" in error for error in result["errors"]))

    def test_rejects_v3_root_url_or_reference_reuse(self) -> None:
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
        self.assertFalse(result["passed"])
        self.assertTrue(any("source_root already exists" in error for error in result["errors"]))

        reused_url = _root_cases(root="NEW-ROOT", url="https://example.invalid/advisory/old")
        result = validate_postfreeze_corpus(reused_url, manifest, prior)
        self.assertFalse(result["passed"])
        self.assertTrue(any("provenance URL already exists" in error for error in result["errors"]))

        reused_ref = _root_cases(root="OLD-REFERENCE", url="https://example.invalid/advisory/newer")
        result = validate_postfreeze_corpus(reused_ref, manifest, prior)
        self.assertFalse(result["passed"])
        self.assertTrue(any("provenance reference already exists" in error for error in result["errors"]))

    def test_rejects_external_knowledge_as_target_evidence(self) -> None:
        manifest = load_manifest(DEFAULT_MANIFEST)
        cases = _root_cases()
        cases[0]["support"].append({
            "type": "wstg_reference",
            "source_group": "standards",
            "source": "owasp_wstg",
            "text": "must never count as target evidence",
        })
        result = validate_postfreeze_corpus(cases, manifest, [])
        self.assertFalse(result["passed"])
        self.assertTrue(any("external knowledge leaked" in error for error in result["errors"]))

    def test_rejects_unknown_family_and_unapproved_source_kind(self) -> None:
        manifest = load_manifest(DEFAULT_MANIFEST)
        cases = _root_cases()
        for row in cases:
            row["family"] = "imaginary_family"
            row["expected"] = {"family": "imaginary_family", "admitted": row["case_kind"] == "positive"}
            row["provenance"] = {**row["provenance"], "source_kind": "secondary_blog"}
        result = validate_postfreeze_corpus(cases, manifest, [])
        self.assertFalse(result["passed"])
        self.assertTrue(any("unknown family" in error for error in result["errors"]))
        self.assertTrue(any("source_kind" in error and "not allowed" in error for error in result["errors"]))

    def test_rejects_missing_source_date(self) -> None:
        manifest = load_manifest(DEFAULT_MANIFEST)
        cases = _root_cases()
        for row in cases:
            row.pop("source_date", None)
        result = validate_postfreeze_corpus(cases, manifest, [])
        self.assertFalse(result["passed"])
        self.assertTrue(any("missing source_date" in error for error in result["errors"]))

    def test_rejects_noncanonical_wstg_or_cwe_grounding(self) -> None:
        manifest = load_manifest(DEFAULT_MANIFEST)
        cases = copy.deepcopy(_root_cases())
        for row in cases:
            row["standards"] = {"wstg": ["WSTG-FAKE-01"], "cwe": ["CWE-999999"]}
        result = validate_postfreeze_corpus(cases, manifest, [])
        self.assertFalse(result["passed"])
        self.assertTrue(any("WSTG grounding missing or inconsistent" in error for error in result["errors"]))
        self.assertTrue(any("CWE grounding missing or inconsistent" in error for error in result["errors"]))

    def test_variants_must_share_family_date_source_kind_and_project(self) -> None:
        manifest = load_manifest(DEFAULT_MANIFEST)
        cases = _root_cases()
        cases[3]["source_date"] = "2026-08-09"
        cases[2]["source_project"] = "different-project"
        cases[1]["provenance"] = {**cases[1]["provenance"], "source_kind": "vendor_advisory"}
        result = validate_postfreeze_corpus(cases, manifest, [])
        self.assertFalse(result["passed"])
        self.assertTrue(any("share one source_date" in error for error in result["errors"]))
        self.assertTrue(any("share one source_project" in error for error in result["errors"]))
        self.assertTrue(any("share one source_kind" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
