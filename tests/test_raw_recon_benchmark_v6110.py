from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from raw_recon_benchmark import (
    RAW_QUALITY_GATES,
    RAW_RECON_BENCHMARK_RULE_VERSION,
    RAW_RECON_BENCHMARK_VERSION,
    evaluate_raw_case,
    run_raw_benchmark,
)
from raw_recon_corpus import (
    FORBIDDEN_RAW_KEYS,
    RAW_CORPUS_VALIDATOR_VERSION,
    validate_raw_corpus,
)


def case(*, cid: str, family: str, kind: str, raw: dict, condition_signals: list[str] | None = None) -> dict:
    return {
        "id": cid,
        "family": family,
        "case_kind": kind,
        "rank_required": kind != "sparse_noisy",
        "split": "postfreeze_holdout",
        "source_root": f"ROOT-{cid.rsplit('-', 1)[0]}",
        "source_project": "example/project",
        "source_date": "2026-08-11",
        "provenance": {
            "source_kind": "github_reviewed_advisory",
            "url": f"https://github.com/example/project/security/advisories/{cid.rsplit('-', 1)[0]}",
            "primary_source": True,
        },
        "raw": raw,
        "expected": {
            "family": family,
            "admitted": kind == "positive",
            "condition_signals": condition_signals or [],
        },
    }


class RawReconBenchmark6110Tests(unittest.TestCase):
    def test_versions_and_preregistered_gates(self):
        self.assertEqual(RAW_CORPUS_VALIDATOR_VERSION, "1.0.0")
        self.assertEqual(RAW_RECON_BENCHMARK_VERSION, "1.0.0")
        self.assertEqual(RAW_RECON_BENCHMARK_RULE_VERSION, "2026.08.11.6.11")
        self.assertEqual(RAW_QUALITY_GATES["admission_precision"], ("min", 0.93))
        self.assertEqual(RAW_QUALITY_GATES["false_promotion_rate"], ("max", 0.07))

    def test_raw_label_leakage_is_rejected(self):
        row = case(
            cid="GHSA-demo-positive",
            family="ssrf",
            kind="positive",
            raw={
                "target": "example.test",
                "endpoint": "/preview",
                "method": "POST",
                "endpoint_schema": {"body_fields": ["url"]},
                "details": {"server_fetch_observed": True},
            },
            condition_signals=["server_fetch_observed"],
        )
        report = validate_raw_corpus([row], require_collection_floor=False, enforce_prior_independence=False)
        self.assertFalse(report["passed"])
        self.assertTrue(any("engine-native labels leaked" in error for error in report["errors"]))
        self.assertIn("server_fetch_observed", FORBIDDEN_RAW_KEYS)

    def test_sql_raw_artifact_reaches_admission_without_typed_evidence(self):
        row = case(
            cid="GHSA-sql-positive",
            family="sql_injection",
            kind="positive",
            raw={
                "target": "shop.test",
                "endpoint": "/api/products/search",
                "method": "GET",
                "endpoint_schema": {"query_parameters": ["filter"]},
                "details": {"status_code": 500, "response_text": "SQL syntax error at or near SELECT"},
                "category": "database search query",
            },
            condition_signals=["database_error_observed"],
        )
        result = evaluate_raw_case(row)
        self.assertTrue(result["target_admitted"])
        self.assertIn("database_error_observed", result["target_condition_signals"])
        self.assertEqual(result["top1"], "sql_injection")
        self.assertTrue(result["end_to_end_pass"])

    def test_ssrf_server_fetch_is_raw_semantic_not_active_probe(self):
        row = case(
            cid="GHSA-ssrf-positive",
            family="ssrf",
            kind="positive",
            raw={
                "target": "app.test",
                "endpoint": "/api/preview",
                "method": "POST",
                "endpoint_schema": {"body_fields": ["url"]},
                "details": {"source_code": "def preview(url): return requests.get(url).text"},
            },
            condition_signals=["server_request_function"],
        )
        result = evaluate_raw_case(row)
        self.assertTrue(result["target_admitted"])
        self.assertIn("server_request_function", result["target_condition_signals"])
        self.assertNotIn("open_redirect", result["predicted_condition_families"])

    def test_cors_header_interaction_reaches_admission(self):
        origin = "https://untrusted.example"
        row = case(
            cid="GHSA-cors-positive",
            family="cors_misconfiguration",
            kind="positive",
            raw={
                "target": "api.test",
                "endpoint": "/api/me",
                "method": "GET",
                "endpoint_schema": {"authentication_hints": ["bearer"]},
                "details": {
                    "request_headers": {"Origin": origin},
                    "response_headers": {
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": "true",
                    },
                },
                "business_context": "identity",
            },
            condition_signals=["credentials_allowed", "authenticated_context"],
        )
        result = evaluate_raw_case(row)
        self.assertTrue(result["target_admitted"])
        self.assertEqual(result["top1"], "cors_misconfiguration")

    def test_negative_resource_control_abstains(self):
        row = case(
            cid="GHSA-resource-secure_negative",
            family="unrestricted_resource_consumption",
            kind="secure_negative",
            raw={
                "target": "api.test",
                "endpoint": "/api/export",
                "method": "GET",
                "endpoint_schema": {"query_parameters": ["limit"]},
                "details": {"status_code": 429},
            },
        )
        result = evaluate_raw_case(row)
        self.assertFalse(result["target_admitted"])
        self.assertEqual(result["admitted_families"], [])
        self.assertEqual(result["target_state"], "shadow_contradicted")
        self.assertTrue(result["end_to_end_pass"])

    def test_source_map_raw_response_is_end_to_end_positive(self):
        row = case(
            cid="GHSA-map-positive",
            family="source_map_exposure",
            kind="positive",
            raw={
                "target": "web.test",
                "endpoint": "https://web.test/assets/app.js.map",
                "method": "GET",
                "endpoint_schema": {},
                "details": {"status_code": 200, "response_body": '{"sources":["src/app.ts"],"sourcesContent":["const value = 1"]}'},
            },
            condition_signals=["direct_reachability"],
        )
        result = evaluate_raw_case(row)
        self.assertTrue(result["target_admitted"])
        self.assertIn("direct_reachability", result["target_condition_signals"])

    def test_secret_is_redacted_and_can_admit_from_raw_client_artifact(self):
        raw_secret = "ABCD1234EFGH5678IJKL9012MNOP3456"
        row = case(
            cid="GHSA-secret-positive",
            family="secret_exposure",
            kind="positive",
            raw={
                "target": "web.test",
                "endpoint": "https://web.test/assets/app.js",
                "method": "GET",
                "endpoint_schema": {},
                "details": {"status_code": 200, "source_code": f"const api_key = '{raw_secret}';"},
            },
            condition_signals=["high_entropy_value"],
        )
        result = evaluate_raw_case(row)
        self.assertTrue(result["target_admitted"])
        self.assertNotIn(raw_secret, repr(result))

    def test_metric_engine_separates_condition_routing_and_admission(self):
        positive = case(
            cid="GHSA-metric-positive",
            family="open_redirect",
            kind="positive",
            raw={
                "target": "https://app.test",
                "endpoint": "https://app.test/login",
                "method": "GET",
                "endpoint_schema": {"query_parameters": ["redirect"]},
                "details": {"status_code": 302, "response_headers": {"Location": "https://outside.example/landing"}},
            },
            condition_signals=["external_destination"],
        )
        negative = case(
            cid="GHSA-other-secure_negative",
            family="open_redirect",
            kind="secure_negative",
            raw={
                "target": "https://app.test",
                "endpoint": "https://app.test/login",
                "method": "GET",
                "endpoint_schema": {"query_parameters": ["redirect"]},
                "details": {"status_code": 302, "response_headers": {"Location": "/home"}},
            },
        )
        report = run_raw_benchmark([positive, negative], validation={"passed": True, "source_root_count": 2, "prior_source_root_overlap_count": 0, "errors": []})
        self.assertEqual(report["case_count"], 2)
        self.assertEqual(report["metrics"]["admission_recall"], 1.0)
        self.assertEqual(report["metrics"]["abstention_accuracy"], 1.0)
        self.assertEqual(report["metrics"]["prior_source_root_overlap_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
