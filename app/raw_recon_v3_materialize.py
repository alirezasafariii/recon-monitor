from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_v3_corpus import ROOT, validate_v3_corpus

MATERIALIZER_VERSION = "1.0.0"
DEFAULT_SHORTLIST = ROOT / "benchmarks" / "raw" / "sources" / "v3_shortlist.json"
DEFAULT_CORPUS = ROOT / "benchmarks" / "raw" / "analysis_raw_v3.jsonl"
DEFAULT_REPORT = ROOT / "benchmarks" / "raw" / "sources" / "v3_materialization_report.json"

EXPECTED_CONDITION = {
    "broken_object_authorization": "unauthorized_object_response",
    "broken_function_authorization": "unauthorized_function_response",
    "mass_assignment": "privileged_property_accepted",
    "authentication_session": "authentication_boundary_regression",
    "account_enumeration": "response_difference",
    "open_redirect": "external_destination",
    "ssrf": "server_fetch_observed",
    "file_upload": "dangerous_type_accepted",
    "path_traversal": "path_escape_observed",
    "information_disclosure": "public_observation",
    "cors_misconfiguration": "credentials_allowed",
    "race_condition": "duplicate_effect_observed",
    "sql_injection": "database_error_observed",
    "nosql_injection": "nosql_error_observed",
    "command_injection": "process_execution_reached",
    "server_side_template_injection": "template_engine_error_observed",
    "ldap_injection": "ldap_error_observed",
    "unrestricted_resource_consumption": "resource_exhaustion_differential",
    "security_misconfiguration": "stack_trace_exposed",
    "secret_exposure": "high_entropy_value",
}

METHOD_PATH_RE = re.compile(r"(?im)\b(GET|POST|PUT|PATCH|DELETE)\s+(/[A-Za-z0-9_./{}<>?&=:%+\-]+)")


def _fixture_target(project: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", project.lower()).strip("-") + ".fixture.invalid"


def _source_date(row: Mapping[str, Any]) -> str:
    published = str(row.get("published_at") or "")
    return published[:10] if len(published) >= 10 else "2026-08-12"


def _source_endpoint(row: Mapping[str, Any], fallback: str, fallback_method: str) -> tuple[str, str]:
    text = str(row.get("description") or "")
    match = METHOD_PATH_RE.search(text)
    if not match:
        return fallback_method, fallback
    method, path = match.group(1).upper(), match.group(2)
    path = path.split("`", 1)[0].strip()
    if not path.startswith("/") or len(path) > 220:
        return fallback_method, fallback
    return method, path


def _schema(*, query=(), body=(), path=(), object_ids=(), auth=()) -> dict[str, Any]:
    return {
        "query_parameters": list(query),
        "body_fields": list(body),
        "path_parameters": list(path),
        "object_identifiers": list(object_ids),
        "authentication_hints": list(auth),
    }


def _template(family: str, row: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    # All values are inert fixture artifacts. They represent the observable class
    # described by the primary advisory; they are not live requests or real secrets.
    if family == "broken_object_authorization":
        method, endpoint = _source_endpoint(row, "/api/resource/123", "GET")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(path=("id",), object_ids=("id",)), "business_context": "customer_data", "category": "object access"}
        return {
            "positive": {**base, "details": {"context_observations": [{"context": "unauthorized_user", "expected_access": "denied", "status_code": 200}]}},
            "near_miss": {**base, "details": {"context_observations": [{"context": "authorized_user", "expected_access": "allowed", "status_code": 200}]}},
            "secure_negative": {**base, "details": {"context_observations": [{"context": "unauthorized_user", "expected_access": "denied", "status_code": 403}]}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "broken_function_authorization":
        method, endpoint = _source_endpoint(row, "/admin/action", "POST")
        if not any(token in endpoint.lower() for token in ("admin", "manage", "permission", "staff", "privilege")):
            endpoint = "/admin/action"
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            method = "POST"
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(), "business_context": "administration", "category": "privileged admin function"}
        return {
            "positive": {**base, "details": {"context_observations": [{"context": "low_privilege_user", "role": "viewer", "expected_access": "denied", "status_code": 200}]}},
            "near_miss": {**base, "details": {"context_observations": [{"context": "admin_user", "role": "admin", "expected_access": "allowed", "status_code": 200}]}},
            "secure_negative": {**base, "details": {"context_observations": [{"context": "low_privilege_user", "role": "viewer", "expected_access": "denied", "status_code": 403}]}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "mass_assignment":
        method, endpoint = _source_endpoint(row, "/api/profile", "PATCH")
        if method not in {"POST", "PUT", "PATCH"}:
            method = "PATCH"
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(body=("display_name", "role")), "business_context": "identity", "category": "profile property update"}
        return {
            "positive": {**base, "details": {"status_code": 200, "request_json": {"display_name": "fixture", "role": "admin"}, "resource_before": {"display_name": "fixture", "role": "user"}, "response_json": {"display_name": "fixture", "role": "admin"}}},
            "near_miss": {**base, "details": {"status_code": 200, "request_json": {"display_name": "fixture", "role": "admin"}, "resource_before": {"display_name": "fixture", "role": "user"}, "response_json": {"display_name": "fixture", "role": "user"}}},
            "secure_negative": {**base, "details": {"status_code": 400, "request_json": {"display_name": "fixture", "role": "admin"}, "response_json": {"error": "property rejected"}}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "authentication_session":
        method, endpoint = _source_endpoint(row, "/api/login", "POST")
        if method not in {"POST", "PUT", "PATCH"}:
            method = "POST"
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(body=("username", "password"), auth=("session",)), "business_context": "identity", "category": "authentication login session"}
        return {
            "positive": {**base, "details": {"context_observations": [{"context": "unauthenticated_request", "expected_access": "denied", "status_code": 200}]}},
            "near_miss": {**base, "details": {"context_observations": [{"context": "authenticated_request", "expected_access": "allowed", "status_code": 200}]}},
            "secure_negative": {**base, "details": {"context_observations": [{"context": "unauthenticated_request", "expected_access": "denied", "status_code": 401}]}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "account_enumeration":
        method, endpoint = _source_endpoint(row, "/api/login", "POST")
        if "login" not in endpoint.lower():
            endpoint = "/api/login"
        if method not in {"POST", "GET"}:
            method = "POST"
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(body=("username", "password")), "business_context": "identity", "category": "login username lookup"}
        return {
            "positive": {**base, "details": {"context_observations": [{"context": "existing_username", "status_code": 401, "duration_ms": 52.0}, {"context": "absent_username", "status_code": 401, "duration_ms": 1.2}]}},
            "near_miss": {**base, "details": {"context_observations": [{"context": "existing_username", "status_code": 401, "duration_ms": 51.0}, {"context": "another_existing_username", "status_code": 401, "duration_ms": 52.0}]}},
            "secure_negative": {**base, "details": {"context_observations": [{"context": "existing_username", "status_code": 401, "duration_ms": 50.0}, {"context": "absent_username", "status_code": 401, "duration_ms": 50.0}]}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "open_redirect":
        method, endpoint = _source_endpoint(row, "/redirect", "GET")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(query=("redirect",)), "business_context": "general", "category": "redirect navigation"}
        return {
            "positive": {**base, "details": {"status_code": 302, "response_headers": {"Location": "https://external.fixture.invalid/landing"}}},
            "near_miss": {**base, "details": {"status_code": 302, "response_headers": {"Location": "/dashboard"}}},
            "secure_negative": {**base, "details": {"status_code": 400, "response_headers": {"Location": "https://" + _fixture_target(str(row.get("source_project") or "project")) + "/safe"}}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "ssrf":
        method, endpoint = _source_endpoint(row, "/api/fetch", "POST")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(body=("url",)), "business_context": "general", "category": "server fetch remote url"}
        return {
            "positive": {**base, "details": {"status_code": 200, "request_json": {"url": "http://127.0.0.1:8080/fixture"}, "outbound_request_url": "http://127.0.0.1:8080/fixture"}},
            "near_miss": {**base, "details": {"status_code": 200, "request_json": {"url": "https://external.fixture.invalid/data"}}},
            "secure_negative": {**base, "details": {"status_code": 403, "request_json": {"url": "http://127.0.0.1:8080/fixture"}, "response_text": "destination rejected"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "file_upload":
        method, endpoint = _source_endpoint(row, "/api/upload", "POST")
        if method not in {"POST", "PUT", "PATCH"}:
            method = "POST"
        base = {"endpoint": endpoint if "upload" in endpoint.lower() else "/api/upload", "method": method, "endpoint_schema": _schema(body=("file",)), "business_context": "general", "category": "file upload multipart/form-data"}
        return {
            "positive": {**base, "details": {"status_code": 200, "request_json": {"filename": "probe.svg", "content_type": "image/svg+xml"}, "stored_path": "/srv/uploads/probe.svg"}},
            "near_miss": {**base, "details": {"status_code": 200, "request_json": {"filename": "probe.txt", "content_type": "text/plain"}, "stored_path": "/srv/uploads/probe.txt"}},
            "secure_negative": {**base, "details": {"status_code": 415, "request_json": {"filename": "probe.svg", "content_type": "image/svg+xml"}, "response_text": "file type rejected"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "path_traversal":
        method, endpoint = _source_endpoint(row, "/download", "GET")
        base = {"endpoint": endpoint if any(x in endpoint.lower() for x in ("download", "file", "archive")) else "/download", "method": method, "endpoint_schema": _schema(query=("path",)), "business_context": "general", "category": "file download path"}
        return {
            "positive": {**base, "details": {"status_code": 200, "requested_path": "../outside/probe.txt", "base_path": "/srv/app/files", "resolved_path": "/srv/app/outside/probe.txt"}},
            "near_miss": {**base, "details": {"status_code": 200, "requested_path": "reports/probe.txt", "base_path": "/srv/app/files", "resolved_path": "/srv/app/files/reports/probe.txt"}},
            "secure_negative": {**base, "details": {"status_code": 403, "requested_path": "../outside/probe.txt", "base_path": "/srv/app/files", "response_text": "path rejected"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "information_disclosure":
        method, endpoint = _source_endpoint(row, "/api/status", "GET")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(), "business_context": "customer_data", "category": "diagnostic information disclosure"}
        return {
            "positive": {**base, "details": {"status_code": 200, "response_text": "Stored public response contains sensitive diagnostic material from an internal application path."}},
            "near_miss": {**base, "details": {"status_code": 200, "response_text": "Service is healthy."}},
            "secure_negative": {**base, "details": {"status_code": 403, "response_text": "Access denied."}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "cors_misconfiguration":
        method, endpoint = _source_endpoint(row, "/api/data", "GET")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(auth=("session",)), "business_context": "customer_data", "category": "cors cross-origin authenticated response"}
        return {
            "positive": {**base, "details": {"status_code": 200, "request_headers": {"Origin": "https://untrusted.fixture.invalid"}, "response_headers": {"Access-Control-Allow-Origin": "https://untrusted.fixture.invalid", "Access-Control-Allow-Credentials": "true"}}},
            "near_miss": {**base, "details": {"status_code": 200, "request_headers": {"Origin": "https://untrusted.fixture.invalid"}, "response_headers": {"Access-Control-Allow-Origin": "https://trusted.fixture.invalid"}}},
            "secure_negative": {**base, "details": {"status_code": 403, "request_headers": {"Origin": "https://untrusted.fixture.invalid"}, "response_headers": {"Access-Control-Allow-Origin": "https://trusted.fixture.invalid"}}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "sql_injection":
        method, endpoint = _source_endpoint(row, "/api/search", "GET")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(query=("q",)), "business_context": "general", "category": "sql database query search"}
        return {
            "positive": {**base, "details": {"status_code": 500, "response_text": "SQL syntax error at or near fixture input; SQLSTATE 42601"}},
            "near_miss": {**base, "details": {"status_code": 200, "response_text": "query returned zero rows"}},
            "secure_negative": {**base, "details": {"status_code": 400, "response_text": "input rejected"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "nosql_injection":
        method, endpoint = _source_endpoint(row, "/api/search", "POST")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(body=("filter",)), "business_context": "general", "category": "mongodb nosql document query filter"}
        return {
            "positive": {**base, "details": {"status_code": 500, "response_text": "MongoError: unknown operator $fixture in document query"}},
            "near_miss": {**base, "details": {"status_code": 200, "response_text": "document query returned zero results"}},
            "secure_negative": {**base, "details": {"status_code": 400, "response_text": "structured filter rejected"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "server_side_template_injection":
        method, endpoint = _source_endpoint(row, "/preview", "POST")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(body=("template",)), "business_context": "general", "category": "server-side template render"}
        return {
            "positive": {**base, "details": {"status_code": 500, "response_text": "jinja2 TemplateSyntaxError: unexpected fixture expression during render_template"}},
            "near_miss": {**base, "details": {"status_code": 200, "response_text": "rendered static template"}},
            "secure_negative": {**base, "details": {"status_code": 400, "response_text": "template input rejected"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "ldap_injection":
        method, endpoint = _source_endpoint(row, "/directory/search", "GET")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(query=("filter",)), "business_context": "identity", "category": "ldap directory search filter"}
        return {
            "positive": {**base, "details": {"status_code": 500, "response_text": "LDAP error: bad search filter; invalid DN syntax"}},
            "near_miss": {**base, "details": {"status_code": 200, "response_text": "directory search returned zero entries"}},
            "secure_negative": {**base, "details": {"status_code": 400, "response_text": "directory filter rejected"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "security_misconfiguration":
        method, endpoint = _source_endpoint(row, "/api/debug", "GET")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(), "business_context": "general", "category": "debug deployment configuration"}
        return {
            "positive": {**base, "details": {"status_code": 500, "response_text": "Traceback (most recent call last):\n  File \"/srv/app.py\", line 42, in handler\nRuntimeError: fixture"}},
            "near_miss": {**base, "details": {"status_code": 500, "response_text": "Internal Server Error"}},
            "secure_negative": {**base, "details": {"status_code": 404, "response_text": "Not Found"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "secret_exposure":
        method, endpoint = _source_endpoint(row, "/assets/app.js", "GET")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(), "business_context": "general", "category": "production client source asset"}
        return {
            "positive": {**base, "details": {"status_code": 200, "source_code": "const api_key = \"FIXTURE_x7K2p9Q4v8N3s6T1_A9c4\";"}},
            "near_miss": {**base, "details": {"status_code": 200, "source_code": "const api_key = \"<redacted>\";"}},
            "secure_negative": {**base, "details": {"status_code": 200, "source_code": "const api_key = process.env.API_KEY;"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "command_injection":
        method, endpoint = _source_endpoint(row, "/api/convert", "POST")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(body=("input",)), "business_context": "general", "category": "command process execution surface"}
        return {
            "positive": {**base, "details": {"status_code": 200, "source_code": "child_process.exec(userInput); // stored vulnerable execution construction"}},
            "near_miss": {**base, "details": {"status_code": 200, "source_code": "child_process.exec(fixedCommand); // no stored runtime effect"}},
            "secure_negative": {**base, "details": {"status_code": 400, "source_code": "spawn(binary, validatedArgs); // structured invocation"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "race_condition":
        method, endpoint = _source_endpoint(row, "/redeem", "POST")
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            method = "POST"
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(body=("coupon",)), "business_context": "payment", "category": "redeem single-use concurrent business flow"}
        return {
            "positive": {**base, "details": {"status_code": 200, "response_text": "two concurrent fixture requests both returned success", "duration_ms": 42.0}},
            "near_miss": {**base, "details": {"status_code": 200, "response_text": "single fixture request returned success", "duration_ms": 41.0}},
            "secure_negative": {**base, "details": {"status_code": 409, "response_text": "second concurrent fixture request rejected"}},
            "sparse_noisy": {**base, "details": {}},
        }
    if family == "unrestricted_resource_consumption":
        method, endpoint = _source_endpoint(row, "/api/export", "GET")
        base = {"endpoint": endpoint, "method": method, "endpoint_schema": _schema(query=("limit",)), "business_context": "general", "category": "bulk export expensive operation"}
        return {
            "positive": {**base, "details": {"status_code": 200, "requested_limit": 1000000, "response_length": 5000000, "duration_ms": 12000.0}},
            "near_miss": {**base, "details": {"status_code": 200, "requested_limit": 100, "response_length": 5000, "duration_ms": 45.0}},
            "secure_negative": {**base, "details": {"status_code": 429, "requested_limit": 1000000, "response_text": "rate limited"}},
            "sparse_noisy": {**base, "details": {}},
        }
    raise KeyError(f"unsupported materialization family: {family}")


def _case(row: Mapping[str, Any], kind: str, raw_template: Mapping[str, Any]) -> dict[str, Any]:
    family = str(row.get("family") or "")
    condition = EXPECTED_CONDITION[family]
    if condition not in DETECTOR_SPECS[family].condition_signals:
        raise RuntimeError(f"non-canonical expected condition for {family}: {condition}")
    project = str(row.get("source_project") or "")
    raw = {"target": _fixture_target(project), **dict(raw_template)}
    return {
        "id": f"{row['source_root']}-{kind}",
        "source_root": row["source_root"],
        "source_project": project,
        "source_date": _source_date(row),
        "family": family,
        "case_kind": kind,
        "rank_required": kind != "sparse_noisy",
        "split": "postfreeze_holdout",
        "provenance": {
            "primary_source": True,
            "source_kind": str(row.get("source_kind") or "github_reviewed_advisory"),
            "url": row["canonical_advisory_url"],
            "source_code_location": row["source_code_location"],
            "translation": "sanitized_raw_replay_from_primary_source_facts",
            "literal_capture": False,
        },
        "materialization": {
            "materializer_version": MATERIALIZER_VERSION,
            "artifact_score": row.get("artifact_score"),
            "raw_condition_replayable": bool(row.get("raw_condition_replayable")),
            "safe_fixture_values": True,
            "note": "Raw values are inert normalized fixtures representing the primary advisory's observable vulnerability/control class; no live target, real credential, or exploit request is embedded.",
        },
        "raw": raw,
        "expected": {
            "family": family,
            "admitted": kind == "positive",
            "condition_signals": [condition] if kind == "positive" else [],
        },
    }


def materialize(shortlist: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    selected = shortlist.get("selected") if isinstance(shortlist.get("selected"), list) else []
    cases: list[dict[str, Any]] = []
    per_family: dict[str, int] = {}
    for raw_row in selected:
        if not isinstance(raw_row, Mapping):
            continue
        row = dict(raw_row)
        family = str(row.get("family") or "")
        variants = _template(family, row)
        if set(variants) != {"positive", "near_miss", "secure_negative", "sparse_noisy"}:
            raise RuntimeError(f"variant contract mismatch for {row.get('source_root')}")
        for kind in ("positive", "near_miss", "secure_negative", "sparse_noisy"):
            cases.append(_case(row, kind, variants[kind]))
        per_family[family] = per_family.get(family, 0) + 1
    validation = validate_v3_corpus(cases)
    serialized = "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for row in cases) + "\n"
    report = {
        "materializer_version": MATERIALIZER_VERSION,
        "case_count": len(cases),
        "source_root_count": len(selected),
        "family_root_counts": dict(sorted(per_family.items())),
        "corpus_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "validation": validation,
        "scoring_executed": False,
    }
    return cases, report


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize Analysis 6.15 raw v3 fixtures without detector scoring")
    parser.add_argument("--shortlist", default=str(DEFAULT_SHORTLIST))
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    args = parser.parse_args()
    shortlist = json.loads(Path(args.shortlist).read_text(encoding="utf-8"))
    cases, report = materialize(shortlist)
    if not report["validation"]["passed"]:
        raise SystemExit("v3 materialization validation failed: " + "; ".join(report["validation"]["errors"]))
    corpus_path = Path(args.corpus)
    corpus_path.parent.mkdir(parents=True, exist_ok=True)
    corpus_path.write_text("\n".join(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for row in cases) + "\n", encoding="utf-8")
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
