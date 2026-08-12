from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from raw_recon_v3_materialize import EXPECTED_CONDITION as V3_EXPECTED_CONDITION, _template as _v3_template
from raw_recon_v4_corpus import V4_VARIANTS, validate_v4_corpus

MATERIALIZER_VERSION = "1.0.0"
MATERIALIZER_RULE_VERSION = "2026.08.12.6.26"
DEFAULT_SHORTLIST = ROOT / "benchmarks" / "raw" / "sources" / "v4_shortlist.json"
DEFAULT_CORPUS = ROOT / "benchmarks" / "raw" / "analysis_raw_v4.jsonl"
DEFAULT_REPORT = ROOT / "benchmarks" / "raw" / "sources" / "v4_materialization_report.json"

LEGACY_TEMPLATE_FAMILIES = frozenset(V3_EXPECTED_CONDITION)

EXPECTED_CONDITION = {
    **V3_EXPECTED_CONDITION,
    "dom_xss": "runtime_reachable_flow",
    "postmessage_trust": "missing_origin_check",
    "graphql_authorization": "resolver_authorization_failure",
    "graphql_data_exposure": "sensitive_field_response",
    "websocket_authorization": "unauthorized_subscription",
    "sensitive_caching": "authenticated_response_public_cache",
    "business_logic": "workflow_invariant_violation",
    "sensitive_business_flow_abuse": "automation_controls_missing",
    "improper_inventory_management": "active_legacy_endpoint",
    "unsafe_api_consumption": "upstream_tls_missing",
    "source_map_exposure": "source_map_content",
    "software_supply_chain_failure": "known_vulnerable_component_observed",
    "cryptographic_failure": "weak_tls_configuration",
    "software_data_integrity_failure": "unsigned_update_accepted",
    "security_logging_alerting_failure": "security_event_not_logged",
    "exceptional_condition_mishandling": "unhandled_exception_crash",
}


def _fixture_target(project: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", project.lower()).strip("-") + ".fixture.invalid"


def _source_date(row: Mapping[str, Any]) -> str:
    published = str(row.get("published_at") or "")
    return published[:10] if len(published) >= 10 else "2026-08-12"


def _schema(*, query=(), body=(), path=(), object_ids=(), auth=()) -> dict[str, Any]:
    return {
        "query_parameters": list(query),
        "body_fields": list(body),
        "path_parameters": list(path),
        "object_identifiers": list(object_ids),
        "authentication_hints": list(auth),
    }


def _base(endpoint: str, method: str, *, category: str, business_context: str = "general", schema: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "endpoint": endpoint,
        "method": method,
        "endpoint_schema": dict(schema or _schema()),
        "business_context": business_context,
        "category": category,
    }


def _new_template(family: str, row: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if family == "dom_xss":
        base = _base("/app", "GET", category="client javascript rendering")
        return {
            "positive": {**base, "details": {"status_code": 200, "javascript": "const value = location.hash.slice(1); document.querySelector('#result').innerHTML = value;", "browser_observation": {"input_channel": "location.hash", "render_target": "#result", "rendered_as_html": True}}},
            "near_miss": {**base, "details": {"status_code": 200, "javascript": "const value = location.hash.slice(1); document.querySelector('#result').textContent = value;", "browser_observation": {"input_channel": "location.hash", "render_target": "#result", "rendered_as_html": False}}},
            "secure_negative": {**base, "details": {"status_code": 200, "javascript": "const value = location.hash.slice(1); document.querySelector('#result').textContent = value;", "browser_observation": {"input_channel": "location.hash", "render_target": "#result", "rendered_as_html": False, "sanitized": True}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "javascript": "const value = location.hash.slice(1);"}},
        }

    if family == "postmessage_trust":
        base = _base("/embed", "GET", category="cross-window message handling")
        return {
            "positive": {**base, "details": {"status_code": 200, "javascript": "window.addEventListener('message', (event) => { document.querySelector('#panel').innerHTML = event.data; });", "message_observation": {"sender_origin": "https://untrusted.fixture.invalid", "accepted": True, "origin_checked": False}}},
            "near_miss": {**base, "details": {"status_code": 200, "javascript": "window.addEventListener('message', (event) => { if (event.origin === 'https://trusted.fixture.invalid') document.querySelector('#panel').innerHTML = event.data; });", "message_observation": {"sender_origin": "https://trusted.fixture.invalid", "accepted": True, "origin_checked": True}}},
            "secure_negative": {**base, "details": {"status_code": 200, "javascript": "window.addEventListener('message', (event) => { if (event.origin !== 'https://trusted.fixture.invalid') return; document.querySelector('#panel').textContent = event.data; });", "message_observation": {"sender_origin": "https://untrusted.fixture.invalid", "accepted": False, "origin_checked": True}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "javascript": "window.addEventListener('message', () => {});"}},
        }

    if family == "graphql_authorization":
        base = _base("/graphql", "POST", category="graphql resolver object authorization", business_context="customer_data", schema=_schema(body=("query",), object_ids=("accountId",), auth=("session",)))
        query = "query Account($id: ID!){ account(id:$id){ id privateNotes } }"
        return {
            "positive": {**base, "details": {"status_code": 200, "graphql_query": query, "context_observations": [{"context": "low_privilege_other_account", "requested_object": "acct-200", "expected_access": "denied", "status_code": 200, "response_json": {"data": {"account": {"id": "acct-200", "privateNotes": "fixture-private"}}}}]}},
            "near_miss": {**base, "details": {"status_code": 200, "graphql_query": query, "context_observations": [{"context": "owner_account", "requested_object": "acct-100", "expected_access": "allowed", "status_code": 200}]}},
            "secure_negative": {**base, "details": {"status_code": 200, "graphql_query": query, "context_observations": [{"context": "low_privilege_other_account", "requested_object": "acct-200", "expected_access": "denied", "status_code": 200, "response_json": {"errors": [{"message": "forbidden"}], "data": {"account": None}}}]}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "graphql_query": "query { __typename }"}},
        }

    if family == "graphql_data_exposure":
        base = _base("/graphql", "POST", category="graphql sensitive field response", business_context="customer_data", schema=_schema(body=("query",), auth=("session",)))
        return {
            "positive": {**base, "details": {"status_code": 200, "graphql_query": "query { viewer { id email apiToken } }", "response_json": {"data": {"viewer": {"id": "u-1", "email": "user@fixture.invalid", "apiToken": "fixture-sensitive-token-value"}}}}},
            "near_miss": {**base, "details": {"status_code": 200, "graphql_query": "query { viewer { id displayName } }", "response_json": {"data": {"viewer": {"id": "u-1", "displayName": "Fixture"}}}}},
            "secure_negative": {**base, "details": {"status_code": 200, "graphql_query": "query { viewer { id apiToken } }", "response_json": {"errors": [{"message": "field not permitted"}], "data": {"viewer": {"id": "u-1"}}}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "graphql_query": "query { __typename }"}},
        }

    if family == "websocket_authorization":
        base = _base("/ws", "GET", category="websocket subscription authorization", business_context="customer_data", schema=_schema(query=("channel",), auth=("session",)))
        return {
            "positive": {**base, "details": {"status_code": 101, "websocket_url": "wss://fixture.invalid/ws", "context_observations": [{"context": "low_privilege_user", "channel": "tenant-200-private", "expected_access": "denied", "subscription_accepted": True, "message_received": True}]}},
            "near_miss": {**base, "details": {"status_code": 101, "websocket_url": "wss://fixture.invalid/ws", "context_observations": [{"context": "authorized_user", "channel": "tenant-100-private", "expected_access": "allowed", "subscription_accepted": True, "message_received": True}]}},
            "secure_negative": {**base, "details": {"status_code": 101, "websocket_url": "wss://fixture.invalid/ws", "context_observations": [{"context": "low_privilege_user", "channel": "tenant-200-private", "expected_access": "denied", "subscription_accepted": False, "message_received": False}]}},
            "sparse_noisy": {**base, "details": {"status_code": 101, "websocket_url": "wss://fixture.invalid/ws"}},
        }

    if family == "sensitive_caching":
        base = _base("/api/account", "GET", category="authenticated sensitive response caching", business_context="customer_data", schema=_schema(auth=("session",)))
        return {
            "positive": {**base, "details": {"status_code": 200, "request_headers": {"Cookie": "session=fixture"}, "response_headers": {"Cache-Control": "public, max-age=300"}, "response_json": {"email": "user@fixture.invalid", "balance": "100.00"}, "cache_observation": {"shared_cache_store": True}}},
            "near_miss": {**base, "details": {"status_code": 200, "request_headers": {"Cookie": "session=fixture"}, "response_headers": {"Cache-Control": "private, max-age=0", "Vary": "Cookie"}, "response_json": {"email": "user@fixture.invalid"}, "cache_observation": {"shared_cache_store": False}}},
            "secure_negative": {**base, "details": {"status_code": 200, "request_headers": {"Cookie": "session=fixture"}, "response_headers": {"Cache-Control": "no-store, private", "Vary": "Cookie"}, "response_json": {"email": "user@fixture.invalid"}, "cache_observation": {"shared_cache_store": False}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "response_headers": {"Cache-Control": "max-age=60"}}},
        }

    if family == "business_logic":
        base = _base("/api/checkout", "POST", category="checkout workflow invariant", business_context="payments", schema=_schema(body=("order_id", "amount"), auth=("session",)))
        return {
            "positive": {**base, "details": {"status_code": 200, "workflow_observation": {"order_state_before": "unpaid", "requested_transition": "download", "order_state_after": "download_enabled", "payment_confirmed": False}}},
            "near_miss": {**base, "details": {"status_code": 200, "workflow_observation": {"order_state_before": "paid", "requested_transition": "download", "order_state_after": "download_enabled", "payment_confirmed": True}}},
            "secure_negative": {**base, "details": {"status_code": 409, "workflow_observation": {"order_state_before": "unpaid", "requested_transition": "download", "order_state_after": "unpaid", "payment_confirmed": False, "transition_rejected": True}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "workflow_observation": {"order_state_before": "paid"}}},
        }

    if family == "sensitive_business_flow_abuse":
        base = _base("/api/password-reset", "POST", category="sensitive workflow automation control", business_context="identity", schema=_schema(body=("email",)))
        return {
            "positive": {**base, "details": {"status_code": 200, "automation_observation": {"same_identity_attempts": 50, "accepted_attempts": 50, "rate_limit_response_seen": False, "challenge_present": False}}},
            "near_miss": {**base, "details": {"status_code": 200, "automation_observation": {"same_identity_attempts": 2, "accepted_attempts": 2, "rate_limit_response_seen": False, "challenge_present": False}}},
            "secure_negative": {**base, "details": {"status_code": 429, "automation_observation": {"same_identity_attempts": 50, "accepted_attempts": 5, "rate_limit_response_seen": True, "challenge_present": True}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "automation_observation": {"same_identity_attempts": 1}}},
        }

    if family == "improper_inventory_management":
        base = _base("/legacy/import", "POST", category="deprecated legacy importer endpoint", business_context="administration", schema=_schema(body=("file",)))
        return {
            "positive": {**base, "details": {"status_code": 200, "deployment_observation": {"lifecycle": "deprecated", "route": "/legacy/import", "route_registered": True, "authentication_required": False, "operation_completed": True}}},
            "near_miss": {**base, "details": {"status_code": 401, "deployment_observation": {"lifecycle": "deprecated", "route": "/legacy/import", "route_registered": True, "authentication_required": True, "operation_completed": False}}},
            "secure_negative": {**base, "details": {"status_code": 404, "deployment_observation": {"lifecycle": "removed", "route": "/legacy/import", "route_registered": False, "operation_completed": False}}},
            "sparse_noisy": {**base, "details": {"status_code": 404, "deployment_observation": {"route": "/legacy/import"}}},
        }

    if family == "unsafe_api_consumption":
        base = _base("/api/vendor-sync", "POST", category="third-party upstream api integration", business_context="integration", schema=_schema(body=("vendor_id",)))
        return {
            "positive": {**base, "details": {"status_code": 200, "upstream_observation": {"url": "https://vendor.fixture.invalid/data", "tls_certificate_present": True, "hostname_matches_certificate": False, "response_accepted": True, "trusted_upstream": True}}},
            "near_miss": {**base, "details": {"status_code": 200, "upstream_observation": {"url": "https://vendor.fixture.invalid/data", "tls_certificate_present": True, "hostname_matches_certificate": True, "response_accepted": True, "trusted_upstream": True}}},
            "secure_negative": {**base, "details": {"status_code": 502, "upstream_observation": {"url": "https://vendor.fixture.invalid/data", "tls_certificate_present": True, "hostname_matches_certificate": False, "response_accepted": False, "trusted_upstream": True}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "upstream_observation": {"url": "https://vendor.fixture.invalid/data"}}},
        }

    if family == "source_map_exposure":
        base = _base("/pkg/module.mjs.map", "GET", category="public javascript source map", business_context="application_source")
        return {
            "positive": {**base, "details": {"status_code": 200, "response_headers": {"Content-Type": "application/json"}, "source_map": {"version": 3, "sources": ["../../server/config.ts"], "sourcesContent": ["export const internalSetting = 'fixture';"]}, "public_fetch": True}},
            "near_miss": {**base, "details": {"status_code": 200, "response_headers": {"Content-Type": "application/json"}, "source_map": {"version": 3, "sources": ["webpack:///src/public.ts"], "sourcesContent": []}, "public_fetch": True}},
            "secure_negative": {**base, "details": {"status_code": 404, "response_headers": {"Content-Type": "application/json"}, "source_map": {"version": 3, "sources": [], "sourcesContent": []}, "public_fetch": False}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "response_text": "//# sourceMappingURL=module.mjs.map"}},
        }

    if family == "software_supply_chain_failure":
        base = _base("/build-metadata", "GET", category="dependency component inventory", business_context="build_pipeline")
        return {
            "positive": {**base, "details": {"status_code": 200, "dependency_manifest": {"package": "fixture-component", "version": "1.2.3", "deployed": True}, "component_observation": {"security_advisory_present": True, "affected_version": True, "fixed_version_available": "1.2.4"}}},
            "near_miss": {**base, "details": {"status_code": 200, "dependency_manifest": {"package": "fixture-component", "version": "1.2.4", "deployed": True}, "component_observation": {"security_advisory_present": True, "affected_version": False, "fixed_version_available": "1.2.4"}}},
            "secure_negative": {**base, "details": {"status_code": 200, "dependency_manifest": {"package": "fixture-component", "version": "1.2.4", "deployed": True}, "component_observation": {"security_advisory_present": False, "affected_version": False}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "dependency_manifest": {"package": "fixture-component"}}},
        }

    if family == "cryptographic_failure":
        base = _base("https://crypto.fixture.invalid/session", "GET", category="tls cryptographic transport", business_context="identity")
        return {
            "positive": {**base, "details": {"status_code": 200, "tls_observation": {"protocol": "TLSv1.0", "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "certificate_valid": True}}},
            "near_miss": {**base, "details": {"status_code": 200, "tls_observation": {"protocol": "TLSv1.2", "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "certificate_valid": True}}},
            "secure_negative": {**base, "details": {"status_code": 200, "tls_observation": {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "certificate_valid": True}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "response_text": "TLS enabled"}},
        }

    if family == "software_data_integrity_failure":
        base = _base("/api/update", "POST", category="software update integrity verification", business_context="administration", schema=_schema(body=("package",)))
        return {
            "positive": {**base, "details": {"status_code": 200, "update_observation": {"artifact": "fixture-update.pkg", "signature_present": False, "signature_verified": False, "installation_accepted": True}}},
            "near_miss": {**base, "details": {"status_code": 200, "update_observation": {"artifact": "fixture-update.pkg", "signature_present": True, "signature_verified": True, "installation_accepted": True}}},
            "secure_negative": {**base, "details": {"status_code": 400, "update_observation": {"artifact": "fixture-update.pkg", "signature_present": False, "signature_verified": False, "installation_accepted": False}}},
            "sparse_noisy": {**base, "details": {"status_code": 200, "update_observation": {"artifact": "fixture-update.pkg"}}},
        }

    if family == "security_logging_alerting_failure":
        base = _base("/admin/login", "POST", category="security event audit logging", business_context="identity", schema=_schema(body=("username", "password")))
        return {
            "positive": {**base, "details": {"status_code": 401, "security_event": {"event_type": "repeated_failed_login", "attempts": 12, "actor": "fixture-user"}, "audit_observation": {"matching_log_entries": 0, "alert_emitted": False, "log_store_checked": True}}},
            "near_miss": {**base, "details": {"status_code": 401, "security_event": {"event_type": "single_failed_login", "attempts": 1, "actor": "fixture-user"}, "audit_observation": {"matching_log_entries": 1, "alert_emitted": False, "log_store_checked": True}}},
            "secure_negative": {**base, "details": {"status_code": 401, "security_event": {"event_type": "repeated_failed_login", "attempts": 12, "actor": "fixture-user"}, "audit_observation": {"matching_log_entries": 12, "alert_emitted": True, "log_store_checked": True}}},
            "sparse_noisy": {**base, "details": {"status_code": 401, "security_event": {"event_type": "failed_login"}}},
        }

    if family == "exceptional_condition_mishandling":
        base = _base("/api/process", "POST", category="exception handling state transition", business_context="workflow", schema=_schema(body=("operation",)))
        return {
            "positive": {**base, "details": {"status_code": 500, "exception_observation": {"exception_type": "UnhandledRuntimeError", "handled": False, "process_crashed": True, "state_before": "pending", "state_after": "partially_committed"}, "response_text": "Unhandled exception while processing request"}},
            "near_miss": {**base, "details": {"status_code": 400, "exception_observation": {"exception_type": "ValidationError", "handled": True, "process_crashed": False, "state_before": "pending", "state_after": "pending"}}},
            "secure_negative": {**base, "details": {"status_code": 409, "exception_observation": {"exception_type": "RuntimeError", "handled": True, "process_crashed": False, "rollback_completed": True, "state_before": "pending", "state_after": "pending"}}},
            "sparse_noisy": {**base, "details": {"status_code": 500, "response_text": "error"}},
        }

    raise KeyError(f"unsupported Analysis 6.26 materialization family: {family}")


def _template(family: str, row: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if family in LEGACY_TEMPLATE_FAMILIES:
        return _v3_template(family, row)
    return _new_template(family, row)


def _case(row: Mapping[str, Any], kind: str, raw_template: Mapping[str, Any]) -> dict[str, Any]:
    family = str(row.get("family") or "")
    condition = EXPECTED_CONDITION[family]
    if family not in DETECTOR_SPECS:
        raise RuntimeError(f"materialization family is not sealed in detector registry: {family}")
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
            "source_kind": str(row.get("source_kind") or "primary_security_advisory"),
            "url": row["canonical_advisory_url"],
            "source_code_location": row.get("source_code_location") or f"https://github.com/{project}",
            "translation": "sanitized_raw_replay_from_primary_source_facts",
            "literal_capture": False,
        },
        "materialization": {
            "materializer_version": MATERIALIZER_VERSION,
            "materializer_rule_version": MATERIALIZER_RULE_VERSION,
            "source_family_audit_version": row.get("source_family_audit_version"),
            "source_family_audit_score": row.get("source_family_audit_score"),
            "safe_fixture_values": True,
            "scoring_executed": False,
            "note": "Inert normalized raw target artifacts reproduce the observable vulnerability/control class from the frozen primary-source shortlist; no live target, credential, exploit request, detector score, or advisory prose is embedded in raw input.",
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
    if len(selected) != 36:
        raise RuntimeError(f"Analysis 6.26 materialization requires exactly 36 audited sources: {len(selected)}")
    if set(EXPECTED_CONDITION) != set(DETECTOR_SPECS):
        missing = sorted(set(DETECTOR_SPECS) - set(EXPECTED_CONDITION))
        extra = sorted(set(EXPECTED_CONDITION) - set(DETECTOR_SPECS))
        raise RuntimeError(f"Analysis 6.26 materializer family coverage mismatch missing={missing} extra={extra}")

    cases: list[dict[str, Any]] = []
    per_family: dict[str, int] = {}
    for raw_row in selected:
        if not isinstance(raw_row, Mapping):
            continue
        row = dict(raw_row)
        family = str(row.get("family") or "")
        variants = _template(family, row)
        if tuple(variants) != V4_VARIANTS and set(variants) != set(V4_VARIANTS):
            raise RuntimeError(f"variant contract mismatch for {row.get('source_root')}: {sorted(variants)}")
        for kind in V4_VARIANTS:
            cases.append(_case(row, kind, variants[kind]))
        per_family[family] = per_family.get(family, 0) + 1

    validation = validate_v4_corpus(cases, shortlist=shortlist)
    serialized = "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for row in cases) + "\n"
    report = {
        "materializer_version": MATERIALIZER_VERSION,
        "materializer_rule_version": MATERIALIZER_RULE_VERSION,
        "case_count": len(cases),
        "source_root_count": len(selected),
        "family_root_counts": dict(sorted(per_family.items())),
        "corpus_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "validation": validation,
        "scoring_executed": False,
    }
    return cases, report


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize Analysis 6.26 fresh raw v4 fixtures without detector scoring")
    parser.add_argument("--shortlist", default=str(DEFAULT_SHORTLIST))
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    args = parser.parse_args()

    shortlist = json.loads(Path(args.shortlist).read_text(encoding="utf-8"))
    cases, report = materialize(shortlist)
    if not report["validation"]["passed"]:
        raise SystemExit("v4 materialization validation failed: " + "; ".join(report["validation"]["errors"]))

    corpus_path = Path(args.corpus)
    corpus_path.parent.mkdir(parents=True, exist_ok=True)
    corpus_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for row in cases) + "\n",
        encoding="utf-8",
    )
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
