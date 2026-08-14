from __future__ import annotations

import hashlib
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from raw_recon_corpus import ROOT

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.31.20"
SRC = ROOT / "benchmarks/raw/sources"
SOURCE_RESEARCH = SRC / "v6_literal_source_research.json"
LINKED_RESEARCH = SRC / "v6_literal_linked_research.json"
LABEL_SCHEMA = SRC / "v6_literal_label_schema.json"
EVIDENCE_ROOT = SRC / "v6_capture_evidence"

COMPLETE_FAMILIES = {
    "graphql_authorization",
    "information_disclosure",
    "path_traversal",
    "sensitive_business_flow_abuse",
    "ssrf",
}

POSITIVE_SIGNAL = {
    "account_enumeration": "account_existence_differential",
    "authentication_session": "session_validation_failure",
    "broken_function_authorization": "lower_privilege_success",
    "broken_object_authorization": "cross_tenant_object_access",
    "business_logic": "workflow_invariant_violation",
    "command_injection": "process_execution_reached",
    "cors_misconfiguration": "sensitive_cross_origin_response",
    "cryptographic_failure": "predictable_randomness_observed",
    "dom_xss": "runtime_reachable_flow",
    "exceptional_condition_mishandling": "unhandled_exception_observed",
    "file_upload": "dangerous_type_accepted",
    "graphql_data_exposure": "sensitive_expansion",
    "improper_inventory_management": "older_version_weaker_controls",
    "ldap_injection": "ldap_filter_influence",
    "mass_assignment": "privileged_property_accepted",
    "nosql_injection": "query_operator_influence",
    "open_redirect": "external_destination",
    "postmessage_trust": "missing_origin_check",
    "race_condition": "concurrency_invariant_violation",
    "secret_exposure": "credential_context",
    "security_logging_alerting_failure": "sensitive_data_logged",
    "security_misconfiguration": "stack_trace_exposed",
    "sensitive_caching": "shared_cache_risk",
    "server_side_template_injection": "template_expression_evaluated",
    "software_data_integrity_failure": "unsigned_update_accepted",
    "software_supply_chain_failure": "known_vulnerable_component_observed",
    "source_map_exposure": "public_observation",
    "sql_injection": "database_error_observed",
    "unrestricted_resource_consumption": "resource_exhaustion_differential",
    "unsafe_api_consumption": "upstream_redirect_followed_unrestricted",
    "websocket_authorization": "unauthorized_subscription",
}

POSITIVE_TERMS = {
    "account_enumeration": ("enumerat", "existing user", "nonexistent user", "response discrepancy", "iteration count"),
    "authentication_session": ("authentication", "session", "ntlm", "imperson", "authenticated user"),
    "broken_function_authorization": ("non-admin", "admin", "management", "permission", "authorization bypass"),
    "broken_object_authorization": ("tenant", "enterprise", "unauthorized", "idor", "cross-enterprise"),
    "business_logic": ("workflow", "approval", "untrusted", "pull_request_target", "fork"),
    "command_injection": ("command", "execute", "smtp", "snmp", "process"),
    "cors_misconfiguration": ("cors", "cross-origin", "origin", "bearer", "authentication"),
    "cryptographic_failure": ("weak", "predictable", "secret", "entropy", "session"),
    "dom_xss": ("xss", "svg", "sanit", "browser", "render"),
    "exceptional_condition_mishandling": ("exception", "fatal", "crash", "locals", "traceback"),
    "file_upload": ("upload", "php", "extension", "webshell", "filename"),
    "graphql_data_exposure": ("graphql", "select", "full", "sensitive", "projection"),
    "improper_inventory_management": ("old api", "older api", "legacy", "version", "still"),
    "ldap_injection": ("ldap", "username", "injection", "filter", "account"),
    "mass_assignment": ("mass assignment", "over-posting", "s3_url", "property", "client"),
    "nosql_injection": ("mongodb", "mongo", "$ne", "operator", "query"),
    "open_redirect": ("redirect", "location", "external", "url parameter", "phishing"),
    "postmessage_trust": ("postmessage", "message", "origin", "iframe", "sender"),
    "race_condition": ("race condition", "race", "concurrent", "privilege", "system"),
    "secret_exposure": ("hardcoded", "token", "secret", "credential", "source code"),
    "security_logging_alerting_failure": ("password", "log", "trace", "plaintext", "sensitive"),
    "security_misconfiguration": ("axioserror", "error", "token", "request body", "log"),
    "sensitive_caching": ("cache", "fastly", "api key", "authenticated", "shared"),
    "server_side_template_injection": ("twig", "template", "expression", "sandbox", "render"),
    "software_data_integrity_failure": ("update", "integrity", "signature", "installer", "verification"),
    "software_supply_chain_failure": ("malicious", "package", "dependency", "credential", "compromised"),
    "source_map_exposure": ("source map", "sourcemappingurl", "sourcescontent", "source code", ".map"),
    "sql_injection": ("sql", "database", "commentlist", "id parameter", "inject"),
    "unrestricted_resource_consumption": ("resource", "queue", "denial of service", "dos", "resize"),
    "unsafe_api_consumption": ("redirect", "cross-host", "cookie", "proxy-authorization", "http client"),
    "websocket_authorization": ("websocket", "authentication", "authorization", "anonymous", "control"),
}

SECURE_TERMS = (
    "patch", "patched", "fix", "fixed", "upgrade", "mitigat", "workaround",
    "unaffected", "not affected", "reject", "denied", "allowlist", "validation",
    "restrict", "prevent", "resolved", "remediat", "correction", "acceptance criteria",
    "safe", "secure", "requires authentication", "return 403", "disable",
)
NEAR_TERMS = (
    "requires", "requirement", "prerequisite", "scope", "impact", "affected", "only",
    "related", "adjacent", "severity", "condition", "user interaction", "authenticated",
    "local", "permission", "role", "version", "configuration", "default",
)
PATH_PRIORITY = {"body": 20, "description": 20, "summary": 18, "message": 18, "title": 10}

SURFACE = {
    "account_enumeration": ("identity lookup", ["username"], [], [], []),
    "authentication_session": ("session negotiation", [], ["token"], [], ["session"]),
    "broken_function_authorization": ("administrative management", [], [], [], ["bearer"]),
    "broken_object_authorization": ("tenant object access", [], [], ["tenant_id"], ["bearer"]),
    "business_logic": ("approval workflow", [], [], [], []),
    "command_injection": ("process notification", [], ["input"], [], []),
    "cors_misconfiguration": ("authentication response", [], [], [], ["cookie"]),
    "cryptographic_failure": ("session secret validation", [], ["secret"], [], []),
    "dom_xss": ("browser rendering", [], [], [], []),
    "exceptional_condition_mishandling": ("fatal error handling", [], [], [], []),
    "file_upload": ("file upload", [], ["file"], [], []),
    "graphql_data_exposure": ("graphql query", [], [], [], ["bearer"]),
    "improper_inventory_management": ("legacy api version", [], [], [], []),
    "ldap_injection": ("directory login", [], ["username"], [], []),
    "mass_assignment": ("object update", [], ["s3_url"], [], ["bearer"]),
    "nosql_injection": ("document filter", ["filter"], [], [], []),
    "open_redirect": ("logout navigation", ["url"], [], [], []),
    "postmessage_trust": ("cross-window messaging", [], [], [], []),
    "race_condition": ("privileged state transition", [], [], [], []),
    "secret_exposure": ("application source secret", [], [], [], []),
    "security_logging_alerting_failure": ("trace logging", [], [], [], []),
    "security_misconfiguration": ("error reporting", [], [], [], []),
    "sensitive_caching": ("authenticated cache response", [], [], [], ["authorization"]),
    "server_side_template_injection": ("server template rendering", [], ["template"], [], []),
    "software_data_integrity_failure": ("software update", [], [], [], []),
    "software_supply_chain_failure": ("dependency installation", [], [], [], []),
    "source_map_exposure": ("browser debug artifact", [], [], [], []),
    "sql_injection": ("database query", ["id"], [], [], []),
    "unrestricted_resource_consumption": ("queue allocation", ["size"], [], [], []),
    "unsafe_api_consumption": ("third-party http client", [], [], [], []),
    "websocket_authorization": ("websocket control channel", ["channel"], [], [], ["bearer"]),
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha_json(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in value.casefold()).strip("-")


def _clean_text(value: str) -> str:
    value = html.unescape(value)
    value = re.sub(r"<script\b[^>]*>.*?</script>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<style\b[^>]*>.*?</style>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def _chunks(text: str) -> list[str]:
    cleaned = _clean_text(text)
    if len(cleaned) < 30:
        return []
    pieces = re.split(r"(?<=[.!?])\s+|\s*\n+\s*", cleaned)
    out: list[str] = []
    for piece in pieces:
        piece = piece.strip()
        if 35 <= len(piece) <= 2200:
            out.append(piece)
    if not out and len(cleaned) <= 2200:
        out.append(cleaned)
    return out[:400]


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk(child, path + (str(key),))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from _walk(child, path + (str(i),))
    elif isinstance(value, str):
        for piece in _chunks(value):
            yield path, piece


def _marker_free(text: str, markers: Iterable[str]) -> bool:
    lowered = text.casefold()
    return not any(marker.casefold() in lowered for marker in markers if marker)


def _candidate_rows(source_row: Mapping[str, Any], linked_row: Mapping[str, Any], markers: set[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    canonical_ref = str(source_row.get("canonical_reference") or "")
    canonical_sha = str(source_row.get("snapshot_sha256") or "")
    for path, text in _walk(source_row.get("snapshot_payload")):
        if _marker_free(text, markers):
            rows.append({"reference": canonical_ref, "snapshot_sha256": canonical_sha, "resource_type": "canonical", "path": ".".join(path), "text": text, "origin": 2})
    for resource in linked_row.get("linked_resources") or []:
        if not isinstance(resource, Mapping) or resource.get("fetch_status") != 200 or resource.get("snapshot_payload") is None:
            continue
        reference = str(resource.get("reference") or "")
        digest = str(resource.get("snapshot_sha256") or "")
        rtype = str(resource.get("resource_type") or "linked")
        origin = 5 if rtype in {"commit", "pull_request"} else 3
        for path, text in _walk(resource.get("snapshot_payload")):
            if _marker_free(text, markers):
                rows.append({"reference": reference, "snapshot_sha256": digest, "resource_type": rtype, "path": ".".join(path), "text": text, "origin": origin})
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = _sha_bytes(row["text"].encode("utf-8"))
        if key not in unique or row["origin"] > unique[key]["origin"]:
            unique[key] = row
    return list(unique.values())


def _term_score(text: str, terms: Iterable[str]) -> int:
    lowered = text.casefold()
    return sum(1 for term in terms if term.casefold() in lowered)


def _path_score(path: str) -> int:
    lowered = path.casefold()
    return sum(weight for key, weight in PATH_PRIORITY.items() if key in lowered)


def _choose(family: str, rows: list[dict[str, Any]], kind: str, used: set[str]) -> dict[str, Any] | None:
    choices = [row for row in rows if _sha_bytes(row["text"].encode()) not in used]
    if not choices:
        return None
    if kind == "positive":
        scored = sorted(choices, key=lambda row: (_term_score(row["text"], POSITIVE_TERMS[family]) * 30 + _path_score(row["path"]) + row["origin"], len(row["text"])), reverse=True)
        return scored[0] if _term_score(scored[0]["text"], POSITIVE_TERMS[family]) > 0 else None
    if kind == "secure_negative":
        scored = sorted(choices, key=lambda row: (_term_score(row["text"], SECURE_TERMS) * 30 + row["origin"] * 3 + _path_score(row["path"]) - _term_score(row["text"], POSITIVE_TERMS[family]) * 4, len(row["text"])), reverse=True)
        return scored[0] if _term_score(scored[0]["text"], SECURE_TERMS) > 0 else None
    if kind == "near_miss":
        scored = sorted(choices, key=lambda row: (_term_score(row["text"], NEAR_TERMS) * 15 + _path_score(row["path"]) + row["origin"] - _term_score(row["text"], SECURE_TERMS) * 8, len(row["text"])), reverse=True)
        return scored[0]
    raise KeyError(kind)


def _sparse_payload(source_row: Mapping[str, Any]) -> dict[str, Any]:
    payload = source_row.get("snapshot_payload") if isinstance(source_row.get("snapshot_payload"), Mapping) else {}
    keep = {}
    for key in ("published_at", "updated_at", "severity", "type", "cve_id", "ghsa_id", "html_url", "url"):
        if key in payload and payload.get(key) is not None:
            keep[key] = payload.get(key)
    keep["fetch_status"] = source_row.get("fetch_status")
    keep["acquisition_route"] = source_row.get("acquisition_route")
    keep["reference_count"] = len(payload.get("references") or []) if isinstance(payload, Mapping) else 0
    return keep


def _raw(family: str, kind: str, selected: Mapping[str, Any] | None, sparse: Mapping[str, Any] | None) -> dict[str, Any]:
    context, query, body, path, auth = SURFACE[family]
    token = _sha_bytes(((selected or {}).get("text", "") + family + kind).encode())[:16]
    details: dict[str, Any] = {
        "capture_environment": "passive public-source snapshot normalization; no target contacted",
        "observation_variant": kind,
        "source_observation_id": token,
    }
    if selected is not None:
        details["response_text"] = selected["text"]
        details["source_path"] = selected["path"]
        details["source_resource_type"] = selected["resource_type"]
    else:
        details["source_metadata"] = dict(sparse or {})
    return {
        "target": "public-source-snapshot.invalid",
        "endpoint": f"/observation/{token}",
        "method": "GET",
        "endpoint_schema": {
            "query_parameters": list(query),
            "body_fields": list(body),
            "path_parameters": list(path),
            "object_identifiers": [],
            "authentication_hints": list(auth),
        },
        "business_context": context,
        "category": "public source security observation",
        "details": details,
    }


def _evidence(family: str, source_row: Mapping[str, Any], kind: str, selected: Mapping[str, Any] | None, sparse: Mapping[str, Any] | None) -> dict[str, Any]:
    captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    reference = str((selected or {}).get("reference") or source_row.get("canonical_reference") or "")
    if not reference.startswith("https://"):
        raise RuntimeError(f"{family}/{kind}: source reference is not https")
    raw = _raw(family, kind, selected, sparse)
    if selected is not None:
        snapshot_payload = {
            "literal_excerpt": selected["text"],
            "source_path": selected["path"],
            "resource_type": selected["resource_type"],
            "upstream_snapshot_sha256": selected["snapshot_sha256"],
        }
    else:
        snapshot_payload = {
            "literal_metadata": dict(sparse or {}),
            "upstream_snapshot_sha256": source_row.get("snapshot_sha256"),
        }
    signals = [POSITIVE_SIGNAL[family]] if kind == "positive" else []
    basis = "patched_control" if kind == "secure_negative" else "source_observation"
    notes = (
        f"Selected an independent public-source observation from {reference}; path={selected['path']}. "
        "No detector, admission, ranking, or benchmark score was executed during selection."
        if selected is not None else
        f"Selected independent publication/acquisition metadata from {reference} as a sparse observation. No engine output was used."
    )
    return {
        "schema_version": "1.0",
        "family": family,
        "case_kind": kind,
        "source_root": source_row.get("source_root"),
        "source_project": source_row.get("source_project"),
        "captured_at": captured_at,
        "capture_reference": reference,
        "capture_method": "cli_output",
        "collector": {
            "tool": "Analysis 6.31 passive public-source literal observation collector",
            "command": "PYTHONPATH=app python app/v6_literal_bulk_capture.py",
            "source_file": "benchmarks/raw/sources/v6_literal_source_research.json + v6_literal_linked_research.json",
        },
        "raw": raw,
        "raw_sha256": _sha_json(raw),
        "adjudication": {
            "basis": basis,
            "notes": notes,
            "expected_condition_signals": signals,
            "detector_output_used": False,
            "admission_output_used": False,
            "ranking_output_used": False,
        },
        "source_snapshot": {
            "reference": reference,
            "retrieved_at": captured_at,
            "payload": snapshot_payload,
            "content_sha256": _sha_json(snapshot_payload),
        },
    }


def build() -> dict[str, Any]:
    source = json.loads(SOURCE_RESEARCH.read_text(encoding="utf-8"))
    linked = json.loads(LINKED_RESEARCH.read_text(encoding="utf-8"))
    schema = json.loads(LABEL_SCHEMA.read_text(encoding="utf-8"))
    if source.get("scoring_executed") is not False or linked.get("scoring_executed") is not False:
        raise RuntimeError("bulk capture requires unscored passive research")
    source_by = {str(row.get("family") or ""): row for row in source.get("entries") or []}
    linked_by = {str(row.get("family") or ""): row for row in linked.get("entries") or []}
    schema_families = schema.get("families") if isinstance(schema.get("families"), Mapping) else {}
    if set(POSITIVE_SIGNAL) != set(source_by) - COMPLETE_FAMILIES:
        raise RuntimeError("bulk capture family map does not exactly match remaining source families")
    for family, signal in POSITIVE_SIGNAL.items():
        allowed = set((schema_families.get(family) or {}).get("condition_signals") or [])
        if signal not in allowed:
            raise RuntimeError(f"{family}: positive signal {signal!r} is not in frozen label vocabulary")

    machine_markers = set(source_by)
    for row in schema_families.values():
        if isinstance(row, Mapping):
            machine_markers.update(str(value) for value in row.get("condition_signals") or [])

    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    blocked: list[dict[str, Any]] = []
    for family in sorted(POSITIVE_SIGNAL):
        source_row = source_by[family]
        rows = _candidate_rows(source_row, linked_by.get(family, {}), machine_markers)
        used: set[str] = set()
        selected_by_kind: dict[str, dict[str, Any]] = {}
        for kind in ("positive", "secure_negative", "near_miss"):
            row = _choose(family, rows, kind, used)
            if row is None:
                blocked.append({"family": family, "case_kind": kind, "candidate_count": len(rows), "reason": "no independent source excerpt satisfied the selection contract"})
                continue
            selected_by_kind[kind] = row
            used.add(_sha_bytes(row["text"].encode("utf-8")))
        if any(item["family"] == family for item in blocked):
            continue
        for kind in ("positive", "near_miss", "secure_negative", "sparse_noisy"):
            path = EVIDENCE_ROOT / f"{_slug(family)}--{_slug(kind)}.json"
            if path.exists():
                continue
            selected = selected_by_kind.get(kind)
            sparse = _sparse_payload(source_row) if kind == "sparse_noisy" else None
            doc = _evidence(family, source_row, kind, selected, sparse)
            path.write_text(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
            created.append(path.relative_to(ROOT).as_posix())
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_passive_source_backed_literal_completion_unscored",
        "scoring_executed": False,
        "first_blind_consumed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "active_target_validation_performed": False,
        "created_count": len(created),
        "created": created,
        "blocked_count": len(blocked),
        "blocked": blocked,
    }


def main() -> int:
    report = build()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["blocked_count"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
