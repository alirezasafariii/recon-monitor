from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from raw_recon_corpus import ROOT

SRC = ROOT / "benchmarks/raw/sources"
SOURCE_RESEARCH = SRC / "v6_literal_source_research.json"
LINKED_RESEARCH = SRC / "v6_literal_linked_research.json"
LABEL_SCHEMA = SRC / "v6_literal_label_schema.json"
PLAN = SRC / "v6_literal_capture_plan.json"
OUTPUT = SRC / "v6_capture_candidate_proposals.json"

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
    "patch", "patched", "fix", "fixed", "upgrade", "mitigat", "workaround", "unaffected",
    "not affected", "reject", "denied", "allowlist", "validation", "restrict", "prevent",
    "resolved", "remediat", "correction", "safe", "secure", "requires authentication",
    "return 403", "disable",
)
NEAR_TERMS = (
    "requires", "requirement", "prerequisite", "scope", "impact", "affected", "only", "related",
    "adjacent", "severity", "condition", "user interaction", "authenticated", "local", "permission",
    "role", "version", "configuration", "default",
)
PATH_PRIORITY = {"body": 20, "description": 20, "summary": 18, "message": 18, "title": 10}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    out = [piece.strip() for piece in pieces if 35 <= len(piece.strip()) <= 1800]
    if not out and len(cleaned) <= 1800:
        out = [cleaned]
    return out[:500]


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[str, str]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk(child, path + (str(key),))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from _walk(child, path + (str(i),))
    elif isinstance(value, str):
        for piece in _chunks(value):
            yield ".".join(path), piece


def _marker_free(text: str, markers: Iterable[str]) -> bool:
    lowered = text.casefold()
    return not any(marker.casefold() in lowered for marker in markers if marker)


def _rows(source_row: Mapping[str, Any], linked_row: Mapping[str, Any], markers: set[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    canonical_ref = str(source_row.get("canonical_reference") or "")
    for path, text in _walk(source_row.get("snapshot_payload")):
        if _marker_free(text, markers):
            rows.append({"reference": canonical_ref, "resource_type": "canonical", "path": path, "text": text, "origin": 2})
    for resource in linked_row.get("linked_resources") or []:
        if not isinstance(resource, Mapping) or resource.get("fetch_status") != 200 or resource.get("snapshot_payload") is None:
            continue
        ref = str(resource.get("reference") or "")
        rtype = str(resource.get("resource_type") or "linked")
        origin = 5 if rtype in {"commit", "pull_request"} else 3
        for path, text in _walk(resource.get("snapshot_payload")):
            if _marker_free(text, markers):
                rows.append({"reference": ref, "resource_type": rtype, "path": path, "text": text, "origin": origin})
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = _sha(row["text"])
        if key not in unique or row["origin"] > unique[key]["origin"]:
            unique[key] = row
    return list(unique.values())


def _term_score(text: str, terms: Iterable[str]) -> int:
    lower = text.casefold()
    return sum(1 for term in terms if term.casefold() in lower)


def _path_score(path: str) -> int:
    lower = path.casefold()
    return sum(weight for key, weight in PATH_PRIORITY.items() if key in lower)


def _choose(family: str, rows: list[dict[str, Any]], kind: str, used: set[str]) -> dict[str, Any] | None:
    choices = [row for row in rows if _sha(row["text"]) not in used]
    if not choices:
        return None
    if kind == "positive":
        scored = sorted(choices, key=lambda r: (_term_score(r["text"], POSITIVE_TERMS[family]) * 30 + _path_score(r["path"]) + r["origin"], len(r["text"])), reverse=True)
        return scored[0] if _term_score(scored[0]["text"], POSITIVE_TERMS[family]) else None
    if kind == "secure_negative":
        scored = sorted(choices, key=lambda r: (_term_score(r["text"], SECURE_TERMS) * 30 + r["origin"] * 3 + _path_score(r["path"]) - _term_score(r["text"], POSITIVE_TERMS[family]) * 4, len(r["text"])), reverse=True)
        return scored[0] if _term_score(scored[0]["text"], SECURE_TERMS) else None
    scored = sorted(choices, key=lambda r: (_term_score(r["text"], NEAR_TERMS) * 15 + _path_score(r["path"]) + r["origin"] - _term_score(r["text"], SECURE_TERMS) * 8, len(r["text"])), reverse=True)
    return scored[0]


def main() -> int:
    source = json.loads(SOURCE_RESEARCH.read_text(encoding="utf-8"))
    linked = json.loads(LINKED_RESEARCH.read_text(encoding="utf-8"))
    schema = json.loads(LABEL_SCHEMA.read_text(encoding="utf-8"))
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    source_by = {str(row.get("family") or ""): row for row in source.get("entries") or [] if isinstance(row, Mapping)}
    linked_by = {str(row.get("family") or ""): row for row in linked.get("entries") or [] if isinstance(row, Mapping)}
    schema_families = schema.get("families") if isinstance(schema.get("families"), Mapping) else {}
    remaining = sorted({str(row.get("family") or "") for row in plan.get("requirements") or [] if isinstance(row, Mapping) and not bool(row.get("evidence_present"))})
    markers = set(source_by)
    for row in schema_families.values():
        if isinstance(row, Mapping):
            markers.update(str(value) for value in row.get("condition_signals") or [])

    proposals = []
    for family in remaining:
        rows = _rows(source_by[family], linked_by.get(family, {}), markers)
        used: set[str] = set()
        selected = {}
        for kind in ("positive", "secure_negative", "near_miss"):
            row = _choose(family, rows, kind, used)
            if row is not None:
                selected[kind] = row
                used.add(_sha(row["text"]))
        proposals.append({
            "family": family,
            "candidate_excerpt_count": len(rows),
            "positive": selected.get("positive"),
            "secure_negative": selected.get("secure_negative"),
            "near_miss": selected.get("near_miss"),
            "all_three_proposed": all(kind in selected for kind in ("positive", "secure_negative", "near_miss")),
        })
    out = {
        "evaluation_kind": "fresh_blind_v6_capture_candidate_proposals_unscored",
        "remaining_family_count": len(remaining),
        "families_with_three_excerpt_candidates": sum(1 for row in proposals if row["all_three_proposed"]),
        "proposals": proposals,
        "proposal_only_no_evidence_written": True,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }
    OUTPUT.write_text(json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("remaining_family_count", "families_with_three_excerpt_candidates", "scoring_executed")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
