from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

AUDIT_VERSION = "1.0.0"
AUDIT_RULE_VERSION = "2026.08.12.6.26"
DEFAULT_CANDIDATES = ROOT / "benchmarks" / "raw" / "sources" / "v4_candidates.json"
DEFAULT_SHORTLIST = ROOT / "benchmarks" / "raw" / "sources" / "v4_shortlist.json"
DEFAULT_SUPPLEMENT = ROOT / "benchmarks" / "raw" / "sources" / "v4_primary_supplement.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_source_family_audit.json"
DEFAULT_REBUILT = ROOT / "benchmarks" / "raw" / "sources" / "v4_shortlist_audited.json"

# Each family must satisfy EVERY group; one phrase from each group is enough.
# These are source-advisory semantics, not detector signal names. The audit is
# deliberately stricter than CWE assignment so broad CWE matches cannot silently
# become a benchmark case for the wrong vulnerability family.
HARD_ANCHORS: dict[str, tuple[tuple[str, ...], ...]] = {
    "account_enumeration": (("enumerat", "account existence", "user existence", "registered email", "existing user"), ("email", "username", "account", "user")),
    "authentication_session": (("authentication", "login", "session", "saml", "oauth", "token", "mfa"), ("bypass", "impersonat", "fixation", "validation", "forg", "stolen", "reuse")),
    "broken_function_authorization": (("function level authorization", "function-level authorization", "admin", "privilege", "role", "permission"), ("unauthorized", "bypass", "access control", "low privilege", "lower privilege")),
    "broken_object_authorization": (("idor", "object level authorization", "object-level authorization", "other user", "another user", "tenant", "ownership"), ("unauthorized", "access control", "authorization", "permission", "bypass")),
    "business_logic": (("business logic", "workflow", "payment status", "order status", "state transition", "price", "checkout"), ("bypass", "without proper", "invalid", "unpaid", "skip", "incorrect", "invariant")),
    "command_injection": (("command injection", "os command injection", "shell injection"), ("command", "shell", "exec", "process", "system")),
    "cors_misconfiguration": (("cors", "cross-origin resource sharing", "access-control-allow-origin"), ("origin", "credential", "allow-credentials", "cross-origin")),
    "cryptographic_failure": (("pbkdf", "cryptograph", "crypto", "cipher", "tls", "ssl", "random", "nonce", "hash"), ("weak", "insecure", "predictable", "downgrade", "reuse", "plaintext", "iteration")),
    "dom_xss": (("dom xss", "dom-based xss", "dom based xss", "dom-based cross-site scripting", "dom based cross-site scripting"), ("innerhtml", "outerhtml", "document.write", "insertadjacenthtml", "location.hash", "location.search", "document.url", "dom sink", "dom source")),
    "exceptional_condition_mishandling": (("unhandled exception", "uncaught exception", "panic", "crash", "fatal error", "fail open", "fail-open"), ("exception", "error", "panic", "crash", "rollback", "state", "bypass")),
    "file_upload": (("file upload", "upload file", "uploaded file", "arbitrary file upload", "unrestricted upload"), ("file", "upload", "mime", "extension", "filename", "attachment")),
    "graphql_authorization": (("graphql",), ("authorization", "access control", "unauthorized", "permission", "scope"), ("field", "resolver", "query", "mutation", "schema")),
    "graphql_data_exposure": (("graphql",), ("data exposure", "information disclosure", "sensitive", "xs-search", "cross-site request forgery", "csrf", "read-only"), ("query", "field", "response", "schema", "data")),
    "improper_inventory_management": (("legacy", "deprecated", "old version", "outdated api", "staging", "non-production", "nonproduction", "retired endpoint"), ("endpoint", "api", "version", "host", "environment"), ("reachable", "active", "exposed", "public", "accessible", "still")),
    "information_disclosure": (("information disclosure", "sensitive information", "data exposure", "leak", "disclos"), ("exposed", "response", "public", "unauthorized", "sensitive", "internal")),
    "ldap_injection": (("ldap injection",), ("ldap", "filter", "directory")),
    "mass_assignment": (("mass assignment", "over-posting", "overposting", "over post"), ("field", "property", "parameter", "role", "admin", "privilege")),
    "nosql_injection": (("nosql injection", "mongodb injection", "mongo injection"), ("mongodb", "mongo", "nosql", "operator", "query")),
    "open_redirect": (("open redirect", "unvalidated redirect", "external redirect"), ("redirect", "location", "url", "destination")),
    "path_traversal": (("path traversal", "directory traversal", "zip slip"), ("path", "file", "directory", "archive", "extract")),
    "postmessage_trust": (("postmessage", "post message", "message event", "window message"), ("origin validation", "origin check", "e.origin", "missing origin", "cross-origin"), ("handler", "message", "iframe", "window")),
    "race_condition": (("race condition", "toctou", "time-of-check", "time of check", "concurrent", "simultaneous"), ("race", "atomic", "overwrite", "duplicate", "double", "concurrent", "time-of")),
    "secret_exposure": (("hardcoded", "hard-coded", "credential", "secret", "api key", "private key", "password", "token"), ("expos", "leak", "public", "client", "repository", "source", "bundle")),
    "security_logging_alerting_failure": (("log", "logging", "audit", "telemetry", "alert"), ("sensitive", "password", "token", "api key", "secret", "injection", "not logged", "missing log", "no alert")),
    "security_misconfiguration": (("misconfiguration", "configuration", "debug", "default configuration", "directory listing", "stack trace", "security header"), ("exposed", "enabled", "insecure", "unsafe", "default", "public")),
    "sensitive_business_flow_abuse": (("password reset", "reservation", "booking", "signup", "purchase", "coupon", "redeem", "business flow", "functionality misuse"), ("flood", "rate limit", "automation", "abuse", "unrestricted", "multiple", "bulk", "limit")),
    "sensitive_caching": (("cache", "caching", "cdn"), ("session", "cookie", "authentication", "authenticated", "sensitive"), ("cached", "cache-control", "public cache", "cdn", "shared cache")),
    "server_side_template_injection": (("server-side template injection", "server side template injection", "ssti", "template injection"), ("template", "render", "expression", "jinja", "twig", "freemarker")),
    "software_data_integrity_failure": (("deserial", "pickle", "unsafe yaml", "unsigned update", "signature verification", "integrity verification", "software update", "firmware"), ("untrusted", "arbitrary code", "code execution", "unsigned", "unsafe", "tamper", "malicious")),
    "software_supply_chain_failure": (("dependency", "package", "supply chain", "build pipeline", "artifact", "registry", "module"), ("malicious", "compromis", "untrusted", "vulnerable", "unmaintained", "dependency response", "package source")),
    "source_map_exposure": (("source map", "sourcemap", "sourcemappingurl", ".js.map", "sourcescontent"), ("expos", "public", "disclos", "accessible", "served", "published")),
    "sql_injection": (("sql injection", "sqli"), ("sql", "database", "query")),
    "ssrf": (("ssrf", "server-side request forgery", "server side request forgery"), ("url", "request", "internal", "localhost", "metadata", "fetch")),
    "unrestricted_resource_consumption": (("denial of service", "resource exhaustion", "unbounded", "memory exhaustion", "cpu exhaustion", "resource consumption"), ("memory", "cpu", "resource", "large", "unbounded", "dos", "exhaust")),
    "unsafe_api_consumption": (("third-party api", "third party api", "external api", "upstream api", "upstream service", "external service", "third-party service"), ("validation", "trust", "sanitize", "tls", "redirect", "timeout", "untrusted", "response")),
    "websocket_authorization": (("websocket", "web socket", "stomp"), ("unauthorized", "authorization", "access control", "security bypass", "permission"), ("message", "subscription", "channel", "socket", "stomp")),
}


def _text(row: Mapping[str, Any]) -> str:
    return (str(row.get("summary") or "") + "\n" + str(row.get("description") or "")).lower()


def audit_row(family: str, row: Mapping[str, Any]) -> tuple[bool, list[list[str]], int]:
    text = _text(row)
    group_hits: list[list[str]] = []
    score = 0
    for group in HARD_ANCHORS[family]:
        hits = sorted({term for term in group if term.lower() in text})
        group_hits.append(hits)
        if not hits:
            return False, group_hits, score
        score += 5 + len(hits)
    if str(row.get("repository_advisory_url") or ""):
        score += 2
    if str(row.get("source_code_location") or ""):
        score += 1
    return True, group_hits, score


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise RuntimeError(f"expected object in {path}")
    return dict(value)


def rebuild(candidates: Mapping[str, Any], shortlist: Mapping[str, Any], supplement: Mapping[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    selected = {str(row.get("family") or ""): dict(row) for row in shortlist.get("selected") or [] if isinstance(row, Mapping)}
    if set(selected) != set(HARD_ANCHORS):
        raise RuntimeError(f"shortlist family coverage mismatch: {len(selected)}/36")
    pools_raw = candidates.get("candidates_by_family") if isinstance(candidates.get("candidates_by_family"), Mapping) else {}
    pools: dict[str, list[dict[str, Any]]] = {
        family: [dict(row) for row in pools_raw.get(family, []) if isinstance(row, Mapping)]
        for family in HARD_ANCHORS
    }
    if supplement is not None:
        for row in supplement.get("selected") or []:
            if isinstance(row, Mapping) and str(row.get("family") or "") in pools:
                pools[str(row["family"])].append(dict(row))

    initial_audit: dict[str, Any] = {}
    failed: list[str] = []
    for family, row in sorted(selected.items()):
        passed, hits, score = audit_row(family, row)
        initial_audit[family] = {
            "passed": passed,
            "score": score,
            "group_hits": hits,
            "source_root": row.get("source_root"),
            "source_project": row.get("source_project"),
            "summary": row.get("summary"),
        }
        if not passed:
            failed.append(family)

    # Rebuild the complete 36-family assignment rather than patching failures in
    # place. This guarantees project/root uniqueness is checked globally after
    # stricter semantic validation, still without any engine scoring.
    eligible: dict[str, list[dict[str, Any]]] = {}
    for family in sorted(HARD_ANCHORS):
        rows: list[dict[str, Any]] = []
        seen_roots: set[str] = set()
        for raw in pools[family]:
            root = str(raw.get("source_root") or "")
            project = str(raw.get("source_project") or "")
            if not root or not project or root in seen_roots:
                continue
            passed, hits, score = audit_row(family, raw)
            if not passed:
                continue
            row = dict(raw)
            row["source_family_audit_version"] = AUDIT_VERSION
            row["source_family_audit_rule_version"] = AUDIT_RULE_VERSION
            row["source_family_audit_score"] = score
            row["source_family_audit_group_hits"] = hits
            rows.append(row)
            seen_roots.add(root)
        rows.sort(key=lambda row: (int(row["source_family_audit_score"]), str(row.get("published_at") or ""), str(row.get("source_root") or "")), reverse=True)
        eligible[family] = rows

    family_order = sorted(eligible, key=lambda family: (len(eligible[family]), family))
    rebuilt: list[dict[str, Any]] = []
    used_roots: set[str] = set()
    used_projects: set[str] = set()
    missing: list[str] = []
    for family in family_order:
        chosen = None
        for row in eligible[family]:
            root = str(row["source_root"])
            project = str(row["source_project"])
            if root in used_roots or project in used_projects:
                continue
            chosen = dict(row)
            break
        if chosen is None:
            missing.append(family)
            continue
        rebuilt.append(chosen)
        used_roots.add(str(chosen["source_root"]))
        used_projects.add(str(chosen["source_project"]))
    rebuilt.sort(key=lambda row: str(row["family"]))

    changed = []
    rebuilt_by_family = {str(row["family"]): row for row in rebuilt}
    for family in sorted(set(selected) & set(rebuilt_by_family)):
        before = selected[family]
        after = rebuilt_by_family[family]
        if str(before.get("source_root")) != str(after.get("source_root")):
            changed.append({
                "family": family,
                "before_root": before.get("source_root"),
                "before_project": before.get("source_project"),
                "before_summary": before.get("summary"),
                "after_root": after.get("source_root"),
                "after_project": after.get("source_project"),
                "after_summary": after.get("summary"),
            })

    audit = {
        "audit_version": AUDIT_VERSION,
        "audit_rule_version": AUDIT_RULE_VERSION,
        "initial_failed_family_count": len(failed),
        "initial_failed_families": failed,
        "eligible_family_counts": {family: len(rows) for family, rows in sorted(eligible.items())},
        "rebuilt_family_count": len(rebuilt_by_family),
        "rebuilt_root_count": len(used_roots),
        "rebuilt_project_count": len(used_projects),
        "missing_families": missing,
        "changed_selection_count": len(changed),
        "changed_selections": changed,
        "initial_audit": initial_audit,
        "selection_executes_analysis_engine": False,
        "selection_uses_detector_scores": False,
        "selection_uses_admission_results": False,
        "selection_uses_benchmark_results": False,
        "note": "Hard source-family semantic audit executed before raw corpus materialization and before any Analysis Engine scoring.",
    }
    rebuilt_shortlist = {
        **{k: v for k, v in shortlist.items() if k != "selected"},
        "source_family_audit_version": AUDIT_VERSION,
        "source_family_audit_rule_version": AUDIT_RULE_VERSION,
        "selected_family_count": len(rebuilt_by_family),
        "selected_root_count": len(used_roots),
        "selected_project_count": len(used_projects),
        "missing_families": missing,
        "selected": rebuilt,
        "selection_note": "Final pre-scoring shortlist after strict source-family semantic audit; no Analysis Engine output participated.",
    }
    return audit, rebuilt_shortlist


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit Analysis 6.26 source-family semantic fit before materialization")
    parser.add_argument("--candidates", default=str(DEFAULT_CANDIDATES))
    parser.add_argument("--shortlist", default=str(DEFAULT_SHORTLIST))
    parser.add_argument("--supplement", default=str(DEFAULT_SUPPLEMENT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--rebuilt", default=str(DEFAULT_REBUILT))
    args = parser.parse_args()
    candidates = _load(Path(args.candidates))
    shortlist = _load(Path(args.shortlist))
    supplement_path = Path(args.supplement)
    supplement = _load(supplement_path) if supplement_path.exists() else None
    audit, rebuilt_shortlist = rebuild(candidates, shortlist, supplement)
    Path(args.output).write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(args.rebuilt).write_text(json.dumps(rebuilt_shortlist, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "initial_failed_families": audit["initial_failed_families"],
        "eligible_family_counts": audit["eligible_family_counts"],
        "rebuilt_family_count": audit["rebuilt_family_count"],
        "rebuilt_root_count": audit["rebuilt_root_count"],
        "rebuilt_project_count": audit["rebuilt_project_count"],
        "missing_families": audit["missing_families"],
        "changed_selections": audit["changed_selections"],
    }, indent=2, ensure_ascii=False, sort_keys=True))
    complete = audit["rebuilt_family_count"] == 36 and audit["rebuilt_root_count"] == 36 and audit["rebuilt_project_count"] == 36 and not audit["missing_families"]
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
