from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

SHORTLIST_VERSION = "1.0.0"
SHORTLIST_RULE_VERSION = "2026.08.12.6.26"
DEFAULT_CANDIDATES = ROOT / "benchmarks" / "raw" / "sources" / "v4_candidates.json"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_shortlist.json"
TARGET_FAMILY_COUNT = 36
TARGET_ROOT_COUNT = 36
TARGET_PROJECT_COUNT = 36

# These are advisory-language disambiguators only. They are intentionally not
# detector signal names and this module never imports ranking/admission/detector
# execution. Candidate family labels originate from external CWE taxonomy.
SEMANTIC_GROUPS: dict[str, tuple[tuple[str, ...], ...]] = {
    "broken_object_authorization": (("idor", "object level authorization", "object-level authorization", "other user", "another user", "ownership", "tenant"), ("unauthorized", "access", "authorization", "permission", "bypass")),
    "broken_function_authorization": (("function level authorization", "function-level authorization", "admin", "privilege", "role", "permission"), ("unauthorized", "bypass", "lower privilege", "access control")),
    "mass_assignment": (("mass assignment", "over-post", "overpost", "property", "field", "parameter"), ("role", "admin", "privilege", "permission", "sensitive", "write")),
    "authentication_session": (("authentication", "login", "session", "token", "oauth", "password", "mfa", "saml", "sso"), ("bypass", "unauthenticated", "validation", "fixation", "rotation", "state", "pkce", "impersonat")),
    "account_enumeration": (("enumerat", "account existence", "username", "email", "existing user"), ("different response", "timing", "oracle", "exist", "response")),
    "dom_xss": (("dom xss", "dom-based", "dom based", "cross-site scripting", "cross site scripting", "xss"), ("innerhtml", "document.write", "location", "javascript", "sink", "source", "dom")),
    "postmessage_trust": (("postmessage", "post message", "message event", "web messaging", "window message"), ("origin", "event.data", "message", "iframe", "window", "source")),
    "open_redirect": (("open redirect", "unvalidated redirect", "redirect"), ("external", "location", "url", "destination", "attacker-controlled")),
    "ssrf": (("ssrf", "server-side request", "server side request"), ("url", "fetch", "internal", "localhost", "metadata", "outbound", "request")),
    "file_upload": (("upload", "uploaded"), ("file", "filename", "mime", "extension", "content-type", "attachment", "dangerous")),
    "path_traversal": (("path traversal", "directory traversal", "../", "..\\", "zip slip"), ("file", "path", "directory", "archive", "extract")),
    "information_disclosure": (("disclos", "expos", "leak"), ("information", "sensitive", "response", "debug", "data", "secret", "internal")),
    "graphql_authorization": (("graphql",), ("authorization", "permission", "resolver", "unauthorized", "access control", "idor")),
    "graphql_data_exposure": (("graphql",), ("field", "data exposure", "disclos", "sensitive", "overfetch", "introspection", "response")),
    "websocket_authorization": (("websocket", "web socket", "ws://", "wss://"), ("authorization", "channel", "subscription", "room", "message", "permission", "tenant")),
    "cors_misconfiguration": (("cors", "cross-origin", "cross origin", "access-control-allow-origin"), ("origin", "credential", "allow-credentials", "response", "read")),
    "sensitive_caching": (("cache", "cache-control", "caching", "cdn"), ("sensitive", "authenticated", "authorization", "cookie", "private", "public", "vary")),
    "business_logic": (("business logic", "workflow", "state transition", "sequence", "process flow"), ("bypass", "invariant", "price", "value", "limit", "step", "transition")),
    "race_condition": (("race condition", "race", "concurrent", "simultaneous", "parallel", "atomic"), ("double", "duplicate", "single-use", "single use", "balance", "redeem", "claim", "transfer")),
    "sql_injection": (("sql injection", "sqli"), ("query", "database", "sql", "select", "where")),
    "nosql_injection": (("nosql", "mongodb", "mongo", "document database"), ("injection", "operator", "query", "$where", "$regex", "filter")),
    "command_injection": (("command injection", "os command", "shell injection"), ("shell", "command", "exec", "process", "spawn", "system(")),
    "server_side_template_injection": (("template injection", "ssti", "server-side template", "server side template"), ("template", "render", "expression", "jinja", "twig", "freemarker")),
    "ldap_injection": (("ldap",), ("injection", "filter", "directory", "search", "distinguished name")),
    "unrestricted_resource_consumption": (("resource", "denial of service", " dos", "memory", "cpu", "exhaust"), ("unbounded", "large", "size", "runtime", "limit", "amplif", "request")),
    "sensitive_business_flow_abuse": (("automation", "bot", "scalp", "abuse", "business flow", "reservation", "booking", "signup", "redeem", "coupon", "purchase"), ("limit", "frequency", "bulk", "multiple", "unrestricted", "rate", "bypass")),
    "security_misconfiguration": (("misconfiguration", "configuration", "debug", "stack trace", "directory listing", "security header", "http method"), ("exposed", "enabled", "unsafe", "default", "response", "cleartext", "trace")),
    "improper_inventory_management": (("legacy", "deprecated", "old version", "api version", "staging", "development", "non-production", "nonproduction"), ("api", "endpoint", "version", "reachable", "active", "exposed", "inventory")),
    "unsafe_api_consumption": (("third-party", "third party", "upstream", "vendor", "external api", "external service", "integration"), ("validation", "tls", "redirect", "timeout", "trust", "response", "sanitize")),
    "source_map_exposure": (("source map", "sourcemap", "sourceMappingURL", ".map"), ("source", "exposed", "public", "sourcescontent", "internal", "javascript")),
    "secret_exposure": (("hard-coded", "hardcoded", "embedded", "bundled", "credential", "secret"), ("api key", "password", "token", "private key", "credential", "secret", "key")),
    "software_supply_chain_failure": (("supply chain", "dependency", "package", "component", "build pipeline", "ci/cd", "artifact", "registry"), ("vulnerable", "unmaintained", "untrusted", "compromis", "malicious", "dependency", "package")),
    "cryptographic_failure": (("cryptograph", "crypto", "tls", "ssl", "cipher", "encrypt", "random", "nonce", "hash"), ("weak", "plaintext", "predictable", "downgrade", "reuse", "md5", "sha1", "sha-1", "insecure")),
    "software_data_integrity_failure": (("integrity", "deserial", "software update", "firmware", "signature", "pickle", "yaml", "objectinputstream"), ("unsigned", "untrusted", "verification", "verify", "unsafe", "execute", "tamper", "deserialize")),
    "security_logging_alerting_failure": (("log", "logging", "audit", "telemetry", "alert"), ("missing", "absent", "injection", "sensitive", "password", "token", "secret", "integrity", "alert")),
    "exceptional_condition_mishandling": (("exception", "error handling", "panic", "crash", "segmentation fault", "fatal error"), ("unhandled", "fail open", "fail-open", "rollback", "partial", "state", "bypass", "crash")),
}

GENERIC_ARTIFACT_MARKERS = (
    "proof of concept", "## poc", "### poc", "```", "curl ", "http ", "request", "response",
    "status code", "stack trace", "expected", "actual", "reproduction", "steps to reproduce",
)


def _text(row: Mapping[str, Any]) -> str:
    return (str(row.get("summary") or "") + "\n" + str(row.get("description") or "")).lower()


def _semantic_score(family: str, row: Mapping[str, Any]) -> tuple[bool, int, list[str]]:
    text = _text(row)
    groups = SEMANTIC_GROUPS[family]
    hits: list[str] = []
    for group in groups:
        group_hits = [term for term in group if term.lower() in text]
        if not group_hits:
            return False, 0, hits
        hits.extend(group_hits)
    score = len(set(hits)) * 3
    for marker in GENERIC_ARTIFACT_MARKERS:
        if marker in text:
            score += 1
    if re.search(r"(?im)\b(?:GET|POST|PUT|PATCH|DELETE)\s+/", text):
        score += 2
    if re.search(r"(?i)\b(?:HTTP\s*)?[1-5][0-9]{2}\b", text):
        score += 1
    if row.get("repository_advisory_url"):
        score += 2
    if row.get("source_code_location"):
        score += 1
    return True, score, sorted(set(hits))


def build_shortlist(candidates: Mapping[str, Any]) -> dict[str, Any]:
    pools = candidates.get("candidates_by_family") if isinstance(candidates.get("candidates_by_family"), Mapping) else {}
    if set(pools) != set(SEMANTIC_GROUPS):
        missing = sorted(set(SEMANTIC_GROUPS) - set(pools))
        extra = sorted(set(pools) - set(SEMANTIC_GROUPS))
        raise RuntimeError(f"v4 candidate family mismatch missing={missing} extra={extra}")

    eligible: dict[str, list[dict[str, Any]]] = {}
    semantic_rejections: dict[str, int] = {}
    for family in sorted(SEMANTIC_GROUPS):
        rows: list[dict[str, Any]] = []
        rejected = 0
        for raw in pools.get(family, []):
            if not isinstance(raw, Mapping):
                continue
            row = dict(raw)
            ok, score, hits = _semantic_score(family, row)
            if not ok:
                rejected += 1
                continue
            row["shortlist_semantic_score"] = score
            row["shortlist_semantic_hits"] = hits
            rows.append(row)
        rows.sort(
            key=lambda item: (
                int(item["shortlist_semantic_score"]),
                str(item.get("published_at") or ""),
                str(item.get("source_root") or ""),
            ),
            reverse=True,
        )
        eligible[family] = rows
        semantic_rejections[family] = rejected

    # Scarce families choose first. This maximizes the chance that globally unique
    # projects can be assigned without looking at any detector/ranker result.
    family_order = sorted(eligible, key=lambda family: (len(eligible[family]), family))
    selected: list[dict[str, Any]] = []
    used_roots: set[str] = set()
    used_projects: set[str] = set()
    missing_families: list[str] = []
    for family in family_order:
        chosen: dict[str, Any] | None = None
        for row in eligible[family]:
            root = str(row.get("source_root") or "")
            project = str(row.get("source_project") or "")
            if not root or not project or root in used_roots or project in used_projects:
                continue
            chosen = dict(row)
            break
        if chosen is None:
            missing_families.append(family)
            continue
        selected.append(chosen)
        used_roots.add(str(chosen["source_root"]))
        used_projects.add(str(chosen["source_project"]))

    selected.sort(key=lambda row: str(row.get("family") or ""))
    selected_families = {str(row.get("family") or "") for row in selected}
    return {
        "shortlist_version": SHORTLIST_VERSION,
        "shortlist_rule_version": SHORTLIST_RULE_VERSION,
        "target_family_count": TARGET_FAMILY_COUNT,
        "target_root_count": TARGET_ROOT_COUNT,
        "target_project_count": TARGET_PROJECT_COUNT,
        "selected_family_count": len(selected_families),
        "selected_root_count": len(used_roots),
        "selected_project_count": len(used_projects),
        "missing_families": sorted(missing_families),
        "eligible_family_counts": {family: len(rows) for family, rows in sorted(eligible.items())},
        "semantic_rejection_counts": semantic_rejections,
        "selection_executes_analysis_engine": False,
        "selection_uses_detector_scores": False,
        "selection_uses_admission_results": False,
        "selection_uses_benchmark_results": False,
        "selected": selected,
        "selection_note": (
            "Exactly one candidate is chosen per family using only pre-scoring CWE family assignment, advisory-language semantic fit, "
            "artifact richness, recency, and globally unique project/root constraints. No Analysis Engine output participates in selection."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the pre-scoring Analysis 6.26 raw v4 36-family shortlist")
    parser.add_argument("--candidates", default=str(DEFAULT_CANDIDATES))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
    report = build_shortlist(candidates)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "selected_family_count": report["selected_family_count"],
        "selected_root_count": report["selected_root_count"],
        "selected_project_count": report["selected_project_count"],
        "missing_families": report["missing_families"],
        "eligible_family_counts": report["eligible_family_counts"],
    }, indent=2, sort_keys=True))
    complete = (
        report["selected_family_count"] == TARGET_FAMILY_COUNT
        and report["selected_root_count"] == TARGET_ROOT_COUNT
        and report["selected_project_count"] == TARGET_PROJECT_COUNT
        and not report["missing_families"]
    )
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
