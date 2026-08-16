from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from core import (
    AppPaths,
    Config,
    Database,
    PolicySet,
    ReconError,
    TargetPolicy,
    json_dumps,
    normalize_url,
    parse_int,
    safe_json_loads,
    sha256_text,
    utc_now,
)
from family_reasoning import FAMILY_REASONING, validation_level_for_family
from safe_transport import perform_pinned_request

VALIDATION_VERSION = "6.2.0"
VALIDATION_LEVELS = ["offline", "passive_live", "controlled", "manual_only"]
PLAN_STATES = ["plan_ready", "awaiting_approval", "approved", "running", "completed", "stopped_for_safety", "failed", "not_eligible"]
VALIDATION_RESULTS = ["strengthened", "weakened", "inconclusive", "manual_only", "offline_only", "blocked_by_scope", "stopped_for_safety"]
FEEDBACK_DECISIONS = ["useful", "confirmed_by_analyst", "rejected", "needs_more_evidence", "false_positive"]
FEEDBACK_REASONS = [
    "ownership_boundary_failure", "role_boundary_failure", "unexpected_sensitive_data", "authentication_regression",
    "state_machine_violation", "cross_tenant_behavior", "expected_behavior", "authorization_enforced",
    "identifier_ignored", "duplicate", "unreachable_code", "parser_error", "wrong_bug_family",
    "out_of_scope", "insufficient_evidence",
]

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_REQUESTS = 3
MAX_RUNTIME_SECONDS = 15
MAX_RESPONSE_BYTES = 256 * 1024
MIN_DELAY_SECONDS = 1.0
SAFE_ORIGIN = "https://safe-validation.invalid"

DANGEROUS_PATH_WORDS = {
    "logout", "signout", "delete", "destroy", "remove", "unsubscribe", "reset", "confirm", "verify",
    "activate", "deactivate", "refund", "withdraw", "transfer", "payment", "checkout", "purchase",
    "role", "permission", "invite", "webhook", "callback", "upload", "import", "execute", "trigger",
}
DANGEROUS_QUERY_KEYS = {
    "token", "code", "state", "password", "passwd", "secret", "key", "signature", "sig", "email",
    "phone", "redirect", "redirect_uri", "return", "return_url", "next", "url", "target", "dest",
}
SENSITIVE_KEY_WORDS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token", "api_key", "apikey",
    "authorization", "cookie", "session", "credit_card", "card_number", "cvv", "ssn", "national_id",
    "account_number", "balance", "iban", "email", "phone", "address", "role", "permission",
}
SENSITIVE_PATTERNS = {
    "email": re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "bearer_token": re.compile(rb"(?i)bearer\s+[A-Za-z0-9._~+/-]{12,}"),
    "jwt_like": re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

LEGACY_MANUAL_FAMILY_HINTS = {
    "ssrf", "server side request", "xss", "cross site scripting", "file upload", "path traversal", "race",
    "business logic", "payment", "refund", "account recovery", "role modification", "stored xss", "command",
}
LEGACY_CONTROLLED_FAMILY_HINTS = {
    "bola", "idor", "object authorization", "bfla", "function authorization", "mass assignment",
    "graphql authorization", "websocket authorization", "cross tenant", "cross-tenant",
}
LEGACY_PASSIVE_FAMILY_HINTS = {
    "authentication", "session", "information disclosure", "excessive data", "cors", "redirect", "cache",
    "source map", "secret exposure", "graphql data", "enumeration",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _loads(value: Any, default: Any) -> Any:
    return safe_json_loads(value, default, expected_type=type(default))


def _case(db: Database, case_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    row = db.one("SELECT * FROM security_cases WHERE case_id=?", (case_id,))
    if not row:
        raise ReconError(f"Case not found: {case_id}")
    candidates = [dict(item) for item in db.all(
        "SELECT c.* FROM security_case_members m JOIN bug_candidates c ON c.candidate_id=m.member_id "
        "WHERE m.case_id=? AND m.member_type='candidate' ORDER BY c.investigation_value DESC,c.priority_score DESC",
        (case_id,),
    )]
    return dict(row), candidates


def _family_text(case: dict[str, Any], candidates: Iterable[dict[str, Any]]) -> str:
    values = [str(case.get("primary_family") or "")]
    for row in candidates:
        values.extend((str(row.get("bug_family") or ""), str(row.get("bug_variant") or ""), str(row.get("title") or "")))
    return " ".join(values).lower()


def _canonical_family_id(case: dict[str, Any], candidates: Iterable[dict[str, Any]]) -> str:
    values = [str(case.get("primary_family") or "")]
    values.extend(str(row.get("bug_family") or "") for row in candidates)
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        if value in FAMILY_REASONING:
            return value
        normalized = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
        if normalized in FAMILY_REASONING:
            return normalized
        lower = value.lower()
        for family, policy in FAMILY_REASONING.items():
            if lower == str(policy.get("label") or "").strip().lower():
                return family
    aliases = {
        "bola": "broken_object_authorization",
        "idor": "broken_object_authorization",
        "bola / idor": "broken_object_authorization",
        "bfla": "broken_function_authorization",
        "xss": "dom_xss",
        "dom xss": "dom_xss",
        "source map exposure": "source_map_exposure",
        "secret exposure": "secret_exposure",
        "graphql authorization": "graphql_authorization",
        "graphql data exposure": "graphql_data_exposure",
        "websocket authorization": "websocket_authorization",
        "cors": "cors_misconfiguration",
        "sensitive caching": "sensitive_caching",
    }
    for raw in values:
        resolved = aliases.get(str(raw or "").strip().lower())
        if resolved:
            return resolved
    return ""


def validation_eligibility(db: Database, case_id: str) -> dict[str, Any]:
    case, candidates = _case(db, case_id)
    family_text = _family_text(case, candidates)
    canonical_family = _canonical_family_id(case, candidates)
    reasons: list[str] = []
    if canonical_family:
        level = validation_level_for_family(canonical_family)
        reason_by_level = {
            "offline": "Family Reasoning defines this family as offline-only for automatic validation.",
            "passive_live": "Family Reasoning permits only bounded passive-live observation for this family.",
            "controlled": "Family Reasoning requires explicitly controlled test identities/resources for this family.",
            "manual_only": "Family Reasoning requires manual-only validation because active automation could cause unsafe effects.",
        }
        reasons.append(reason_by_level.get(level, "Family Reasoning did not define a live validation recipe."))
    elif any(hint in family_text for hint in LEGACY_MANUAL_FAMILY_HINTS):
        level = "manual_only"
        reasons.append("Legacy family text maps to a manual-only safety class; no canonical family identifier was available.")
    elif any(hint in family_text for hint in LEGACY_CONTROLLED_FAMILY_HINTS):
        level = "controlled"
        reasons.append("Legacy family text maps to controlled validation; canonical family metadata should be added.")
    elif any(hint in family_text for hint in LEGACY_PASSIVE_FAMILY_HINTS):
        level = "passive_live"
        reasons.append("Legacy family text maps to passive-live validation; canonical family metadata should be added.")
    else:
        level = "offline"
        reasons.append("Unknown/non-canonical family fails closed to offline validation.")
    executable = level in {"offline", "passive_live"}
    return {
        "case_id": case_id,
        "target": case["target"],
        "primary_family": case["primary_family"],
        "canonical_family": canonical_family,
        "recommended_level": level,
        "executable_in_this_release": executable,
        "reasons": reasons,
        "constraints": {
            "methods": sorted(SAFE_METHODS),
            "maximum_requests": MAX_REQUESTS,
            "maximum_runtime_seconds": MAX_RUNTIME_SECONDS,
            "maximum_response_bytes": MAX_RESPONSE_BYTES,
            "redirects_followed": False,
            "cookies_or_credentials": False,
            "identifier_enumeration": False,
            "state_changes": False,
        },
    }


def _policy_for_target(paths: AppPaths, target: str) -> TargetPolicy | None:
    try:
        policies = PolicySet.load(paths)
    except Exception:
        return None
    target_host = urllib.parse.urlsplit(target if "://" in target else f"https://{target}").hostname or target
    for policy in policies.targets:
        if policy.name == target or target in policy.roots or policy.host_in_scope(target_host):
            return policy
    return None


def _candidate_url_targets(db: Database, target: str, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Resolve candidate endpoints while preserving which candidate owns each URL.

    Validation requests are case-scoped, but evidence links are candidate-scoped.
    Carrying candidate IDs from planning prevents a response for one endpoint
    from being attached to unrelated candidates that merely share the case.
    """
    found: dict[str, set[str]] = {}
    for row in candidates:
        candidate_id = str(row.get("candidate_id") or "").strip()
        endpoint = str(row.get("endpoint") or "").strip()
        source_ref = str(row.get("source_ref") or "").strip()
        for value in (endpoint, source_ref):
            if not value:
                continue
            normalized = normalize_url(value)
            if not normalized:
                validation = db.one(
                    "SELECT resolved_url FROM endpoint_validations WHERE target=? AND endpoint=? ORDER BY checked_at DESC LIMIT 1",
                    (target, value),
                )
                if validation:
                    normalized = normalize_url(str(validation["resolved_url"] or ""))
            if not normalized and value.startswith("/") and "{" not in value and "}" not in value:
                normalized = normalize_url(f"https://{target}{value}")
            if not normalized:
                continue
            parsed = urllib.parse.urlsplit(normalized)
            # Queries are not replayed automatically. This prevents token reuse
            # and state-changing/sensitive parameters from being re-used.
            clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            if candidate_id:
                found.setdefault(clean, set()).add(candidate_id)
    return [
        {"url": url, "candidate_ids": sorted(candidate_ids)}
        for url, candidate_ids in list(found.items())[:3]
    ]


def _candidate_urls(db: Database, target: str, candidates: list[dict[str, Any]]) -> list[str]:
    """Compatibility projection for callers that only need URLs."""
    return [item["url"] for item in _candidate_url_targets(db, target, candidates)]


def _url_safety(url: str, policy: TargetPolicy | None) -> tuple[bool, str]:
    normalized = normalize_url(url)
    if not normalized:
        return False, "invalid_url"
    parsed = urllib.parse.urlsplit(normalized)
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "localhost.localdomain"}:
        return False, "local_host_blocked"
    if policy is None or not policy.url_in_scope(normalized):
        return False, "outside_scope"
    words = {item for item in re.split(r"[^a-z0-9]+", parsed.path.lower()) if item}
    if words & DANGEROUS_PATH_WORDS:
        return False, "state_changing_path"
    query_keys = {key.lower() for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
    if query_keys & DANGEROUS_QUERY_KEYS:
        return False, "sensitive_query"
    return True, "safe"


def _request_recipe(family: str, url: str, *, candidate_ids: Iterable[str] = ()) -> list[dict[str, Any]]:
    family_id = str(family or "").strip().lower()
    owners = sorted({str(value) for value in candidate_ids if str(value).strip()})

    def request(method: str, headers: dict[str, str], purpose: str) -> dict[str, Any]:
        return {
            "method": method,
            "url": url,
            "headers": headers,
            "purpose": purpose,
            "candidate_ids": owners,
        }

    if family_id == "cors_misconfiguration" or "cors" in family_id:
        return [
            request("OPTIONS", {"Origin": SAFE_ORIGIN, "Access-Control-Request-Method": "GET"}, "Observe preflight policy"),
            request("GET", {"Origin": SAFE_ORIGIN}, "Observe CORS response headers"),
        ]
    if family_id == "source_map_exposure" or "source map" in family_id or url.endswith(".map"):
        return [request("GET", {}, "Presence and metadata check only")]
    if family_id == "open_redirect" or "redirect" in family_id:
        return [request("GET", {}, "Inspect Location without following redirect")]
    if family_id == "authentication_session" or "authentication" in family_id or "session" in family_id:
        return [request("GET", {}, "Anonymous boundary observation")]
    if family_id == "sensitive_caching" or "cache" in family_id or "caching" in family_id:
        return [request("GET", {}, "Observe cache directives and redacted response shape")]
    return [
        request("HEAD", {}, "Reachability and response metadata"),
        request("GET", {}, "Redacted response-shape observation"),
    ]


def create_validation_plan(paths: AppPaths, db: Database, case_id: str, *, requested_level: str = "", actor: str = "analyst") -> dict[str, Any]:
    case, candidates = _case(db, case_id)
    eligibility = validation_eligibility(db, case_id)
    recommended = str(eligibility["recommended_level"])
    level = requested_level or recommended
    if level not in VALIDATION_LEVELS:
        raise ReconError(f"Invalid validation level: {level}")
    # Offline validation is always allowed. A controlled/manual family cannot
    # be downgraded into passive-live simply by selecting a different level.
    allowed_levels = {
        "offline": {"offline"},
        "passive_live": {"offline", "passive_live", "controlled", "manual_only"},
        "controlled": {"offline", "controlled", "manual_only"},
        "manual_only": {"offline", "manual_only"},
    }
    if level not in allowed_levels.get(recommended, {recommended}):
        raise ReconError(f"Requested level {level} is less restrictive than required level {recommended}")
    policy = _policy_for_target(paths, str(case["target"]))
    targets = _candidate_url_targets(db, str(case["target"]), candidates)
    safe_targets: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for target_item in targets:
        url = str(target_item.get("url") or "")
        allowed, reason = _url_safety(url, policy)
        if allowed:
            safe_targets.append(target_item)
        else:
            blocked.append({
                "url": url,
                "reason": reason,
                "candidate_ids": list(target_item.get("candidate_ids") or []),
            })
    family = str(eligibility.get("canonical_family") or "") or _family_text(case, candidates)
    requests: list[dict[str, Any]] = []
    if level == "passive_live":
        for target_item in safe_targets:
            requests.extend(
                _request_recipe(
                    family,
                    str(target_item["url"]),
                    candidate_ids=target_item.get("candidate_ids") or (),
                )
            )
            if len(requests) >= MAX_REQUESTS:
                break
        requests = requests[:MAX_REQUESTS]
    status = "plan_ready" if level == "offline" else "awaiting_approval" if level == "passive_live" and requests else "not_eligible"
    if level in {"controlled", "manual_only"}:
        status = "not_eligible"
    plan_id = "SVP-" + uuid.uuid4().hex[:12].upper()
    confirmation = f"I_CONFIRM_SAFE_VALIDATION_FOR_{plan_id}"
    plan = {
        "plan_id": plan_id,
        "case_id": case_id,
        "target": case["target"],
        "primary_family": case["primary_family"],
        "level": level,
        "status": status,
        "eligibility": eligibility,
        "requests": requests,
        "blocked_urls": blocked,
        "budgets": {
            "maximum_requests": MAX_REQUESTS,
            "maximum_runtime_seconds": MAX_RUNTIME_SECONDS,
            "maximum_response_bytes": MAX_RESPONSE_BYTES,
            "minimum_delay_seconds": MIN_DELAY_SECONDS,
            "concurrency": 1,
            "retries": 0,
        },
        "stop_conditions": [
            "Stop on HTTP 429.", "Stop after repeated 5xx responses.", "Stop if redirect leaves scope.",
            "Stop if response exceeds the byte budget.", "Stop if a state-changing endpoint is detected.",
            "Do not store raw bodies; store only hashes, bounded shapes and redacted metadata.",
        ],
        "approval_phrase": confirmation if level == "passive_live" else "",
        "created_at": utc_now(),
        "created_by": actor,
    }
    db.execute(
        "INSERT INTO validation_plans(plan_id,case_id,target,level,status,plan_json,approval_phrase_hash,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (plan_id, case_id, case["target"], level, status, json_dumps(plan), sha256_text(confirmation) if confirmation else "", actor, plan["created_at"], plan["created_at"]),
    )
    db.execute("INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)", (case_id, "validation_plan_created", actor, json_dumps({"plan_id": plan_id, "level": level, "status": status}), utc_now()))
    db.audit("validation_plan_created", actor=actor, target=str(case["target"]), entity_type="validation_plan", entity_value=plan_id, details={"case_id": case_id, "level": level, "status": status})
    return plan


def approve_validation_plan(db: Database, plan_id: str, confirmation: str, *, actor: str = "analyst") -> dict[str, Any]:
    row = db.one("SELECT * FROM validation_plans WHERE plan_id=?", (plan_id,))
    if not row:
        raise ReconError(f"Validation plan not found: {plan_id}")
    if str(row["level"]) != "passive_live":
        raise ReconError("Only passive-live plans are executable in this release")
    if sha256_text(confirmation.strip()) != str(row["approval_phrase_hash"]):
        raise ReconError("Candidate-specific validation confirmation did not match")
    now = utc_now()
    db.execute("UPDATE validation_plans SET status='approved',approved_by=?,approved_at=?,updated_at=? WHERE plan_id=?", (actor, now, now, plan_id))
    db.execute("INSERT INTO validation_approvals(plan_id,actor,confirmation_hash,created_at) VALUES(?,?,?,?)", (plan_id, actor, sha256_text(confirmation.strip()), now))
    db.audit("validation_plan_approved", actor=actor, target=str(row["target"]), entity_type="validation_plan", entity_value=plan_id, details={"case_id": row["case_id"]})
    return {"ok": True, "plan_id": plan_id, "status": "approved", "approved_by": actor, "approved_at": now}


def _public_resolution(host: str) -> tuple[bool, list[str]]:
    addresses: list[str] = []
    try:
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            address = str(item[4][0])
            if address not in addresses:
                addresses.append(address)
    except socket.gaierror:
        return False, []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False, addresses
        if not ip.is_global:
            return False, addresses
    return bool(addresses), addresses


def _shape(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key)[:120]: _shape(item, depth + 1) for key, item in list(value.items())[:100]}
    if isinstance(value, list):
        return [_shape(value[0], depth + 1)] if value else []
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def _sensitive_key_names(value: Any, prefix: str = "", depth: int = 0) -> list[str]:
    if depth >= 4:
        return []
    results: list[str] = []
    if isinstance(value, dict):
        for key, item in list(value.items())[:100]:
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            if any(word in key_text.lower() for word in SENSITIVE_KEY_WORDS):
                results.append(path[:240])
            results.extend(_sensitive_key_names(item, path, depth + 1))
    elif isinstance(value, list) and value:
        results.extend(_sensitive_key_names(value[0], prefix + "[]", depth + 1))
    return sorted(set(results))[:100]


def _observation(method: str, url: str, status: int, headers: Any, body: bytes, error: str = "") -> dict[str, Any]:
    selected_headers = {}
    for key in ("Content-Type", "Cache-Control", "Vary", "Age", "ETag", "Location", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Allow", "Server"):
        value = headers.get(key) if headers is not None else None
        if value is not None:
            selected_headers[key.lower()] = str(value)[:1000]
    content_type = selected_headers.get("content-type", "")
    decoded: Any = None
    response_shape: Any = {}
    sensitive_keys: list[str] = []
    if body and ("json" in content_type.lower() or body.lstrip().startswith((b"{", b"["))):
        try:
            decoded = json.loads(body.decode("utf-8", "replace"))
            response_shape = _shape(decoded)
            sensitive_keys = _sensitive_key_names(decoded)
        except (ValueError, TypeError):
            response_shape = {"type": "unparsed_json_like"}
    sensitive_patterns = [name for name, pattern in SENSITIVE_PATTERNS.items() if pattern.search(body[:MAX_RESPONSE_BYTES])]
    return {
        "method": method,
        "url": url,
        "status_code": status,
        "headers": selected_headers,
        "content_type": content_type,
        "response_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
        "response_shape": response_shape,
        "shape_hash": sha256_text(json_dumps(response_shape)) if response_shape else "",
        "sensitive_key_names": sensitive_keys,
        "sensitive_pattern_categories": sensitive_patterns,
        "raw_body_stored": False,
        "error": error,
        "observed_at": utc_now(),
    }


def _perform_request_via_safe_transport(
    item: dict[str, Any],
    policy: TargetPolicy,
) -> tuple[dict[str, Any], str]:
    """Canonical core transport hook using the pinned Safe Transport boundary."""
    return perform_pinned_request(
        item,
        policy,
        safe_methods=SAFE_METHODS,
        url_safety=_url_safety,
        observation=_observation,
        max_response_bytes=MAX_RESPONSE_BYTES,
        validation_version=VALIDATION_VERSION,
    )


def _perform_request(
    item: dict[str, Any],
    policy: TargetPolicy,
) -> tuple[dict[str, Any], str]:
    return _perform_request_via_safe_transport(item, policy)


def _classify(primary_family: str, observations: list[dict[str, Any]]) -> tuple[str, list[str]]:
    family = primary_family.lower()
    reasons: list[str] = []
    statuses = [parse_int(row.get("status_code"), 0) for row in observations]
    sensitive = sorted({item for row in observations for item in row.get("sensitive_key_names", [])})
    patterns = sorted({item for row in observations for item in row.get("sensitive_pattern_categories", [])})
    if "cors" in family:
        permissive_reasons: list[str] = []
        explicit_other_origin = False
        successful_response = False
        for row in observations:
            status = parse_int(row.get("status_code"), 0)
            successful_response = successful_response or 200 <= status <= 399
            origin = str(row.get("headers", {}).get("access-control-allow-origin", "")).strip()
            credentials = str(row.get("headers", {}).get("access-control-allow-credentials", "")).strip().lower() == "true"
            if origin == "*":
                if credentials:
                    permissive_reasons.append(
                        "Wildcard ACAO and a credentials header were observed, but wildcard ACAO is not proof of a credentialed browser-readable response."
                    )
                else:
                    permissive_reasons.append(
                        "Wildcard ACAO was observed; this is policy surface and does not establish sensitive browser readability."
                    )
            elif origin == SAFE_ORIGIN:
                permissive_reasons.append(
                    "The controlled validation Origin was allowed by the response policy"
                    + (" with ACAC=true." if credentials else ".")
                )
            elif origin:
                explicit_other_origin = True
        if permissive_reasons:
            return "inconclusive", permissive_reasons + [
                "Safe Validation does not send credentials or execute a browser cross-origin read; confirmation requires stored controlled-origin/browser readability evidence."
            ]
        if explicit_other_origin or successful_response:
            return "weakened", [
                "The bounded response did not grant CORS access to the controlled validation Origin; this weakens but does not disprove other-origin misconfiguration."
            ]
        return "inconclusive", ["No decisive CORS policy behavior was observed in the bounded request."]
    if "redirect" in family:
        if any(row.get("redirect_outside_scope") for row in observations):
            return "strengthened", ["A redirect Location outside the authorized scope was observed without following it."]
        if any(row.get("headers", {}).get("location") for row in observations):
            return "inconclusive", ["A redirect was observed, but it remained in scope or lacked controllability evidence."]
        return "weakened", ["No redirect response was observed in the bounded request."]
    if "cache" in family:
        for row in observations:
            cache = str(row.get("headers", {}).get("cache-control", "")).lower()
            if ("public" in cache or "s-maxage" in cache) and sensitive:
                return "strengthened", ["A public/shared cache directive coincided with sensitive response-field names."]
            if "no-store" in cache or "private" in cache:
                reasons.append("Private/no-store cache directives were observed.")
        return ("weakened" if reasons else "inconclusive"), reasons or ["Cache directives were not conclusive."]
    if "source map" in family:
        if any(status == 200 and (str(row.get("url", "")).endswith(".map") or "json" in str(row.get("content_type", "")).lower()) for status, row in zip(statuses, observations)):
            return "strengthened", ["The source-map-like resource was reachable; contents were not retained."]
        if statuses and all(status in {403, 404, 410} for status in statuses if status):
            return "weakened", ["The source-map-like resource was unavailable in current observations."]
    if "authentication" in family or "session" in family:
        if any(status in {401, 403} for status in statuses):
            return "weakened", ["Anonymous access was denied in the observed context; object/role authorization remains unknown."]
        if any(status == 200 for status in statuses) and (sensitive or patterns):
            return "strengthened", ["Anonymous access returned a successful response with sensitive field or pattern categories."]
        if any(status == 200 for status in statuses):
            return "inconclusive", ["Anonymous access succeeded, but the redacted response metadata did not establish sensitive exposure."]
    if "information" in family or "excessive data" in family or "secret" in family:
        if sensitive or patterns:
            return "strengthened", [f"Sensitive metadata categories observed: {', '.join((sensitive + patterns)[:8])}."]
        if any(status == 200 for status in statuses):
            return "inconclusive", ["The endpoint responded, but no sensitive category was established from bounded redacted metadata."]
    if any(status in {401, 403, 404, 410} for status in statuses) and not any(status == 200 for status in statuses):
        return "weakened", ["The candidate endpoint was protected or unavailable in the current bounded observation."]
    return "inconclusive", ["The safe observation confirmed reachability or metadata but did not establish the security property."]


def _record_validation_evidence(db: Database, case_id: str, run_id: str, result: str, observations: list[dict[str, Any]]) -> int:
    _, candidates = _case(db, case_id)
    count = 0
    has_explicit_ownership = any(
        row.get("candidate_id") or row.get("candidate_ids")
        for row in observations
    )
    for candidate in candidates:
        candidate_id = str(candidate["candidate_id"])
        matched = [
            row
            for row in observations
            if candidate_id == str(row.get("candidate_id") or "")
            or candidate_id in {str(value) for value in row.get("candidate_ids", [])}
        ]
        # Backward compatibility for a single-candidate case only. Multi-candidate
        # cases must carry explicit ownership from plan/request provenance.
        if not matched and len(candidates) == 1 and not has_explicit_ownership:
            matched = list(observations)
        if not matched:
            continue

        explicit_results = {
            str(row.get("validation_result") or "")
            for row in matched
            if str(row.get("validation_result") or "")
        }
        if len(explicit_results) == 1:
            candidate_result = next(iter(explicit_results))
        elif any(row.get("method") or row.get("url") for row in matched):
            candidate_result, _ = _classify(str(candidate.get("bug_family") or ""), matched)
        else:
            candidate_result = result
        polarity = (
            "supports" if candidate_result == "strengthened"
            else "contradicts" if candidate_result == "weakened"
            else "unknown"
        )
        root = sha256_text(json_dumps({
            "run_id": run_id,
            "candidate_id": candidate_id,
            "observations": matched,
        }))
        evidence_id = "EVD-" + root[:16].upper()
        summary = (
            f"Candidate-scoped Safe Validation result {candidate_result}; "
            "raw response bodies were not stored."
        )
        now = utc_now()
        db.execute(
            "INSERT OR REPLACE INTO evidence_records(evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,summary,raw_reference,integrity_hash,first_seen,last_seen,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (evidence_id, candidate["analysis_id"], candidate["source_run_id"], candidate["target"], "safe_validation", polarity, "live_observation", "recon-monitor-safe-validation", run_id, "safe_validation", VALIDATION_VERSION, f"safe_validation:{run_id}:{candidate_id}", root, 85, 85, "direct", summary, f"validation_run:{run_id};candidate:{candidate_id}", root, now, now, now),
        )
        db.execute(
            "INSERT OR REPLACE INTO candidate_evidence_links(candidate_id,evidence_id,polarity,weight,relation,created_at) VALUES(?,?,?,?,?,?)",
            (candidate_id, evidence_id, polarity, 80, "safe_validation_result", now),
        )
        count += 1
    return count


def _offline_validate(db: Database, case_id: str) -> tuple[str, list[dict[str, Any]], list[str]]:
    _, candidates = _case(db, case_id)
    observations: list[dict[str, Any]] = []
    candidate_results: list[str] = []
    for candidate in candidates:
        roots: set[str] = set()
        direct = 0
        static_only = 0
        contradictions = 0
        rows = db.all(
            "SELECT e.root_fingerprint,e.directness,e.polarity,e.source_kind,e.integrity_hash,e.summary FROM candidate_evidence_links l JOIN evidence_records e ON e.evidence_id=l.evidence_id WHERE l.candidate_id=?",
            (candidate["candidate_id"],),
        )
        for row in rows:
            roots.add(str(row["root_fingerprint"]))
            direct += 1 if str(row["directness"]) == "direct" else 0
            static_only += 1 if str(row["source_kind"]) in {"javascript", "source_map", "static_inference"} else 0
            contradictions += 1 if str(row["polarity"]) == "contradicts" else 0
        if len(roots) >= 2 and direct >= 1 and contradictions == 0:
            candidate_result = "strengthened"
        elif roots and static_only >= max(1, len(roots)) and direct == 0:
            candidate_result = "weakened"
        else:
            candidate_result = "inconclusive"
        candidate_results.append(candidate_result)
        observations.append({
            "check": "evidence_lineage",
            "candidate_id": str(candidate["candidate_id"]),
            "candidate_ids": [str(candidate["candidate_id"])],
            "candidate_endpoint": str(candidate.get("endpoint") or ""),
            "validation_result": candidate_result,
            "independent_roots": len(roots),
            "direct_observations": direct,
            "static_only_observations": static_only,
            "contradictions": contradictions,
            "raw_body_stored": False,
        })
    if "strengthened" in candidate_results:
        return "strengthened", observations, ["At least one candidate has two independent roots, direct evidence and no contradiction; each evidence link remains candidate-scoped."]
    if candidate_results and all(value == "weakened" for value in candidate_results):
        return "weakened", observations, ["All candidate-scoped offline checks rely on static/inferred evidence without direct observation."]
    return "inconclusive", observations, ["Candidate-scoped offline provenance checks completed, but the evidence mix was not decisive."]



def _refresh_validation_intelligence(db: Database, run_id: str) -> None:
    """Persist explainable confidence and revalidation timestamps after a completed run.

    The import is local to keep the Safe Validation executor usable on older
    databases during migration and to avoid a hard module cycle. A failure in
    the intelligence layer must never invalidate or repeat the validation run.
    """
    try:
        from platform_v6 import validation_intelligence
        validation_intelligence(db, run_id, persist=True)
    except Exception as exc:
        db.audit(
            "validation_intelligence_refresh_failed",
            entity_type="validation_run",
            entity_value=run_id,
            details={"error": str(exc)[:1000]},
        )

def execute_validation_plan(paths: AppPaths, config: Config, db: Database, plan_id: str, *, allow_live: bool = False, actor: str = "analyst") -> dict[str, Any]:
    row = db.one("SELECT * FROM validation_plans WHERE plan_id=?", (plan_id,))
    if not row:
        raise ReconError(f"Validation plan not found: {plan_id}")
    plan = _loads(row["plan_json"], {})
    case_id = str(row["case_id"])
    level = str(row["level"])
    run_id = "SVR-" + uuid.uuid4().hex[:12].upper()
    now = utc_now()
    if level in {"controlled", "manual_only"}:
        result = "manual_only"
        db.execute("INSERT INTO validation_runs(run_id,plan_id,case_id,target,status,result,summary_json,started_at,finished_at,executed_by) VALUES(?,?,?,?,?,?,?,?,?,?)", (run_id, plan_id, case_id, row["target"], "completed", result, json_dumps({"reasons": plan.get("eligibility", {}).get("reasons", []), "network_requests": 0}), now, now, actor))
        db.execute("UPDATE security_cases SET validation_state=?,validation_summary=?,last_validation_at=?,updated_at=? WHERE case_id=?", (result, "Manual or controlled validation is required.", now, now, case_id))
        _refresh_validation_intelligence(db, run_id)
        return {"run_id": run_id, "plan_id": plan_id, "status": "completed", "result": result, "network_requests": 0}
    if level == "offline":
        result, observations, reasons = _offline_validate(db, case_id)
        evidence_links = _record_validation_evidence(db, case_id, run_id, result, observations)
        summary = {"result": result, "reasons": reasons, "observations": observations, "network_requests": 0, "evidence_links": evidence_links}
        db.execute("INSERT INTO validation_runs(run_id,plan_id,case_id,target,status,result,summary_json,started_at,finished_at,executed_by) VALUES(?,?,?,?,?,?,?,?,?,?)", (run_id, plan_id, case_id, row["target"], "completed", result, json_dumps(summary), now, utc_now(), actor))
        db.execute("UPDATE validation_plans SET status='completed',updated_at=? WHERE plan_id=?", (utc_now(), plan_id))
        db.execute("UPDATE security_cases SET validation_state=?,validation_summary=?,last_validation_at=?,updated_at=? WHERE case_id=?", (result, "; ".join(reasons), utc_now(), utc_now(), case_id))
        _refresh_validation_intelligence(db, run_id)
        return {"run_id": run_id, "plan_id": plan_id, "status": "completed", **summary}
    if level != "passive_live":
        raise ReconError(f"Unsupported validation level: {level}")
    if str(row["status"]) != "approved":
        raise ReconError("Passive-live plan requires candidate-specific approval")
    if not allow_live:
        raise ReconError("Live validation requires the explicit --allow-live gate")
    policy = _policy_for_target(paths, str(row["target"]))
    if policy is None:
        raise ReconError("No target policy matches this case")
    if not policy.active_allowed(config, True):
        raise ReconError("Global authorization, active-module enablement, and target active confirmation are all required")
    requests = list(plan.get("requests") or [])[:MAX_REQUESTS]
    if not requests:
        raise ReconError("Validation plan contains no executable safe request")
    db.execute("UPDATE validation_plans SET status='running',updated_at=? WHERE plan_id=?", (now, plan_id))
    db.execute("INSERT INTO validation_runs(run_id,plan_id,case_id,target,status,result,summary_json,started_at,executed_by) VALUES(?,?,?,?,?,'',?, ?,?)", (run_id, plan_id, case_id, row["target"], "running", "{}", now, actor))
    observations: list[dict[str, Any]] = []
    start = time.monotonic()
    failed_5xx = 0
    stopped = ""
    try:
        for index, item in enumerate(requests):
            if time.monotonic() - start > MAX_RUNTIME_SECONDS:
                stopped = "runtime_budget_exceeded"
                break
            observation, state = _perform_request(item, policy)
            observation["sequence"] = index + 1
            observation["candidate_ids"] = sorted({
                str(value) for value in item.get("candidate_ids", []) if str(value).strip()
            })
            observation["request_purpose"] = str(item.get("purpose") or "")
            observations.append(observation)
            db.execute("INSERT INTO validation_observations(run_id,sequence,method,url,status_code,observation_json,created_at) VALUES(?,?,?,?,?,?,?)", (run_id, index + 1, observation["method"], observation["url"], observation["status_code"], json_dumps(observation), utc_now()))
            status = parse_int(observation.get("status_code"), 0)
            if 500 <= status <= 599:
                failed_5xx += 1
            if state == "stopped_for_safety" or failed_5xx >= 2:
                stopped = observation.get("error") or "repeated_server_errors"
                break
            if index < len(requests) - 1:
                time.sleep(MIN_DELAY_SECONDS)
        if stopped:
            result = "stopped_for_safety"
            reasons = [f"Validation stopped: {stopped}."]
            status = "stopped_for_safety"
        else:
            case, _ = _case(db, case_id)
            result, reasons = _classify(str(case["primary_family"]), observations)
            status = "completed"
        evidence_links = _record_validation_evidence(db, case_id, run_id, result, observations)
        summary = {"result": result, "reasons": reasons, "observations": observations, "network_requests": len(observations), "evidence_links": evidence_links, "raw_bodies_stored": False}
        finished = utc_now()
        db.execute("UPDATE validation_runs SET status=?,result=?,summary_json=?,finished_at=? WHERE run_id=?", (status, result, json_dumps(summary), finished, run_id))
        db.execute("UPDATE validation_plans SET status=?,updated_at=? WHERE plan_id=?", (status, finished, plan_id))
        db.execute("UPDATE security_cases SET validation_state=?,validation_summary=?,last_validation_at=?,updated_at=? WHERE case_id=?", (result, "; ".join(reasons), finished, finished, case_id))
        db.execute("INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)", (case_id, "safe_validation_completed", actor, json_dumps({"plan_id": plan_id, "run_id": run_id, "result": result, "requests": len(observations)}), finished))
        db.audit("safe_validation_completed", actor=actor, target=str(row["target"]), entity_type="validation_run", entity_value=run_id, details={"case_id": case_id, "plan_id": plan_id, "result": result, "requests": len(observations), "raw_bodies_stored": False})
        _refresh_validation_intelligence(db, run_id)
        return {"run_id": run_id, "plan_id": plan_id, "status": status, **summary}
    except Exception as exc:
        finished = utc_now()
        db.execute("UPDATE validation_runs SET status='failed',result='inconclusive',summary_json=?,finished_at=? WHERE run_id=?", (json_dumps({"error": str(exc)[:1000], "observations": observations}), finished, run_id))
        db.execute("UPDATE validation_plans SET status='failed',updated_at=? WHERE plan_id=?", (finished, plan_id))
        raise


def validation_detail(db: Database, *, case_id: str = "", plan_id: str = "", limit: int = 100) -> dict[str, Any]:
    where = ""
    params: tuple[Any, ...] = ()
    if case_id:
        where = " WHERE case_id=?"; params = (case_id,)
    elif plan_id:
        where = " WHERE plan_id=?"; params = (plan_id,)
    plans = [dict(row) for row in db.all(f"SELECT * FROM validation_plans{where} ORDER BY created_at DESC LIMIT ?", (*params, max(1, min(500, limit))))]
    runs: list[dict[str, Any]] = []
    if case_id:
        runs = [dict(row) for row in db.all("SELECT * FROM validation_runs WHERE case_id=? ORDER BY started_at DESC LIMIT ?", (case_id, max(1, min(500, limit))))]
    elif plan_id:
        runs = [dict(row) for row in db.all("SELECT * FROM validation_runs WHERE plan_id=? ORDER BY started_at DESC LIMIT ?", (plan_id, max(1, min(500, limit))))]
    else:
        runs = [dict(row) for row in db.all("SELECT * FROM validation_runs ORDER BY started_at DESC LIMIT ?", (max(1, min(500, limit)),))]
    feedback = []
    if case_id:
        feedback = [dict(row) for row in db.all("SELECT * FROM validation_feedback WHERE case_id=? ORDER BY created_at DESC LIMIT ?", (case_id, max(1, min(500, limit))))]
    return {"version": VALIDATION_VERSION, "case_id": case_id, "plan_id": plan_id, "plans": plans, "runs": runs, "feedback": feedback}


def record_validation_feedback(db: Database, run_id: str, decision: str, reason: str, note: str = "", *, actor: str = "analyst") -> dict[str, Any]:
    if decision not in FEEDBACK_DECISIONS:
        raise ReconError(f"Invalid validation feedback decision: {decision}")
    if reason not in FEEDBACK_REASONS:
        raise ReconError(f"Invalid validation feedback reason: {reason}")
    run = db.one("SELECT * FROM validation_runs WHERE run_id=?", (run_id,))
    if not run:
        raise ReconError(f"Validation run not found: {run_id}")
    now = utc_now()
    db.execute("INSERT INTO validation_feedback(run_id,case_id,decision,reason_code,note,actor,created_at) VALUES(?,?,?,?,?,?,?)", (run_id, run["case_id"], decision, reason, note, actor, now))
    db.execute("INSERT INTO security_case_events(case_id,event_type,actor,details_json,created_at) VALUES(?,?,?,?,?)", (run["case_id"], "validation_feedback", actor, json_dumps({"run_id": run_id, "decision": decision, "reason": reason, "note": note}), now))
    db.audit("validation_feedback_recorded", actor=actor, target=str(run["target"]), entity_type="validation_run", entity_value=run_id, details={"decision": decision, "reason": reason})
    return {"ok": True, "run_id": run_id, "case_id": run["case_id"], "decision": decision, "reason": reason, "created_at": now}


def _store_imported_observation(db: Database, case_id: str, source_type: str, source_file: str, item: dict[str, Any], actor: str) -> str:
    case, candidates = _case(db, case_id)
    observation_id = "IMP-" + uuid.uuid4().hex[:12].upper()
    payload = {
        "method": str(item.get("method") or "GET")[:16],
        "url": str(item.get("url") or "")[:4000],
        "status_code": parse_int(item.get("status_code"), 0),
        "request_headers": dict(item.get("request_headers") or {}),
        "response_headers": dict(item.get("response_headers") or {}),
        "content_type": str(item.get("content_type") or "")[:500],
        "response_shape": item.get("response_shape") or {},
        "shape_hash": str(item.get("shape_hash") or ""),
        "body_sha256": str(item.get("body_sha256") or ""),
        "response_bytes": parse_int(item.get("response_bytes"), 0),
        "raw_body_stored": False,
    }
    db.execute("INSERT INTO imported_http_evidence(observation_id,case_id,target,source_type,source_file,observation_json,imported_by,created_at) VALUES(?,?,?,?,?,?,?,?)", (observation_id, case_id, case["target"], source_type, source_file, json_dumps(payload), actor, utc_now()))
    # Imported observations are neutral until an analyst supplies a decision.
    for candidate in candidates:
        root = sha256_text(json_dumps({"source_type": source_type, "source_file": source_file, "payload": payload, "candidate": candidate["candidate_id"]}))
        evidence_id = "EVD-" + root[:16].upper()
        now = utc_now()
        db.execute("INSERT OR REPLACE INTO evidence_records(evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,summary,raw_reference,integrity_hash,first_seen,last_seen,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (evidence_id, candidate["analysis_id"], candidate["source_run_id"], candidate["target"], "imported_http_observation", "unknown", "analyst_import", source_type, source_file, f"{source_type}_import", VALIDATION_VERSION, f"import:{observation_id}", root, 75, 75, "direct", "Redacted HTTP observation imported; raw request and response bodies were not retained.", f"imported_http:{observation_id}", root, now, now, now))
        db.execute("INSERT OR REPLACE INTO candidate_evidence_links(candidate_id,evidence_id,polarity,weight,relation,created_at) VALUES(?,?,?,?,?,?)", (candidate["candidate_id"], evidence_id, "unknown", 60, "analyst_import", now))
    return observation_id


def _headers_from_har(items: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(items, list):
        return result
    for item in items[:100]:
        if isinstance(item, dict) and item.get("name"):
            name = str(item["name"]).lower()
            if name in {"authorization", "cookie", "set-cookie", "proxy-authorization"}:
                result[name] = "<redacted>"
            else:
                result[name] = str(item.get("value") or "")[:1000]
    return result


def import_har(paths: AppPaths, db: Database, case_id: str, file_path: str | Path, *, actor: str = "analyst", limit: int = 500) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise ReconError(f"HAR file not found: {path}")
    if path.stat().st_size > 25 * 1024 * 1024:
        raise ReconError("HAR import is limited to 25 MB")
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    entries = (((data.get("log") or {}).get("entries")) if isinstance(data, dict) else None) or []
    imported = 0
    skipped = 0
    ids: list[str] = []
    case, _ = _case(db, case_id)
    policy = _policy_for_target(paths, str(case["target"]))
    for entry in entries[:max(1, min(5000, limit))]:
        if not isinstance(entry, dict):
            skipped += 1; continue
        request = entry.get("request") or {}; response = entry.get("response") or {}
        url = str(request.get("url") or "")
        if policy is None or not policy.url_in_scope(url):
            skipped += 1; continue
        content = response.get("content") or {}
        body = str(content.get("text") or "").encode("utf-8", "replace")[:MAX_RESPONSE_BYTES]
        if str(content.get("encoding") or "").lower() == "base64":
            try: body = base64.b64decode(body, validate=False)[:MAX_RESPONSE_BYTES]
            except Exception: body = b""
        observation = _observation(str(request.get("method") or "GET"), url, parse_int(response.get("status"), 0), {str(k): str(v) for k, v in _headers_from_har(response.get("headers")).items()}, body)
        observation["request_headers"] = _headers_from_har(request.get("headers"))
        observation["response_headers"] = observation.pop("headers")
        ids.append(_store_imported_observation(db, case_id, "har", path.name, observation, actor)); imported += 1
    db.audit("har_imported", actor=actor, target=str(case["target"]), entity_type="case", entity_value=case_id, details={"file": path.name, "imported": imported, "skipped": skipped, "raw_bodies_stored": False})
    return {"case_id": case_id, "source": "har", "file": path.name, "imported": imported, "skipped": skipped, "observation_ids": ids[:100], "raw_bodies_stored": False}


def _parse_http_message(raw: bytes) -> tuple[dict[str, str], bytes]:
    separator = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    head, _, body = raw.partition(separator)
    lines = head.decode("iso-8859-1", "replace").splitlines()
    headers: dict[str, str] = {}
    for line in lines[1:100]:
        if ":" not in line: continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        headers[key] = "<redacted>" if key in {"authorization", "cookie", "set-cookie", "proxy-authorization"} else value.strip()[:1000]
    return headers, body[:MAX_RESPONSE_BYTES]


def import_burp_xml(paths: AppPaths, db: Database, case_id: str, file_path: str | Path, *, actor: str = "analyst", limit: int = 500) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise ReconError(f"Burp XML file not found: {path}")
    if path.stat().st_size > 25 * 1024 * 1024:
        raise ReconError("Burp XML import is limited to 25 MB")
    raw_xml = path.read_bytes()
    if b"<!DOCTYPE" in raw_xml.upper() or b"<!ENTITY" in raw_xml.upper():
        raise ReconError("DTD/entity declarations are not allowed in Burp XML imports")
    root = ET.fromstring(raw_xml)
    case, _ = _case(db, case_id)
    policy = _policy_for_target(paths, str(case["target"]))
    imported = 0; skipped = 0; ids: list[str] = []
    for item in list(root.findall(".//item"))[:max(1, min(5000, limit))]:
        url = (item.findtext("url") or "").strip()
        if policy is None or not policy.url_in_scope(url):
            skipped += 1; continue
        method = (item.findtext("method") or "GET").strip().upper()
        status = parse_int(item.findtext("status"), 0)
        request_node = item.find("request"); response_node = item.find("response")
        request_raw = b""; response_raw = b""
        if request_node is not None and request_node.text:
            request_raw = base64.b64decode(request_node.text) if request_node.attrib.get("base64", "false").lower() == "true" else request_node.text.encode("iso-8859-1", "replace")
        if response_node is not None and response_node.text:
            response_raw = base64.b64decode(response_node.text) if response_node.attrib.get("base64", "false").lower() == "true" else response_node.text.encode("iso-8859-1", "replace")
        request_headers, _ = _parse_http_message(request_raw)
        response_headers, response_body = _parse_http_message(response_raw)
        observation = _observation(method, url, status, response_headers, response_body)
        observation["request_headers"] = request_headers
        observation["response_headers"] = observation.pop("headers")
        ids.append(_store_imported_observation(db, case_id, "burp_xml", path.name, observation, actor)); imported += 1
    db.audit("burp_xml_imported", actor=actor, target=str(case["target"]), entity_type="case", entity_value=case_id, details={"file": path.name, "imported": imported, "skipped": skipped, "raw_bodies_stored": False})
    return {"case_id": case_id, "source": "burp_xml", "file": path.name, "imported": imported, "skipped": skipped, "observation_ids": ids[:100], "raw_bodies_stored": False}
