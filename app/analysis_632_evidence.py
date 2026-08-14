from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from hypothesis_admission import FAMILY_ADMISSION_POLICIES


def _detector_specs():
    # Lazy import avoids package __init__ -> execution -> reconstruction cycle.
    from family_detectors.registry import DETECTOR_SPECS
    return DETECTOR_SPECS

ENGINE_VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.32.1"

# This layer turns explicit stored facts into the canonical family vocabulary.
# It never calls a target, generates payloads, or treats OWASP/WSTG/CWE/write-up
# text as target evidence. Standards and write-ups define the vocabulary and
# proof shape; only stored target/source observations can satisfy it.

_EXTERNAL_KNOWLEDGE_KEYS = {
    "owasp", "wstg", "cwe", "mitre", "writeup", "writeups", "standards",
    "knowledge", "knowledge_references", "external_knowledge", "reference_only",
}

_ASSERTION_WORDS = {
    "accepted", "allowed", "bypass", "bypassed", "exposed", "exposure",
    "observed", "reached", "returned", "executed", "execution", "success",
    "successful", "succeeded", "missing", "absent", "without", "unrestricted",
    "unauthorized", "improper", "failed", "failure", "vulnerable", "unsafe",
    "enabled", "reachable", "leaked", "logged", "disclosed", "differ", "differs",
    "different", "distinguish", "inferred", "mismatch", "cross", "outside",
}

_SECURE_CONTROL_WORDS = {
    "blocked", "denied", "rejected", "fixed", "patched", "unaffected", "enforced",
    "validated", "verified", "isolated", "capped", "limited", "disabled", "sanitized",
    "escaped", "allowlisted", "private", "no-store", "no_store", "rollback",
}

_TOKEN_ALIASES: dict[str, set[str]] = {
    "account": {"account", "user", "identity", "username", "login"},
    "existence": {"existence", "exists", "existing", "known", "unknown", "present", "absent"},
    "differential": {"differential", "difference", "different", "distinguish", "infer", "inferred", "mismatch", "variance"},
    "authentication": {"authentication", "auth", "login", "session", "credential", "ntlm", "scram", "sso", "oauth"},
    "authorization": {"authorization", "authorize", "authorisation", "permission", "rbac", "access"},
    "boundary": {"boundary", "scope", "role", "tenant", "ownership", "privilege"},
    "regression": {"regression", "bypass", "improper", "weakened", "failed", "failure"},
    "privileged": {"privileged", "admin", "administrator", "superuser", "management", "protected"},
    "function": {"function", "operation", "mutation", "action", "endpoint", "route"},
    "object": {"object", "record", "resource", "service", "item", "entity"},
    "tenant": {"tenant", "enterprise", "organization", "organisation", "workspace", "account"},
    "property": {"property", "field", "attribute", "role", "status", "owner"},
    "workflow": {"workflow", "flow", "state", "transition", "process", "pipeline"},
    "invariant": {"invariant", "rule", "constraint", "single-use", "single_use", "duplicate", "repeat"},
    "command": {"command", "shell", "process", "os", "operating-system", "exec", "execution"},
    "process": {"process", "command", "shell", "exec", "execution"},
    "cors": {"cors", "cross-origin", "cross_origin", "origin"},
    "authenticated": {"authenticated", "credentialed", "session", "authorization", "cookie"},
    "crypto": {"crypto", "cryptographic", "cipher", "tls", "ssl", "random", "secret"},
    "randomness": {"randomness", "random", "predictable", "entropy", "nonce"},
    "runtime": {"runtime", "browser", "javascript", "dom", "executed", "execution"},
    "exception": {"exception", "error", "crash", "panic", "fault"},
    "upload": {"upload", "file", "attachment", "multipart", "extension"},
    "dangerous": {"dangerous", "executable", "active", "script", "php", "html", "svg"},
    "graphql": {"graphql", "resolver", "query", "mutation", "field"},
    "data": {"data", "field", "response", "value", "record", "content"},
    "deprecated": {"deprecated", "legacy", "old", "retired", "version"},
    "reachable": {"reachable", "active", "available", "responds", "success", "200"},
    "disclosure": {"disclosure", "exposure", "leak", "returned", "response", "visible"},
    "ldap": {"ldap", "directory", "filter", "dn", "search"},
    "nosql": {"nosql", "mongo", "mongodb", "document", "operator"},
    "sql": {"sql", "database", "query", "select", "where"},
    "template": {"template", "jinja", "twig", "render", "expression"},
    "redirect": {"redirect", "location", "navigation", "return", "callback"},
    "path": {"path", "filename", "directory", "archive", "zip", "filesystem"},
    "escape": {"escape", "outside", "traversal", "parent", "base", "directory"},
    "message": {"message", "postmessage", "post_message", "event.data", "iframe"},
    "origin": {"origin", "source-window", "source_window", "window", "iframe"},
    "atomicity": {"atomicity", "concurrent", "parallel", "simultaneous", "race", "duplicate"},
    "credential": {"credential", "token", "secret", "password", "key", "api-key", "api_key"},
    "logging": {"logging", "log", "trace", "telemetry", "audit"},
    "alerting": {"alerting", "alert", "alarm", "notification", "monitoring"},
    "debug": {"debug", "diagnostic", "trace", "stack", "development"},
    "business": {"business", "purchase", "invite", "reservation", "redeem", "signup", "checkout"},
    "frequency": {"frequency", "repeat", "repeated", "rate", "limit", "multiple", "twice"},
    "cache": {"cache", "cached", "caching", "cdn", "shared"},
    "integrity": {"integrity", "signature", "verification", "verify", "checksum", "authenticity"},
    "component": {"component", "dependency", "package", "library", "module", "artifact"},
    "source": {"source", "sourcemap", "source-map", "source_map", "mapping"},
    "fetch": {"fetch", "request", "http", "outbound", "backend", "remote", "webhook"},
    "resource": {"resource", "batch", "queue", "memory", "cpu", "cost", "size", "limit"},
    "third": {"third", "third-party", "third_party", "vendor", "upstream", "external"},
    "websocket": {"websocket", "web-socket", "ws", "wss", "socket", "channel", "subscription"},
}

# High-value, standards/write-up-derived phrases. These are generic proof patterns,
# never source names or benchmark IDs. A match is still only accepted from stored
# target/source facts.
_SIGNAL_HINTS: dict[str, tuple[str, ...]] = {
    "account_existence_differential": (
        "account existence can be inferred", "user existence can be inferred", "known user differs",
        "known versus unknown user", "iteration count difference", "distinguish account existence",
    ),
    "authentication_boundary_regression": (
        "authentication bypass", "improper authentication", "authenticated user privileges",
        "privilege context can be reached", "authentication check failed",
    ),
    "authorization_response_differential": (
        "lower privilege success", "non-admin access", "unauthorized access succeeded",
        "role boundary failure", "permission check missing",
    ),
    "cross_tenant_object_access": (
        "cross tenant access", "other tenant data", "other enterprise data", "tenant boundary bypass",
        "different tenant object returned",
    ),
    "cross_identity_object_access": (
        "other user object", "other account object", "different identity object", "cross account access",
    ),
    "workflow_invariant_violation": (
        "workflow invariant violation", "invalid workflow accepted", "state transition accepted",
        "untrusted code in privileged workflow", "single-use operation repeated",
    ),
    "process_execution_reached": (
        "arbitrary command execution", "operating system command execution", "os command execution",
        "shell command executed", "process execution reached",
    ),
    "authenticated_context": (
        "authenticated response", "credentialed request", "session cookie", "authorization header",
    ),
    "credentials_allowed": (
        "allow credentials", "credentials true", "credentialed cross origin",
    ),
    "predictable_randomness_observed": (
        "predictable randomness", "weak random", "deterministic random", "guessable nonce",
    ),
    "weak_crypto_algorithm_observed": (
        "weak cipher", "weak algorithm", "md5 used", "sha1 used", "insecure cryptography",
    ),
    "runtime_reachable_flow": (
        "user controlled data reaches", "attacker controlled data reaches", "runtime flow reaches",
        "dom sink reached", "browser sink reached",
    ),
    "unhandled_exception_observed": (
        "unhandled exception", "uncaught exception", "exception crashed", "panic occurred",
    ),
    "dangerous_type_accepted": (
        "dangerous upload accepted", "executable upload accepted", "script upload accepted",
        "extension filter absent", "unsafe file type accepted",
    ),
    "active_content_served": (
        "uploaded active content served", "uploaded script served", "uploaded html served",
    ),
    "resolver_authorization_failure": (
        "resolver authorization failed", "graphql authorization bypass", "graphql role boundary failure",
    ),
    "unauthorized_data_response": (
        "unauthorized data returned", "sensitive data returned without authorization",
        "full authority state returned", "data outside field policy returned",
    ),
    "deprecated_version_still_reachable": (
        "deprecated version reachable", "legacy api still active", "retired endpoint active",
        "old api version responds",
    ),
    "ldap_auth_bypass_observed": (
        "ldap authentication bypass", "ldap filter changed authentication", "ldap filter injection succeeded",
    ),
    "privileged_property_accepted": (
        "privileged property accepted", "role field accepted", "admin property persisted",
        "server authoritative property writable",
    ),
    "nosql_auth_bypass_observed": (
        "nosql authentication bypass", "mongo operator bypass", "query operator changed authentication",
    ),
    "allowlist_bypass": (
        "redirect allowlist bypass", "destination allowlist bypass", "external redirect accepted",
    ),
    "external_destination": (
        "external destination accepted", "external location returned", "redirects to external",
    ),
    "path_escape_observed": (
        "path escaped base", "outside destination root", "directory traversal succeeded",
        "archive entry escaped", "wrote outside destination",
    ),
    "message_schema_unvalidated": (
        "message schema not validated", "message content not validated", "postmessage content unchecked",
    ),
    "missing_origin_check": (
        "origin not checked", "missing origin check", "postmessage origin unchecked",
    ),
    "missing_source_window_check": (
        "source window not checked", "message source not checked", "iframe source unchecked",
    ),
    "atomicity_failure": (
        "atomicity failure", "race condition succeeded", "concurrent operations both succeeded",
        "duplicate concurrent success", "double spend",
    ),
    "credential_context": (
        "authentication token", "credential material", "api key", "secret used for authentication",
    ),
    "non_placeholder_secret": (
        "hard coded token", "hardcoded token", "real credential", "production secret",
    ),
    "sensitive_data_logged": (
        "password logged", "secret logged", "credential logged", "plaintext password in trace",
    ),
    "alerting_absent_observed": (
        "no alert generated", "alerting absent", "security event not alerted",
    ),
    "debug_mode_exposed": (
        "debug mode exposed", "debug mode enabled", "production debug enabled",
    ),
    "unsafe_default_configuration": (
        "unsafe default configuration", "insecure default", "default configuration is insecure",
    ),
    "workflow_frequency_unrestricted": (
        "workflow can be repeated", "same invitation accepted twice", "frequency unrestricted",
        "repeat operation unrestricted",
    ),
    "per_user_limit_absent": (
        "per user limit absent", "no per-user limit", "user limit missing",
    ),
    "browser_cache_no_store_missing": (
        "no-store missing", "cache-control no-store missing", "authenticated response cacheable",
    ),
    "server_template_execution": (
        "server template executed", "template expression evaluated", "server side expression evaluated",
    ),
    "integrity_check_missing": (
        "integrity check missing", "signature verification missing", "download without signature verification",
    ),
    "known_vulnerable_component_observed": (
        "known vulnerable component", "malicious dependency version", "vulnerable dependency deployed",
    ),
    "privileged_pipeline_executes_untrusted_code": (
        "privileged pipeline executes untrusted code", "pull_request_target checks out untrusted code",
    ),
    "direct_reachability": (
        "directly reachable", "publicly reachable", "source map reachable", "reachable source map",
    ),
    "boolean_response_differential": (
        "boolean response differential", "true false response differs", "sql boolean difference",
    ),
    "database_error_observed": (
        "database error observed", "sql error returned", "database syntax error",
    ),
    "server_fetch_observed": (
        "server performed request", "backend request observed", "server fetch observed",
        "outbound request observed", "requests.get called",
    ),
    "backend_fetch": (
        "backend fetch", "server side fetch", "server-side request",
    ),
    "batch_limit_absent_observed": (
        "batch limit absent", "unbounded batch", "queue resize denial of service", "no batch limit",
    ),
    "rate_limit_absent_observed": (
        "rate limit absent", "no rate limit", "unlimited requests",
    ),
    "third_party_auth_weak": (
        "third party authentication weak", "upstream authentication weak", "external api authentication weak",
    ),
    "unsafe_upstream_data_reaches_sink": (
        "untrusted upstream data reaches sink", "third party response reaches sink",
    ),
    "unauthorized_subscription": (
        "unauthorized websocket subscription", "subscribe without authorization", "unauthenticated channel subscription",
    ),
    "channel_authorization_failure": (
        "websocket authorization failure", "channel authorization missing", "hardware command without authentication",
    ),
}


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _words(value: Any) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", str(value or "").lower()) if token}


def _semantic_tokens(token: str) -> set[str]:
    token = token.lower().strip()
    aliases = set(_TOKEN_ALIASES.get(token, set()))
    aliases.add(token)
    if token.endswith("s") and len(token) > 4:
        aliases.add(token[:-1])
    if token.endswith("ed") and len(token) > 4:
        aliases.add(token[:-2])
    if token.endswith("ing") and len(token) > 5:
        aliases.add(token[:-3])
    if token in {"differential", "difference", "different"}:
        aliases.update(_TOKEN_ALIASES["differential"])
    if token in {"auth", "authenticated", "authentication"}:
        aliases.update(_TOKEN_ALIASES["authentication"])
    return aliases


def _flatten_facts(value: Any, *, path: tuple[str, ...] = (), depth: int = 0) -> list[tuple[str, Any]]:
    if depth > 7:
        return []
    rows: list[tuple[str, Any]] = []
    if isinstance(value, Mapping):
        for key, child in list(value.items())[:500]:
            nk = _norm(key)
            if nk in _EXTERNAL_KNOWLEDGE_KEYS:
                continue
            child_path = (*path, nk)
            if isinstance(child, (Mapping, list, tuple)):
                rows.extend(_flatten_facts(child, path=child_path, depth=depth + 1))
            else:
                rows.append((".".join(child_path), child))
    elif isinstance(value, (list, tuple)):
        for child in list(value)[:300]:
            if isinstance(child, (Mapping, list, tuple)):
                rows.extend(_flatten_facts(child, path=path, depth=depth + 1))
            else:
                rows.append((".".join(path), child))
    return rows


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, (int, float)) and value == 1:
        return True
    return str(value or "").strip().lower() in {
        "true", "yes", "1", "observed", "present", "accepted", "enabled", "reachable", "success", "succeeded"
    }


def _falsey(value: Any) -> bool:
    if value is False:
        return True
    if isinstance(value, (int, float)) and value == 0:
        return True
    return str(value or "").strip().lower() in {
        "false", "no", "0", "absent", "missing", "disabled", "rejected", "denied", "blocked"
    }


def _fact_text(path: str, value: Any) -> str:
    text = f"{path.replace('.', ' ')} {value}".replace("_", " ")
    return re.sub(r"\s+", " ", text).strip().lower()


def _phrase_hit(signal: str, text: str) -> bool:
    normalized = re.sub(r"\s+", " ", text.lower())
    return any(phrase in normalized for phrase in _SIGNAL_HINTS.get(signal, ()))


def _semantic_match(signal: str, text: str, *, condition: bool) -> float:
    signal_tokens = [
        token for token in _norm(signal).split("_")
        if token not in {"observed", "response", "surface", "semantic", "direct", "data"}
    ]
    if not signal_tokens:
        return 0.0
    text_words = _words(text)
    hits = 0
    for token in signal_tokens:
        aliases = set()
        for alias in _semantic_tokens(token):
            aliases.update(_words(alias.replace("_", " ")))
        if aliases & text_words:
            hits += 1
    ratio = hits / len(signal_tokens)
    if _phrase_hit(signal, text):
        ratio = max(ratio, 1.0)
    if condition and ratio < 1.0:
        assertive = bool(text_words & _ASSERTION_WORDS)
        if not assertive:
            return 0.0
    return ratio


def _looks_secure_control(text: str) -> bool:
    words = _words(text)
    return bool(words & _SECURE_CONTROL_WORDS)


def _emit(packet: dict[str, list[dict[str, Any]]], family: str, signal: str, text: str, *, role: str, path: str) -> None:
    spec = _detector_specs()[family]
    allowed = spec.identity_signals | spec.condition_signals | spec.blocking_controls
    if signal not in allowed:
        return
    side = "contradict" if role == "control" else "support"
    source_group = "stored_observation"
    item = {
        "type": signal,
        "source": "stored_assertion",
        "source_group": source_group,
        "weight": 36 if role == "condition" else (-28 if role == "control" else 14),
        "text": text[:1200],
        "artifact": path[:500],
        "direct": True,
        "observation_quality": 92 if role == "condition" else 84,
        "family_scope": family,
        "signal_role": role,
        "counts_for_family": role in {"identity", "condition", "control"},
        "analysis_632_reconstruction": True,
        "analysis_632_engine_version": ENGINE_VERSION,
        "analysis_632_rule_version": RULE_VERSION,
        "analysis_632_basis": "explicit_stored_fact_semantic_reconstruction",
        "execution_engine_version": "1.4.0",
        "execution_rule_version": "2026.08.13.6.30",
        "execution_family": family,
        "execution_strategy": "analysis_632_stored_assertion_bridge",
        "execution_basis": "passive_stored_assertion",
        "execution_passive_only": True,
    }
    key = (item["type"], item["source_group"], item["text"], side)
    if any((row.get("type"), row.get("source_group"), row.get("text"), side) == key for row in packet[side]):
        return
    packet[side].append(item)


def _identity_context(target: str, endpoint: str, category: str, business_context: str, facts: Iterable[tuple[str, Any]]) -> str:
    parts = [target, endpoint, category, business_context]
    for path, value in facts:
        parts.append(path.replace("_", " "))
        if isinstance(value, (str, int, float, bool)):
            parts.append(str(value))
    return re.sub(r"\s+", " ", " ".join(parts)).lower()[:100000]


def reconstruct_asserted_evidence(
    *,
    target: str,
    endpoint: str,
    method: str,
    endpoint_schema: Mapping[str, Any] | None,
    details: Mapping[str, Any] | None,
    category: str = "",
    business_context: str = "general",
) -> dict[str, dict[str, Any]]:
    """Reconstruct canonical family signals from explicit stored facts.

    This is a post-6.31 bridge between literal/passive observations and the
    family admission vocabulary. It deliberately refuses to infer a condition
    from a route name or generic keyword alone. Identity may be reconstructed
    from the broader stored context; decisive conditions require an explicit
    fact/phrase and are emitted as one direct observation root.
    """
    del method, endpoint_schema  # Reserved for future typed evidence adapters.
    details = dict(details or {})
    facts = _flatten_facts(details)
    context_text = _identity_context(target, endpoint, category, business_context, facts)
    result: dict[str, dict[str, Any]] = {}

    for family, spec in _detector_specs().items():
        packet = {"support": [], "contradict": []}
        policy = FAMILY_ADMISSION_POLICIES[family]
        identity_signals = set(spec.identity_signals)
        condition_signals = set(spec.condition_signals)
        control_signals = set(spec.blocking_controls)

        # Analysis 6.32 intentionally does not infer family identity from broad
        # narrative context. Existing physical detectors own surface identity.
        # Only an explicit stored boolean/key matching a canonical identity
        # signal may add identity evidence here.
        for path, value in facts:
            leaf = _norm(path.split(".")[-1])
            if not _truthy(value):
                continue
            for signal in sorted(identity_signals):
                if leaf == _norm(signal):
                    _emit(packet, family, signal, f"Stored fact explicitly asserts family identity signal {signal}.", role="identity", path=path)

        # Conditions and controls must come from an explicit fact. A generic
        # endpoint/category token can never create a decisive condition.
        for path, value in facts:
            text = _fact_text(path, value)
            if not text:
                continue
            for signal in sorted(condition_signals):
                key_match = _semantic_match(signal, path.replace("_", " "), condition=True)
                text_match = _semantic_match(signal, text, condition=True)
                leaf = _norm(path.split(".")[-1])
                explicit_boolean = _truthy(value) and (leaf == _norm(signal) or key_match >= 0.90)
                if explicit_boolean or text_match >= 0.82 or _phrase_hit(signal, text):
                    # Secure/fixed wording must not be converted into a positive
                    # condition unless the signal itself expresses a missing or
                    # failed control and the stored fact explicitly asserts it.
                    if _looks_secure_control(text) and not any(token in signal for token in ("missing", "absent", "failure", "bypass", "unrestricted", "weak", "unsafe")):
                        continue
                    _emit(packet, family, signal, f"Stored fact supports decisive condition {signal}: {text}", role="condition", path=path)

            for signal in sorted(control_signals):
                leaf = _norm(path.split(".")[-1])
                text_match = _semantic_match(signal, text, condition=False)
                explicit_control = _truthy(value) and leaf == _norm(signal)
                # A false-valued control flag (for example signature_verified=false)
                # is evidence that the control is absent, never proof that it exists.
                secure_narrative = (not _falsey(value)) and _looks_secure_control(text) and text_match >= 0.95
                if explicit_control or secure_narrative:
                    _emit(packet, family, signal, f"Stored fact supports blocking control {signal}: {text}", role="control", path=path)

        if packet["support"] or packet["contradict"]:
            result[family] = packet

    return result
