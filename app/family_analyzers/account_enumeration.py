from __future__ import annotations

"""Dedicated Account Enumeration analyzer.

This analyzer distinguishes identity/authentication lookup surfaces from stored
evidence that controlled test identities produce a material response or stable
timing discrepancy. Standards and public pattern references guide methodology
only; they never create target evidence or satisfy admission/confirmation.
"""

import json
import re
from typing import Any, Iterable, Mapping

from core import Database, parse_int
from family_reasoning import FAMILY_REASONING, confirmation_gaps

from .base import FamilyAnalyzer, FamilyAnalyzerContext


ACCOUNT_ENUMERATION_FAMILY_ANALYZER_VERSION = "1.0.0"
ACCOUNT_ENUMERATION_FAMILY_ANALYZER_RULE_VERSION = "2026.08.11.1"

IDENTITY_FIELDS = {
    "username", "user_name", "email", "email_address", "phone", "phone_number",
    "account", "account_id", "login", "identifier", "identity", "user",
}
ENUMERATION_MARKERS = (
    "login", "signin", "sign-in", "forgot", "reset", "recover", "recovery",
    "register", "signup", "sign-up", "check-email", "check_email", "username",
    "email", "account", "user", "identity", "lookup",
)
GENERIC_MESSAGE_MARKERS = (
    "invalid credentials", "invalid username or password", "unable to process",
    "if an account exists", "if your account exists", "check your email",
    "request received", "invalid login",
)
RATE_LIMIT_STATUSES = {429}

ACCOUNT_ENUMERATION_TAXONOMY = {
    "owasp": ["A07:2021 Identification and Authentication Failures"],
    "wstg": ["WSTG-IDNT-04"],
    "cwe": ["CWE-204", "CWE-208"],
    "related_cwe": ["CWE-203"],
}

ACCOUNT_ENUMERATION_METHOD = (
    {
        "id": "ENUM-01-identity-surface",
        "basis": ["WSTG-IDNT-04", "CWE-204"],
        "principle": "Identify login, recovery, registration or identity-lookup operations that accept a user/account identifier; the route or field name alone is only attack-surface evidence.",
    },
    {
        "id": "ENUM-02-controlled-comparison",
        "basis": ["WSTG-IDNT-04"],
        "principle": "Compare only explicitly controlled test identities, including a known-existing test identity and a deliberately non-existing test identifier; never infer direct evidence from real-user probing.",
    },
    {
        "id": "ENUM-03-response-normalization",
        "basis": ["CWE-204", "CWE-203"],
        "principle": "Normalize status, response shape and semantic message class before deciding whether responses materially disclose identity existence; cosmetic text or volatile metadata should not count.",
    },
    {
        "id": "ENUM-04-timing-stability",
        "basis": ["CWE-208", "WSTG-IDNT-04"],
        "principle": "Treat timing as direct evidence only when repeated controlled samples show a stable material difference and rate limiting or transport noise is not the likely explanation.",
    },
    {
        "id": "ENUM-05-behavioral-decision",
        "basis": ["CWE-204", "CWE-208"],
        "principle": "Confirmation evidence is a material response or stable timing differential between controlled existing/non-existing test identities, not merely an identity lookup surface.",
    },
    {
        "id": "ENUM-06-confounder-review",
        "basis": ["WSTG-IDNT-04", "CWE-203"],
        "principle": "Explicitly check generic responses, uniform timing, rate limiting, CAPTCHA/challenge state, localization and transient backend errors before promotion or confirmation.",
    },
)

ACCOUNT_ENUMERATION_FALSE_POSITIVE_CHECKS = (
    "A login, recovery, registration or username/email field is only an enumeration surface; it is not evidence that account existence is disclosed.",
    "Different request IDs, timestamps, CSRF tokens or other volatile fields must not be treated as an identity response differential.",
    "A generic message such as 'if an account exists' can intentionally hide identity existence even when backend behavior differs internally.",
    "HTTP 429, CAPTCHA, challenge escalation or retry-after behavior can create response/timing differences unrelated to identity existence.",
    "A single slow response is network noise, not a timing side channel; repeated controlled samples are required for inferred timing evidence.",
    "Localization, A/B testing and frontend-only wording differences should not be treated as server-side account enumeration without a material semantic distinction.",
    "Only identities explicitly marked as controlled test identities may satisfy direct comparison evidence; real-user probing is outside this analyzer's evidence contract.",
)

ACCOUNT_ENUMERATION_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-idnt-04-response-pattern",
        "source": "OWASP WSTG",
        "ref": "WSTG-IDNT-04 / Account Enumeration",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
        "principle": "Different authentication or recovery responses for existing versus non-existing identities can disclose valid accounts.",
        "signals": ["identity_response_differential"],
    },
    {
        "id": "cwe-208-account-timing-pattern",
        "source": "MITRE CWE",
        "ref": "CWE-208 / Observable Timing Discrepancy",
        "url": "https://cwe.mitre.org/data/definitions/208.html",
        "principle": "Stable timing differences can disclose whether an account or internal authentication state exists, but repeated observations are required to separate the signal from noise.",
        "signals": ["identity_timing_differential"],
    },
)


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "controlled", "test", "uniform", "same", "generic", "stable"}:
        return True
    if text in {"false", "0", "no", "different", "variable", "unstable"}:
        return False
    return None


def _scalar(item: Mapping[str, Any], keys: Iterable[str]) -> Any:
    normalized = {_normalize(key): value for key, value in item.items()}
    for key in keys:
        value = normalized.get(_normalize(key))
        if value is not None and str(value).strip() != "":
            return value
    return None


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _status(item: Mapping[str, Any]) -> int:
    value = _scalar(item, ("status_code", "status", "http_status"))
    response = item.get("response")
    if value is None and isinstance(response, Mapping):
        value = _scalar(response, ("status_code", "status", "http_status"))
    return parse_int(value, 0)


def _identity_class(item: Mapping[str, Any]) -> str:
    value = _normalize(_scalar(item, ("identity_class", "identity_state", "account_state", "existence", "kind", "class")))
    if value in {"existing", "exists", "valid", "known_existing", "registered", "present"}:
        return "existing"
    if value in {"nonexisting", "non_existing", "not_found", "missing", "invalid", "unknown", "unregistered", "absent"}:
        return "nonexisting"
    exists = _bool(_scalar(item, ("account_exists", "identity_exists", "exists")))
    if exists is True:
        return "existing"
    if exists is False:
        return "nonexisting"
    return ""


def _is_controlled(item: Mapping[str, Any]) -> bool:
    for key in ("controlled_identity", "test_identity", "owned_identity", "identity_controlled", "controlled"):
        if key in item and _bool(item.get(key)) is True:
            return True
    return False


def _observations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in (
        "identity_observations", "enumeration_observations", "account_observations",
        "identity_comparisons", "enumeration_comparisons",
    ):
        raw = details.get(key)
        decoded = _loads(raw, raw)
        if isinstance(decoded, list):
            return [dict(item) for item in decoded if isinstance(item, Mapping)]
        if isinstance(decoded, Mapping):
            result: list[dict[str, Any]] = []
            for label, value in decoded.items():
                if isinstance(value, Mapping):
                    item = dict(value)
                    item.setdefault("identity_class", str(label))
                else:
                    item = {"identity_class": str(label), "result": value}
                result.append(item)
            return result
    return []


def _add_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    identity = (
        str(item.get("type") or ""),
        str(item.get("source_group") or item.get("source") or ""),
        str(item.get("text") or ""),
    )
    for existing in items:
        other = (
            str(existing.get("type") or ""),
            str(existing.get("source_group") or existing.get("source") or ""),
            str(existing.get("text") or ""),
        )
        if other == identity:
            return
    items.append(item)


def _normalized_shape(item: Mapping[str, Any]) -> str:
    explicit = _scalar(item, ("response_shape", "shape", "schema", "response_schema", "body_shape"))
    if explicit is not None:
        if isinstance(explicit, Mapping):
            return json.dumps(sorted(str(key) for key in explicit.keys()))
        if isinstance(explicit, (list, tuple, set)):
            return json.dumps(sorted(str(value) for value in explicit))
        return _normalize(explicit)
    response = item.get("response")
    if isinstance(response, Mapping):
        return json.dumps(sorted(str(key) for key in response.keys() if _normalize(key) not in {"request_id", "trace_id", "timestamp", "csrf", "token"}))
    return ""


def _message_class(item: Mapping[str, Any]) -> str:
    explicit = _scalar(item, ("message_class", "response_class", "error_class", "semantic_class", "message"))
    if explicit is None:
        response = item.get("response")
        if isinstance(response, Mapping):
            explicit = _scalar(response, ("message_class", "response_class", "error_class", "message", "error"))
    text = str(explicit or "").strip().lower()
    if not text:
        return ""
    for marker in GENERIC_MESSAGE_MARKERS:
        if marker in text:
            return "generic_identity_response"
    return _normalize(text)[:160]


def _timing_ms(item: Mapping[str, Any]) -> float | None:
    return _float(_scalar(item, ("median_ms", "median_timing_ms", "elapsed_ms", "timing_ms", "response_time_ms", "duration_ms")))


def _sample_count(item: Mapping[str, Any]) -> int:
    return parse_int(_scalar(item, ("sample_count", "samples", "timing_samples", "count")), 0)


def _rate_limited(item: Mapping[str, Any]) -> bool:
    if _status(item) in RATE_LIMIT_STATUSES:
        return True
    for key in ("rate_limited", "rate_limit_triggered", "captcha", "challenge", "retry_after"):
        value = item.get(key)
        if key == "retry_after" and value not in (None, "", 0, "0"):
            return True
        if key != "retry_after" and _bool(value) is True:
            return True
    return False


def _structural_evidence(
    *,
    endpoint: str,
    body_fields: list[str],
    query_fields: list[str],
    semantic_text: str,
    details: Mapping[str, Any],
) -> list[dict[str, Any]]:
    fields = [str(value) for value in body_fields + query_fields]
    identity_fields = [value for value in fields if _normalize(value) in {_normalize(field) for field in IDENTITY_FIELDS}]
    text = " ".join([endpoint, semantic_text, " ".join(fields), json.dumps(details, sort_keys=True, default=str)]).lower()
    markers = [marker for marker in ENUMERATION_MARKERS if marker in text]
    if not identity_fields and not markers:
        return []

    support: list[dict[str, Any]] = []
    if identity_fields:
        _add_unique(support, {
            "type": "identity_lookup",
            "source": "endpoint_schema",
            "source_group": "identity_input",
            "weight": 20,
            "text": f"Client-visible identity input observed: {', '.join(identity_fields[:6])}.",
        })
    elif any(marker in text for marker in ("lookup", "check-email", "check_email", "username", "email", "account")):
        _add_unique(support, {
            "type": "identity_lookup",
            "source": "semantic",
            "source_group": "identity_input",
            "weight": 14,
            "text": "Endpoint semantics indicate an identity/account lookup surface.",
        })

    if markers:
        _add_unique(support, {
            "type": "authentication_surface",
            "source": "identity_surface",
            "source_group": "identity_operation",
            "weight": 14,
            "text": f"Identity/authentication surface markers observed: {', '.join(markers[:7])}.",
        })
    _add_unique(support, {
        "type": "client_operation",
        "source": "endpoint_contract",
        "source_group": "identity_operation",
        "weight": 9,
        "text": "The identity lookup is tied to a concrete client-visible endpoint operation.",
    })
    return support


def _explicit_behavior(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False
    controlled = _bool(details.get("test_identities_controlled") if "test_identities_controlled" in details else details.get("controlled_test_identities")) is True

    if controlled and _bool(details.get("identity_response_differential")) is True:
        _add_unique(support, {
            "type": "identity_response_differential",
            "source": "stored_identity_comparison",
            "source_group": "identity_response",
            "weight": 38,
            "text": "Stored controlled-test comparison explicitly records a material response differential between existing and non-existing test identities.",
        })
        direct = True
    if controlled and _bool(details.get("identity_timing_differential")) is True and _bool(details.get("rate_limit_confounded")) is not True:
        _add_unique(support, {
            "type": "identity_timing_differential",
            "source": "stored_identity_comparison",
            "source_group": "identity_timing",
            "weight": 34,
            "text": "Stored controlled-test comparison explicitly records a stable timing differential between existing and non-existing test identities.",
        })
        direct = True

    if _bool(details.get("uniform_identity_response")) is True or _bool(details.get("generic_identity_response")) is True:
        _add_unique(contradict, {
            "type": "uniform_identity_response",
            "source": "stored_identity_comparison",
            "source_group": "identity_response",
            "weight": -30,
            "text": "Stored comparison records uniform/generic responses across controlled identity-existence states.",
        })
    if _bool(details.get("uniform_identity_timing")) is True:
        _add_unique(contradict, {
            "type": "uniform_identity_timing",
            "source": "stored_identity_comparison",
            "source_group": "identity_timing",
            "weight": -28,
            "text": "Stored comparison records materially uniform timing across controlled identity-existence states.",
        })
    if _bool(details.get("rate_limit_confounded")) is True or _bool(details.get("rate_limited")) is True:
        _add_unique(contradict, {
            "type": "rate_limit_confounded",
            "source": "stored_identity_comparison",
            "source_group": "enumeration_confounder",
            "weight": -24,
            "text": "Rate limiting/challenge behavior is recorded and may explain the observed response or timing difference.",
        })
    return support, contradict, direct


def _paired_behavior(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False

    observations = [item for item in _observations(details) if _is_controlled(item)]
    existing = next((item for item in observations if _identity_class(item) == "existing"), None)
    missing = next((item for item in observations if _identity_class(item) == "nonexisting"), None)
    if not existing or not missing:
        return support, contradict, direct

    existing_rate = _rate_limited(existing)
    missing_rate = _rate_limited(missing)
    if existing_rate or missing_rate:
        _add_unique(contradict, {
            "type": "rate_limit_confounded",
            "source": "controlled_identity_observation",
            "source_group": "enumeration_confounder",
            "weight": -24,
            "text": "At least one controlled identity observation hit rate limiting or challenge behavior, so response/timing differences are confounded.",
        })

    status_existing, status_missing = _status(existing), _status(missing)
    shape_existing, shape_missing = _normalized_shape(existing), _normalized_shape(missing)
    message_existing, message_missing = _message_class(existing), _message_class(missing)

    response_reasons: list[str] = []
    if status_existing and status_missing and status_existing != status_missing:
        response_reasons.append(f"status {status_existing} vs {status_missing}")
    if shape_existing and shape_missing and shape_existing != shape_missing:
        response_reasons.append("response shape")
    if message_existing and message_missing and message_existing != message_missing:
        response_reasons.append("semantic message class")

    both_generic = message_existing == message_missing == "generic_identity_response"
    explicit_uniform = _bool(_scalar(existing, ("uniform_response", "generic_response"))) is True and _bool(_scalar(missing, ("uniform_response", "generic_response"))) is True
    if (both_generic or explicit_uniform) and not response_reasons:
        _add_unique(contradict, {
            "type": "uniform_identity_response",
            "source": "controlled_identity_observation",
            "source_group": "identity_response",
            "weight": -30,
            "text": "Controlled existing/non-existing test identities produced the same generic response semantics.",
        })
    elif response_reasons and not (existing_rate or missing_rate):
        _add_unique(support, {
            "type": "identity_response_differential",
            "source": "controlled_identity_observation",
            "source_group": "identity_response",
            "weight": 38,
            "text": "Controlled existing/non-existing test identities produced a material response differential: " + ", ".join(response_reasons) + ".",
        })
        direct = True
    elif not response_reasons and (status_existing or shape_existing or message_existing):
        _add_unique(contradict, {
            "type": "uniform_identity_response",
            "source": "controlled_identity_observation",
            "source_group": "identity_response",
            "weight": -28,
            "text": "Controlled existing/non-existing test identities produced materially uniform status/shape/message observations.",
        })

    timing_existing, timing_missing = _timing_ms(existing), _timing_ms(missing)
    samples_existing, samples_missing = _sample_count(existing), _sample_count(missing)
    if timing_existing is not None and timing_missing is not None:
        slow = max(timing_existing, timing_missing)
        fast = max(1.0, min(timing_existing, timing_missing))
        delta = abs(timing_existing - timing_missing)
        ratio = slow / fast
        stable = samples_existing >= 3 and samples_missing >= 3 and delta >= 150.0 and ratio >= 1.5
        if stable and not (existing_rate or missing_rate):
            _add_unique(support, {
                "type": "identity_timing_differential",
                "source": "controlled_identity_observation",
                "source_group": "identity_timing",
                "weight": 34,
                "text": f"Repeated controlled samples show a stable timing differential ({timing_existing:.1f} ms vs {timing_missing:.1f} ms; {samples_existing}/{samples_missing} samples).",
            })
            direct = True
        elif samples_existing >= 3 and samples_missing >= 3 and delta < 75.0:
            _add_unique(contradict, {
                "type": "uniform_identity_timing",
                "source": "controlled_identity_observation",
                "source_group": "identity_timing",
                "weight": -24,
                "text": "Repeated controlled samples show materially uniform response timing across identity-existence states.",
            })

    return support, contradict, direct


def _matched_writeups(observed: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for doc in ACCOUNT_ENUMERATION_WRITEUP_PATTERNS:
        overlap = sorted(observed & {str(signal) for signal in doc.get("signals", [])})
        if not overlap:
            continue
        matches.append({
            "id": str(doc.get("id") or ""),
            "source": str(doc.get("source") or ""),
            "ref": str(doc.get("ref") or ""),
            "url": str(doc.get("url") or ""),
            "principle": str(doc.get("principle") or ""),
            "matched_signals": overlap,
            "non_evidentiary": True,
        })
    return matches


def _triggered_false_positive_checks(contradictions: set[str]) -> list[dict[str, str]]:
    mapping = {
        "uniform_identity_response": "Uniform/generic response semantics are recorded; do not infer account existence from cosmetic or volatile differences.",
        "uniform_identity_timing": "Repeated timing is materially uniform; do not treat isolated latency variance as enumeration evidence.",
        "rate_limit_confounded": "Rate limiting or challenge behavior can create both response and timing differences; collect clean controlled observations before concluding enumeration.",
    }
    return [
        {"signal": signal, "check": mapping[signal]}
        for signal in sorted(contradictions)
        if signal in mapping
    ]


class AccountEnumerationFamilyAnalyzer(FamilyAnalyzer):
    family = "account_enumeration"
    analyzer_version = ACCOUNT_ENUMERATION_FAMILY_ANALYZER_VERSION

    def analyze(
        self,
        context: FamilyAnalyzerContext,
        *,
        body_fields: list[str],
        query_fields: list[str],
        semantic_text: str = "",
        **_: Any,
    ) -> dict[str, Any] | None:
        structural = _structural_evidence(
            endpoint=context.endpoint,
            body_fields=body_fields,
            query_fields=query_fields,
            semantic_text=semantic_text,
            details=context.details,
        )
        explicit_support, explicit_contradict, explicit_direct = _explicit_behavior(context.details)
        paired_support, paired_contradict, paired_direct = _paired_behavior(context.details)
        support = [*structural, *explicit_support, *paired_support]
        contradict = [*explicit_contradict, *paired_contradict]
        observed = {str(item.get("type") or "") for item in support}

        if "identity_lookup" not in observed:
            return None
        if not ({"authentication_surface", "client_operation"} & observed):
            return None

        direct = bool(explicit_direct or paired_direct)
        contradiction_types = {str(item.get("type") or "") for item in contradict}
        confirmation_missing = confirmation_gaps(self.family, observed)
        policy = FAMILY_REASONING[self.family]
        writeups = _matched_writeups(observed)

        if "identity_response_differential" in observed:
            variant = "identity_response_differential"
            summary = "Stored controlled-test evidence indicates a material response difference between existing and non-existing test identities that may disclose account existence."
            base = 40
        elif "identity_timing_differential" in observed:
            variant = "identity_timing_differential"
            summary = "Repeated controlled-test observations indicate a stable timing difference between existing and non-existing test identities that may disclose account existence."
            base = 36
        else:
            variant = "identity_lookup_surface"
            summary = "A client-visible identity lookup surface exists, but no stored controlled-test response or stable timing differential establishes account enumeration."
            base = 18

        if contradict and not direct:
            base = max(8, base - min(12, len(contradict) * 4))

        missing = list(policy.get("next_evidence", ()))
        if confirmation_missing:
            missing = list(dict.fromkeys([*missing, *[f"Confirmation evidence: {' / '.join(group)}" for group in confirmation_missing]]))

        return {
            "family": self.family,
            "variant": variant,
            "base": base,
            "support": support,
            "contradict": contradict,
            "missing": missing,
            "rule_ids": [
                "account-enumeration-identity-surface",
                "account-enumeration-controlled-comparison",
                "account-enumeration-response-normalization",
                "account-enumeration-timing-stability",
            ],
            "summary": summary,
            "direct": direct,
            "family_analyzer": {
                **self.metadata(),
                "rule_version": ACCOUNT_ENUMERATION_FAMILY_ANALYZER_RULE_VERSION,
                "taxonomy": dict(ACCOUNT_ENUMERATION_TAXONOMY),
                "methodology": [dict(step) for step in ACCOUNT_ENUMERATION_METHOD],
                "writeup_patterns": writeups,
                "false_positive_checks": list(ACCOUNT_ENUMERATION_FALSE_POSITIVE_CHECKS),
                "triggered_false_positive_checks": _triggered_false_positive_checks(contradiction_types),
                "promotion_required": [sorted(group) for group in policy["promotion_required"]],
                "confirmation_required": [sorted(group) for group in policy["confirmation_required"]],
                "confirmation_missing": confirmation_missing,
                "confirmation_ready_from_stored_target_evidence": not confirmation_missing,
                "next_evidence": list(policy.get("next_evidence", ())),
                "validation_level": str(policy.get("validation_level") or "passive_live"),
                "knowledge_sources_matched": len(writeups),
                "knowledge_does_not_change_target_evidence": True,
                "controlled_test_identity_requirement": True,
                "timing_inference_min_samples_per_class": 3,
                "timing_inference_min_delta_ms": 150,
                "timing_inference_min_ratio": 1.5,
                "confounders": ["authentication_session", "rate_limiting", "localization", "ab_testing"],
            },
        }


def analyze_account_enumeration_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str,
    body_fields: list[str],
    query_fields: list[str],
    details: Mapping[str, Any],
    business_context: str = "general",
    semantic_text: str = "",
) -> dict[str, Any] | None:
    context = FamilyAnalyzerContext(
        db=db,
        analysis_id=analysis_id,
        target=target,
        endpoint=endpoint,
        method=method,
        details=details,
        business_context=business_context,
    )
    return AccountEnumerationFamilyAnalyzer().analyze(
        context,
        body_fields=body_fields,
        query_fields=query_fields,
        semantic_text=semantic_text,
    )


__all__ = [
    "ACCOUNT_ENUMERATION_FAMILY_ANALYZER_VERSION",
    "ACCOUNT_ENUMERATION_FAMILY_ANALYZER_RULE_VERSION",
    "ACCOUNT_ENUMERATION_TAXONOMY",
    "ACCOUNT_ENUMERATION_METHOD",
    "AccountEnumerationFamilyAnalyzer",
    "analyze_account_enumeration_signal",
]
