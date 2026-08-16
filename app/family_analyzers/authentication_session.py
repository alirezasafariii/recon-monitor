from __future__ import annotations

"""Dedicated Authentication / Session lifecycle analyzer.

The analyzer separates authentication/session surface discovery from evidence that
an intended authentication state transition, token lifecycle rule, recovery
verification rule, logout invalidation rule or expiration boundary actually
failed. Standards and public write-up patterns guide reasoning only; they never
become target evidence and never satisfy admission or confirmation.
"""

import json
import re
from typing import Any, Iterable, Mapping

from core import Database, parse_int
from family_reasoning import FAMILY_REASONING, confirmation_gaps

from .base import FamilyAnalyzer, FamilyAnalyzerContext


AUTH_SESSION_FAMILY_ANALYZER_VERSION = "1.0.0"
AUTH_SESSION_FAMILY_ANALYZER_RULE_VERSION = "2026.08.11.1"

SUCCESS_STATUSES = set(range(200, 300))
DENY_STATUSES = {400, 401, 403, 404, 409, 410, 422}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

AUTH_MARKERS = (
    "login", "signin", "sign-in", "logout", "signout", "sign-out", "session",
    "token", "refresh", "oauth", "saml", "sso", "password", "reset", "forgot",
    "recover", "recovery", "otp", "mfa", "2fa", "webauthn", "passkey",
)
AUTH_FIELDS = {
    "token", "access_token", "refresh_token", "id_token", "session", "session_id",
    "password", "otp", "code", "state", "assertion", "saml_response",
}
LIFECYCLE_STATE_MARKERS = {
    "login", "signin", "logout", "signout", "refresh", "reset", "recover",
    "recovery", "session", "token", "oauth", "saml", "sso",
}

AUTH_SESSION_TAXONOMY = {
    "owasp": ["A07:2021 Identification and Authentication Failures"],
    "wstg": ["WSTG-ATHN-04", "WSTG-SESS-01"],
    "cwe": ["CWE-287"],
    "related_cwe": ["CWE-613", "CWE-384", "CWE-640"],
}

AUTH_SESSION_METHOD = (
    {
        "id": "AUTH-01-state-machine",
        "basis": ["CWE-287", "WSTG-ATHN-04"],
        "principle": "Model the intended anonymous, authenticated, recovery, refresh, logout and expired states before interpreting any response as an authentication failure.",
    },
    {
        "id": "AUTH-02-session-lifecycle",
        "basis": ["WSTG-SESS-01", "CWE-613"],
        "principle": "Track session/token issuance, binding, rotation, invalidation and expiration using only stored target observations; token presence alone is not a weakness.",
    },
    {
        "id": "AUTH-03-boundary-comparison",
        "basis": ["WSTG-ATHN-04", "CWE-287"],
        "principle": "Prefer like-for-like comparisons where the expected authentication state is explicit and the observed state or access decision can be compared safely.",
    },
    {
        "id": "AUTH-04-recovery-verification",
        "basis": ["CWE-640", "CWE-287"],
        "principle": "Treat recovery as an authentication boundary of its own; require evidence that a verification step was expected yet bypassed before raising recovery-bypass evidence.",
    },
    {
        "id": "AUTH-05-behavioral-decision",
        "basis": ["CWE-287", "WSTG-SESS-01"],
        "principle": "Decisive evidence requires an actual lifecycle violation such as session reuse after logout, missing expected rotation, recovery bypass or a documented authentication-state violation.",
    },
    {
        "id": "AUTH-06-contradiction-check",
        "basis": ["WSTG-SESS-01", "WSTG-ATHN-04"],
        "principle": "Look for observed rotation, enforced recovery verification and rejection of expired sessions before promotion or confirmation; a 2xx response or auth-looking route is never enough.",
    },
)

AUTH_SESSION_FALSE_POSITIVE_CHECKS = (
    "An authentication-looking endpoint is only surface discovery; route names and client-side token handling do not prove a server-side weakness.",
    "A token that remains textually identical may be intentionally reusable unless rotation is explicitly required for the observed transition.",
    "A 2xx response may describe login/recovery UI or validation without creating an authenticated session.",
    "Logout may invalidate the server-side session even if a client retains a stale token string.",
    "Recovery may use an alternate verification factor not visible in the current client observation.",
    "An expired or logged-out session that is rejected is evidence of enforcement, not a weakness.",
    "Account enumeration, BFLA and secret exposure are neighboring families and should not be mislabeled as authentication/session failures.",
)

AUTH_SESSION_WRITEUP_PATTERNS = (
    {
        "id": "ghsl-ruby-saml-2024-329-330",
        "source": "GitHub Security Lab",
        "ref": "GHSL-2024-329 / GHSL-2024-330 / ruby-saml",
        "url": "https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/",
        "principle": "Authentication bypass requires a demonstrated trust or lifecycle validation failure that changes authenticated identity/state; parser or protocol surface alone is non-evidentiary.",
        "signals": ["authentication_state_violation"],
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
    if text in {"true", "1", "yes", "allow", "allowed", "accepted", "success", "succeeded", "valid", "authenticated", "granted"}:
        return True
    if text in {"false", "0", "no", "deny", "denied", "rejected", "blocked", "invalid", "unauthenticated", "expired"}:
        return False
    return None


def _status(item: Mapping[str, Any]) -> int:
    value = item.get("status_code")
    response = item.get("response")
    if value is None and isinstance(response, Mapping):
        value = response.get("status_code")
    return parse_int(value, 0)


def _scalar(item: Mapping[str, Any], keys: Iterable[str]) -> Any:
    normalized = {_normalize(key): value for key, value in item.items()}
    for key in keys:
        value = normalized.get(_normalize(key))
        if value is not None and str(value).strip() != "":
            return value
    return None


def _observations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in (
        "auth_observations",
        "authentication_observations",
        "session_observations",
        "lifecycle_observations",
        "state_observations",
    ):
        raw = details.get(key)
        decoded = _loads(raw, raw)
        if isinstance(decoded, Mapping):
            result: list[dict[str, Any]] = []
            for label, value in decoded.items():
                if isinstance(value, Mapping):
                    item = dict(value)
                    item.setdefault("context", str(label))
                else:
                    item = {"context": str(label), "result": value}
                result.append(item)
            return result
        if isinstance(decoded, list):
            return [dict(item) for item in decoded if isinstance(item, Mapping)]
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


def _surface_terms(
    endpoint: str,
    body_fields: list[str],
    query_fields: list[str],
    auth_hints: list[str],
    semantic_text: str,
    details: Mapping[str, Any],
) -> tuple[list[str], list[str]]:
    text = " ".join(
        [
            endpoint,
            semantic_text,
            " ".join(body_fields + query_fields + auth_hints),
            json.dumps(details, sort_keys=True, default=str),
        ]
    ).lower()
    markers = [marker for marker in AUTH_MARKERS if marker in text]
    normalized_auth_fields = {_normalize(value) for value in AUTH_FIELDS}
    fields = [
        field
        for field in body_fields + query_fields
        if _normalize(field) in normalized_auth_fields
    ]
    return list(dict.fromkeys(markers)), list(dict.fromkeys(fields))


def _structural_evidence(
    *,
    endpoint: str,
    method: str,
    body_fields: list[str],
    query_fields: list[str],
    auth_hints: list[str],
    semantic_text: str,
    details: Mapping[str, Any],
) -> list[dict[str, Any]]:
    markers, fields = _surface_terms(endpoint, body_fields, query_fields, auth_hints, semantic_text, details)
    if not markers and not fields:
        return []

    support: list[dict[str, Any]] = []
    surface_text = ", ".join((markers + fields)[:8])
    _add_unique(support, {
        "type": "authentication_surface",
        "source": "auth_surface",
        "source_group": "authentication_surface",
        "weight": 18,
        "text": f"Client-visible authentication/session lifecycle surface observed: {surface_text}.",
    })
    _add_unique(support, {
        "type": "client_operation",
        "source": "endpoint_contract",
        "source_group": "authentication_operation",
        "weight": 10,
        "text": "The authentication/session behavior is tied to a concrete client-visible endpoint operation.",
    })

    normalized_markers = {_normalize(value) for value in markers}
    if method.upper() in STATE_CHANGING_METHODS and normalized_markers & LIFECYCLE_STATE_MARKERS:
        _add_unique(support, {
            "type": "state_change",
            "source": "method",
            "source_group": "authentication_transition",
            "weight": 10,
            "text": f"The authentication/session lifecycle uses state-changing method {method.upper()}.",
        })

    explicit_boundary = _bool(
        details.get("authentication_required")
        if "authentication_required" in details
        else details.get("auth_required")
    )
    if auth_hints or explicit_boundary is not None:
        _add_unique(support, {
            "type": "auth_boundary",
            "source": "stored_auth_contract" if explicit_boundary is not None else "endpoint_schema",
            "source_group": "authentication_boundary",
            "weight": 12,
            "text": "Stored endpoint context exposes an authentication boundary or authentication mechanism for this operation.",
        })
    return support


def _top_level_behavior(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False

    direct_flags = {
        "session_reuse_after_logout": ("session_reuse_after_logout", "logout_invalidation", 38, "Stored target evidence explicitly records successful session reuse after logout."),
        "token_not_rotated": ("token_not_rotated", "session_rotation", 32, "Stored target evidence explicitly records that a token/session identifier did not rotate across a transition where rotation was required."),
        "recovery_bypass": ("recovery_bypass", "recovery_verification", 38, "Stored target evidence explicitly records recovery completion without the required verification step."),
        "authentication_state_violation": ("authentication_state_violation", "authentication_boundary", 40, "Stored target evidence explicitly records an authentication state/access decision that violated the expected boundary."),
    }
    for key, (signal, group, weight, text) in direct_flags.items():
        if _bool(details.get(key)) is True:
            _add_unique(support, {
                "type": signal,
                "source": "stored_auth_result",
                "source_group": group,
                "weight": weight,
                "text": text,
            })
            direct = True

    contradiction_flags = {
        "session_rotation_observed": ("session_rotation_observed", "session_rotation", -28, "Stored target evidence records session/token rotation across the relevant transition."),
        "recovery_verification_enforced": ("recovery_verification_enforced", "recovery_verification", -30, "Stored target evidence records enforcement of the required recovery verification step."),
        "expired_session_rejected": ("expired_session_rejected", "session_expiration", -30, "Stored target evidence records that an expired session/token was rejected."),
    }
    for key, (signal, group, weight, text) in contradiction_flags.items():
        if _bool(details.get(key)) is True:
            _add_unique(contradict, {
                "type": signal,
                "source": "stored_auth_result",
                "source_group": group,
                "weight": weight,
                "text": text,
            })

    token_rotated = _bool(details.get("token_rotated") if "token_rotated" in details else details.get("session_rotated"))
    if token_rotated is True:
        _add_unique(contradict, {
            "type": "session_rotation_observed",
            "source": "stored_auth_result",
            "source_group": "session_rotation",
            "weight": -28,
            "text": "Stored target evidence explicitly records token/session rotation.",
        })

    recovery_enforced = _bool(
        details.get("verification_enforced")
        if "verification_enforced" in details
        else details.get("recovery_verification_required_and_enforced")
    )
    if recovery_enforced is True:
        _add_unique(contradict, {
            "type": "recovery_verification_enforced",
            "source": "stored_auth_result",
            "source_group": "recovery_verification",
            "weight": -30,
            "text": "Stored target evidence explicitly records recovery verification enforcement.",
        })

    return support, contradict, direct


def _observation_behavior(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    direct = False

    for index, observation in enumerate(_observations(details)):
        label = str(
            _scalar(observation, ("context", "phase", "state", "name", "transition"))
            or f"auth-context-{index + 1}"
        )
        label_norm = _normalize(label)
        status = _status(observation)
        success = status in SUCCESS_STATUSES if status else False
        denied = status in DENY_STATUSES if status else False

        expected_access = _bool(_scalar(observation, ("expected_access", "should_allow", "expected_authorized", "access_expected")))
        actual_access = _bool(_scalar(observation, ("access_granted", "authorized", "request_allowed", "resource_access")))
        expected_authenticated = _bool(_scalar(observation, ("expected_authenticated", "should_be_authenticated", "authentication_expected")))
        actual_authenticated = _bool(_scalar(observation, ("authenticated", "session_authenticated", "identity_authenticated")))

        if actual_access is None and status:
            actual_access = success if success else False if denied else None

        after_logout = "logout" in label_norm or "signed_out" in label_norm or "post_logout" in label_norm
        expired = _bool(_scalar(observation, ("expired", "session_expired", "token_expired", "expiration_reached")))

        if after_logout and expected_access is False and actual_access is True:
            _add_unique(support, {
                "type": "session_reuse_after_logout",
                "source": "stored_auth_context",
                "source_group": "logout_invalidation",
                "weight": 40,
                "text": f"Stored context {label!r} expected access to be denied after logout, but access remained granted.",
            })
            direct = True

        state_violation = (
            (expected_authenticated is False and actual_authenticated is True)
            or (expected_access is False and actual_access is True and not after_logout)
            or (expired is True and actual_access is True)
        )
        if state_violation:
            _add_unique(support, {
                "type": "authentication_state_violation",
                "source": "stored_auth_context",
                "source_group": "authentication_boundary",
                "weight": 38,
                "text": f"Stored context {label!r} records an authenticated/access-granted state where the expected authentication boundary required denial.",
            })
            direct = True

        rotation_expected = _bool(_scalar(observation, ("rotation_expected", "token_rotation_expected", "session_rotation_expected", "should_rotate")))
        token_before = _scalar(observation, ("token_before", "session_before", "session_id_before", "credential_before"))
        token_after = _scalar(observation, ("token_after", "session_after", "session_id_after", "credential_after"))
        if rotation_expected is True and token_before is not None and token_after is not None:
            if str(token_before) == str(token_after):
                _add_unique(support, {
                    "type": "token_not_rotated",
                    "source": "stored_auth_context",
                    "source_group": "session_rotation",
                    "weight": 34,
                    "text": f"Stored context {label!r} required token/session rotation, but the recorded identifier remained unchanged.",
                })
                direct = True
            else:
                _add_unique(contradict, {
                    "type": "session_rotation_observed",
                    "source": "stored_auth_context",
                    "source_group": "session_rotation",
                    "weight": -28,
                    "text": f"Stored context {label!r} records token/session rotation across the transition.",
                })

        recovery_required = _bool(_scalar(observation, ("recovery_verification_required", "verification_required", "factor_required")))
        verification_passed = _bool(_scalar(observation, ("verification_passed", "factor_verified", "recovery_verified")))
        recovery_completed = _bool(_scalar(observation, ("recovery_completed", "password_reset_completed", "account_recovered", "recovery_success")))
        verification_enforced = _bool(_scalar(observation, ("verification_enforced", "recovery_verification_enforced")))
        recovery_context = "recover" in label_norm or "reset" in label_norm or recovery_required is not None

        if recovery_context and recovery_required is True and verification_passed is False and recovery_completed is True:
            _add_unique(support, {
                "type": "recovery_bypass",
                "source": "stored_auth_context",
                "source_group": "recovery_verification",
                "weight": 40,
                "text": f"Stored context {label!r} records successful recovery even though a required verification factor was not passed.",
            })
            direct = True
        if recovery_context and verification_enforced is True:
            _add_unique(contradict, {
                "type": "recovery_verification_enforced",
                "source": "stored_auth_context",
                "source_group": "recovery_verification",
                "weight": -30,
                "text": f"Stored context {label!r} records enforcement of the recovery verification step.",
            })

        if expired is True and (actual_access is False or denied):
            _add_unique(contradict, {
                "type": "expired_session_rejected",
                "source": "stored_auth_context",
                "source_group": "session_expiration",
                "weight": -30,
                "text": f"Stored context {label!r} records rejection of an expired session/token.",
            })

    return support, contradict, direct


def _behavioral_evidence(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    support1, contradict1, direct1 = _top_level_behavior(details)
    support2, contradict2, direct2 = _observation_behavior(details)
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    for item in [*support1, *support2]:
        _add_unique(support, item)
    for item in [*contradict1, *contradict2]:
        _add_unique(contradict, item)
    return support, contradict, bool(direct1 or direct2)


def _matched_writeups(observed: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for doc in AUTH_SESSION_WRITEUP_PATTERNS:
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
        "session_rotation_observed": "Rotation is observed for the relevant transition; require independent evidence of a different lifecycle failure before treating the surface as vulnerable.",
        "recovery_verification_enforced": "Recovery verification is enforced in stored target evidence; do not infer bypass from the existence of a recovery endpoint or alternate client flow.",
        "expired_session_rejected": "Expired session/token rejection is recorded; this supports expiration enforcement rather than an authentication/session weakness.",
    }
    return [
        {"signal": signal, "check": mapping[signal]}
        for signal in sorted(contradictions)
        if signal in mapping
    ]


class AuthenticationSessionFamilyAnalyzer(FamilyAnalyzer):
    family = "authentication_session"
    analyzer_version = AUTH_SESSION_FAMILY_ANALYZER_VERSION

    def analyze(
        self,
        context: FamilyAnalyzerContext,
        *,
        body_fields: list[str],
        query_fields: list[str],
        auth_hints: list[str],
        semantic_text: str = "",
        **_: Any,
    ) -> dict[str, Any] | None:
        method = str(context.method or "UNKNOWN").upper()
        structural = _structural_evidence(
            endpoint=context.endpoint,
            method=method,
            body_fields=body_fields,
            query_fields=query_fields,
            auth_hints=auth_hints,
            semantic_text=semantic_text,
            details=context.details,
        )
        behavioral, contradictions, direct = _behavioral_evidence(context.details)
        support = [*structural, *behavioral]
        observed = {str(item.get("type") or "") for item in support}

        if "authentication_surface" not in observed and not (
            {"session_reuse_after_logout", "token_not_rotated", "recovery_bypass", "authentication_state_violation"} & observed
        ):
            return None

        contradiction_types = {str(item.get("type") or "") for item in contradictions}
        confirmation_missing = confirmation_gaps(self.family, observed)
        policy = FAMILY_REASONING[self.family]
        writeups = _matched_writeups(observed)

        if "session_reuse_after_logout" in observed:
            variant = "session_reuse_after_logout"
            summary = "Stored target evidence indicates a session remained usable after an explicit logout boundary."
            base = 48
        elif "recovery_bypass" in observed:
            variant = "recovery_verification_bypass"
            summary = "Stored target evidence indicates account recovery completed without a required verification step."
            base = 48
        elif "authentication_state_violation" in observed:
            variant = "authentication_state_violation"
            summary = "Stored target evidence indicates the observed authenticated/access state violated the documented authentication boundary."
            base = 46
        elif "token_not_rotated" in observed:
            variant = "token_rotation_failure"
            summary = "Stored target evidence indicates token/session rotation did not occur across a transition where rotation was explicitly required."
            base = 42
        else:
            variant = "auth_lifecycle"
            summary = "A client-visible authentication/session lifecycle is present; no stored target evidence yet establishes a state-machine or session-control failure."
            base = 20

        if contradictions and not direct:
            base = max(8, base - min(12, len(contradictions) * 4))

        missing = list(policy.get("next_evidence", ()))
        if confirmation_missing:
            missing = list(dict.fromkeys([
                *missing,
                *[f"Confirmation evidence: {' / '.join(group)}" for group in confirmation_missing],
            ]))

        return {
            "family": self.family,
            "variant": variant,
            "base": base,
            "support": support,
            "contradict": contradictions,
            "missing": missing,
            "rule_ids": [
                "auth-session-state-machine",
                "auth-session-lifecycle",
                "auth-session-boundary-comparison",
                "auth-session-behavioral-decision",
            ],
            "summary": summary,
            "direct": bool(direct),
            "family_analyzer": {
                **self.metadata(),
                "rule_version": AUTH_SESSION_FAMILY_ANALYZER_RULE_VERSION,
                "taxonomy": dict(AUTH_SESSION_TAXONOMY),
                "methodology": [dict(step) for step in AUTH_SESSION_METHOD],
                "writeup_patterns": writeups,
                "false_positive_checks": list(AUTH_SESSION_FALSE_POSITIVE_CHECKS),
                "triggered_false_positive_checks": _triggered_false_positive_checks(contradiction_types),
                "promotion_required": [sorted(group) for group in policy["promotion_required"]],
                "confirmation_required": [sorted(group) for group in policy["confirmation_required"]],
                "confirmation_missing": confirmation_missing,
                "confirmation_ready_from_stored_target_evidence": not confirmation_missing,
                "next_evidence": list(policy.get("next_evidence", ())),
                "validation_level": str(policy.get("validation_level") or "passive_live"),
                "knowledge_sources_matched": len(writeups),
                "knowledge_does_not_change_target_evidence": True,
                "confounders": ["account_enumeration", "broken_function_authorization", "secret_exposure"],
            },
        }


def analyze_authentication_session_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str,
    body_fields: list[str],
    query_fields: list[str],
    auth_hints: list[str],
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
    return AuthenticationSessionFamilyAnalyzer().analyze(
        context,
        body_fields=body_fields,
        query_fields=query_fields,
        auth_hints=auth_hints,
        semantic_text=semantic_text,
    )


__all__ = [
    "AUTH_SESSION_FAMILY_ANALYZER_VERSION",
    "AUTH_SESSION_FAMILY_ANALYZER_RULE_VERSION",
    "AUTH_SESSION_TAXONOMY",
    "AUTH_SESSION_METHOD",
    "AuthenticationSessionFamilyAnalyzer",
    "analyze_authentication_session_signal",
]
