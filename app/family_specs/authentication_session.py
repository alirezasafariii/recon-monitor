from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


AUTHENTICATION_SESSION_STANDARD_SPEC = FamilyStandardSpec(
    family="authentication_session",
    version="1.0.0",
    strategy="authentication_session_state_transition_boundary",
    principle=(
        "Authentication routes, token strings and session-bearing client operations are attack-surface context only; "
        "promotion requires stored target evidence that a documented authentication or session lifecycle boundary "
        "actually failed, such as post-logout reuse, required rotation failure, recovery bypass, or an invalid authenticated state."
    ),
    owasp=("A07:2025 Authentication Failures",),
    wstg=("WSTG-ATHN-04", "WSTG-SESS-03", "WSTG-SESS-06", "WSTG-SESS-07"),
    cwe=("CWE-287", "CWE-384", "CWE-613", "CWE-640"),
    capec=(),
    methodology=(
        MethodologyStep(
            id="AUTH-01-state-machine",
            basis=("A07:2025", "WSTG-ATHN-04", "CWE-287"),
            principle="Model the intended anonymous, authenticated, recovery, refresh, logout and expired states before interpreting any response as an authentication failure.",
        ),
        MethodologyStep(
            id="AUTH-02-session-rotation",
            basis=("WSTG-SESS-03", "CWE-384"),
            principle="Treat token/session identity as lifecycle evidence only when rotation is explicitly expected for the observed transition and before/after values are tied to the same controlled context.",
        ),
        MethodologyStep(
            id="AUTH-03-logout-expiration",
            basis=("WSTG-SESS-06", "WSTG-SESS-07", "CWE-613"),
            principle="Determine whether logout and expiration invalidate the server-side session by comparing only stored authorized before/after states; a stale client token string alone proves nothing.",
        ),
        MethodologyStep(
            id="AUTH-04-recovery-verification",
            basis=("A07:2025", "CWE-640"),
            principle="Treat recovery as an authentication boundary of its own and require evidence that a required verification factor was not passed while recovery nevertheless completed.",
        ),
        MethodologyStep(
            id="AUTH-05-behavioral-decision",
            basis=("CWE-287", "CWE-384", "CWE-613", "CWE-640"),
            principle="Potential-Finding admission requires an actual stored lifecycle violation: post-logout reuse, required rotation failure, recovery bypass, or a documented authentication-state violation.",
        ),
        MethodologyStep(
            id="AUTH-06-falsification",
            basis=("WSTG-SESS-03", "WSTG-SESS-06", "WSTG-SESS-07"),
            principle="Observed rotation, enforced recovery verification and rejection of expired or logged-out sessions are contradiction evidence for the corresponding hypothesis.",
        ),
    ),
    surface_terms=("login", "logout", "session", "token", "refresh", "password reset", "recovery", "sso", "saml", "oauth", "mfa"),
    surface_fields=("password", "token", "access_token", "refresh_token", "session", "session_id", "code", "otp", "state", "assertion"),
    confounders=("account_enumeration", "broken_function_authorization", "secret_exposure"),
    false_positive_checks=(
        "An authentication-looking endpoint or client-side token reference is only attack-surface context.",
        "A token that remains textually identical is not a rotation failure unless the same stored transition explicitly required rotation.",
        "A successful HTTP response does not prove that an authenticated session was created or that an invalid state was accepted.",
        "Client-side logout cleanup is not sufficient evidence of server invalidation, and retaining a stale client token is not evidence of server acceptance.",
        "Recovery may use a verification factor not visible in the current observation; bypass requires an explicit expected-factor versus completed-recovery comparison.",
        "Observed session rotation, recovery verification enforcement, and expired-session rejection are contradiction evidence for the corresponding lifecycle failure.",
        "OWASP, WSTG, CWE and research write-ups define the reasoning method but add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="ghsl-ruby-saml-2024-329-330",
            source="GitHub Security Lab",
            ref="GHSL-2024-329 / GHSL-2024-330 / ruby-saml",
            url="https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/",
            relation="authentication_state_validation_case",
            lesson=(
                "The reusable lesson is that protocol or parser surface is not the finding: a target-side validation failure must change the authenticated identity or state before it becomes authentication evidence."
            ),
            signal_hints=("authentication_state_violation",),
        ),
        WriteupLesson(
            id="ghsl-2022-083-datahub-session-logout",
            source="GitHub Security Lab",
            ref="GHSL-2022-083 / DataHub failure to invalidate session on logout",
            url="https://github.blog/security/vulnerability-research/github-security-lab-audited-datahub-heres-what-they-found/",
            relation="direct_session_invalidation_case",
            lesson=(
                "DataHub demonstrated the decisive lifecycle pattern: a previously issued session remained accepted after logout. The detector should therefore require post-logout server acceptance, not merely client cookie retention."
            ),
            signal_hints=("session_reuse_after_logout", "expired_session_rejected"),
        ),
    ),
)
