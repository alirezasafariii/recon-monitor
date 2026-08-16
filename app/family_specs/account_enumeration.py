from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


ACCOUNT_ENUMERATION_STANDARD_SPEC = FamilyStandardSpec(
    family="account_enumeration",
    version="1.0.0",
    strategy="controlled_identity_existence_discrepancy",
    principle=(
        "Login, recovery, registration and identity-lookup surfaces are discovery context only; promotion requires "
        "stored controlled-test evidence that existing and non-existing test identities produce a material response "
        "difference or a stable repeated timing discrepancy that is not explained by rate limiting or challenge state."
    ),
    owasp=("A07:2025 Authentication Failures",),
    wstg=("WSTG-IDNT-04",),
    cwe=("CWE-204", "CWE-208", "CWE-203"),
    capec=(),
    methodology=(
        MethodologyStep(
            id="ENUM-01-identity-surface",
            basis=("WSTG-IDNT-04", "A07:2025", "CWE-204"),
            principle="Identify registration, login, recovery or identity-lookup operations and keep route/field names as surface evidence only.",
        ),
        MethodologyStep(
            id="ENUM-02-controlled-comparison",
            basis=("WSTG-IDNT-04", "CWE-204"),
            principle="Compare only explicitly controlled test identities, including a known-existing test identity and a deliberately non-existing identifier; never infer direct evidence from real-user probing.",
        ),
        MethodologyStep(
            id="ENUM-03-response-normalization",
            basis=("CWE-204", "CWE-203"),
            principle="Normalize status, response shape and semantic message class so request IDs, timestamps, CSRF values, localization and other volatile metadata do not create false discrepancies.",
        ),
        MethodologyStep(
            id="ENUM-04-timing-stability",
            basis=("CWE-208", "WSTG-IDNT-04"),
            principle="Treat timing as target evidence only when repeated controlled samples show a stable material difference and rate limiting, challenge state and transport noise are not plausible explanations.",
        ),
        MethodologyStep(
            id="ENUM-05-behavioral-decision",
            basis=("A07:2025", "CWE-204", "CWE-208"),
            principle="Potential-Finding admission requires an actual controlled identity response or timing discrepancy; an identity lookup surface alone remains a hidden hypothesis.",
        ),
        MethodologyStep(
            id="ENUM-06-falsification",
            basis=("WSTG-IDNT-04",),
            principle="Uniform generic responses, materially uniform repeated timing and rate-limit/challenge confounding are false-positive controls that must remain visible in the dossier.",
        ),
    ),
    surface_terms=("login", "signin", "register", "signup", "forgot password", "reset password", "recover", "username", "email", "account lookup"),
    surface_fields=("username", "user_name", "email", "email_address", "phone", "account", "login", "identifier", "identity", "user"),
    confounders=("authentication_session", "rate_limiting", "localization", "ab_testing"),
    false_positive_checks=(
        "A login, recovery, registration or identity field is only an enumeration surface.",
        "Different request IDs, timestamps, CSRF tokens or volatile metadata do not establish identity disclosure.",
        "Generic messages such as 'if an account exists' can intentionally hide identity existence.",
        "HTTP 429, CAPTCHA, challenge escalation and retry-after behavior can create response and timing differences unrelated to account existence.",
        "A single slow response is network noise; timing evidence requires repeated controlled samples.",
        "Only identities explicitly marked as controlled test identities may satisfy direct comparison evidence.",
        "OWASP, WSTG, CWE and write-up similarity add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="owasp-wstg-idnt-04-account-enumeration",
            source="OWASP WSTG",
            ref="WSTG-IDNT-04 / Account Enumeration",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
            relation="historical_knowledge_compatibility",
            lesson="Controlled differences between existing and non-existing test identities define the reusable account-enumeration pattern; endpoint names alone are not target evidence.",
            signal_hints=("identity_lookup", "identity_response_differential", "identity_timing_differential"),
        ),
        WriteupLesson(
            id="owasp-wstg-idnt-04-response-pattern",
            source="OWASP WSTG",
            ref="WSTG-IDNT-04 / Testing for Account Enumeration and Guessable User Account",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
            relation="canonical_controlled_response_comparison",
            lesson=(
                "The reusable detector lesson is to compare how the same identity operation responds to a controlled existing identity versus a deliberately non-existing test identifier; the lookup surface itself is not the finding."
            ),
            signal_hints=("identity_lookup", "identity_response_differential", "uniform_identity_response"),
        ),
        WriteupLesson(
            id="cwe-208-account-timing-pattern",
            source="MITRE CWE",
            ref="CWE-208 / Observable Timing Discrepancy",
            url="https://cwe.mitre.org/data/definitions/208.html",
            relation="stable_timing_side_channel_method",
            lesson=(
                "Timing becomes meaningful only when a repeatable discrepancy is tied to the secret identity state. The engine therefore requires repeated controlled observations rather than one slow request."
            ),
            signal_hints=("identity_timing_differential", "uniform_identity_timing"),
        ),
        WriteupLesson(
            id="owasp-top10-2025-a07-account-enumeration",
            source="OWASP Top 10",
            ref="A07:2025 Authentication Failures / account enumeration guidance",
            url="https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
            relation="authentication_failure_prevention_context",
            lesson=(
                "OWASP recommends uniform outcomes for registration, recovery and authentication paths to resist account enumeration. Detection must therefore focus on target-side discrepancies, not endpoint names."
            ),
            signal_hints=("identity_response_differential", "uniform_identity_response"),
        ),
    ),
)
