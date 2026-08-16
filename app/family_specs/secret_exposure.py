from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


SECRET_EXPOSURE_STANDARD_SPEC = FamilyStandardSpec(
    family="secret_exposure",
    version="1.0.0",
    strategy="client_delivered_credential_material_exposure",
    principle=(
        "Secret-looking names, partial token markers and generic high-entropy literals are discovery context only; promotion "
        "requires stored offline evidence of structurally complete credential material in an unintended client-delivered "
        "context or already-authorized lifecycle evidence that the exposed material is live. Online credential validation is neither required nor performed."
    ),
    owasp=("A07:2025 Authentication Failures", "OWASP Secrets Management Cheat Sheet"),
    wstg=("WSTG-INFO-05",),
    cwe=("CWE-798", "CWE-321", "CWE-540", "CWE-200"),
    capec=(),
    methodology=(
        MethodologyStep(
            id="SECRET-01-pattern-surface",
            basis=("WSTG-INFO-05", "CWE-798"),
            principle="Treat apiKey, clientSecret, token, password and partial provider-token markers as discovery surface only; names or fragments do not prove credential material.",
        ),
        MethodologyStep(
            id="SECRET-02-material-classification",
            basis=("CWE-798", "CWE-321"),
            principle="Classify already-stored client-delivered material offline using complete format structure, paired credential fields and bounded local context; never call the credential provider.",
        ),
        MethodologyStep(
            id="SECRET-03-placeholder-public-filter",
            basis=("OWASP Secrets Management Cheat Sheet",),
            principle="Reject examples, placeholders, environment references, test-only values and intentionally public or publishable client identifiers before promotion.",
        ),
        MethodologyStep(
            id="SECRET-04-exposure-context",
            basis=("WSTG-INFO-05", "CWE-540", "CWE-200"),
            principle="Separate credential structure from the exposure fact: the material must be tied to stored client-delivered source or another unintended target-side disclosure boundary.",
        ),
        MethodologyStep(
            id="SECRET-05-promotion-without-online-validation",
            basis=("CWE-798", "CWE-321"),
            principle="A complete private key, paired credential or equivalently strong provider credential structure in exposed client material is sufficient for Potential-Finding admission without testing whether the credential still works.",
        ),
        MethodologyStep(
            id="SECRET-06-lifecycle-context",
            basis=("OWASP Secrets Management Cheat Sheet",),
            principle="Live, rotated, revoked or inactive status may be recorded only from already-authorized stored lifecycle evidence; the analyzer itself never uses the credential.",
        ),
    ),
    surface_terms=("api key", "secret", "client secret", "access token", "refresh token", "password", "private key", "credential", "jwt"),
    surface_fields=("api_key", "apikey", "client_secret", "access_token", "refresh_token", "auth_token", "password", "private_key", "secret"),
    confounders=("information_disclosure", "source_map_exposure", "authentication_session"),
    false_positive_checks=(
        "Variable or field names such as apiKey, clientSecret, accessToken or password are surface only.",
        "An access-key identifier without its paired secret is not a structurally complete cloud credential.",
        "A JWT-shaped string is a token candidate but is not assumed live, privileged or unintended.",
        "Publishable/public client identifiers and SDK configuration values are not secret credentials merely because they contain the word key.",
        "Examples, placeholders, test values, environment references and template substitutions remain hidden or contradicted.",
        "Provider-specific test credentials are not treated as production-live material solely from syntax.",
        "No raw credential, private-key body, password, token or secret value is copied into analyzer output.",
        "No provider request or online credential validation is performed or required for detection.",
        "OWASP, WSTG, CWE and research write-ups add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="owasp-wstg-info-05-client-secrets",
            source="OWASP WSTG",
            ref="WSTG-INFO-05 / Review Web Page Content for Information Leakage",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage",
            relation="client_side_secret_review_method",
            lesson="Frontend source can expose credentials and keys; the reusable detector lesson is to distinguish a secret-looking name from actual credential material embedded in target-delivered content.",
            signal_hints=("secret_pattern", "context", "credential_material_confirmed"),
        ),
        WriteupLesson(
            id="cwe-798-hard-coded-credential",
            source="MITRE CWE",
            ref="CWE-798 / Use of Hard-coded Credentials",
            url="https://cwe.mitre.org/data/definitions/798.html",
            relation="hard_coded_credential_model",
            lesson="Hard-coded credentials shipped to a client can be extracted by anyone who receives that artifact; confirmation of credential structure does not require attempting authentication.",
            signal_hints=("credential_material_confirmed",),
        ),
        WriteupLesson(
            id="owasp-secrets-management-source-control",
            source="OWASP Cheat Sheet Series",
            ref="Secrets Management Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            relation="secret_storage_and_lifecycle_method",
            lesson="Secrets should be managed outside exposed source/configuration artifacts and lifecycle state should come from trusted management evidence, not detector-side credential use.",
            signal_hints=("credential_material_confirmed", "live_secret_context"),
        ),
        WriteupLesson(
            id="ghsl-2026-037-wekan-token-leak",
            source="GitHub Security Lab",
            ref="GHSL-2026-037 / Wekan webhook URL and token disclosure",
            url="https://securitylab.github.com/advisories/GHSL-2026-035_GHSL-2026-037_wekan/",
            relation="real_world_token_disclosure_case",
            lesson="The reusable lesson is that a token becomes a concrete exposure finding when target-delivered data reveals the credential material across an unintended visibility boundary; provider-side validation is not the detector requirement.",
            signal_hints=("credential_material_confirmed", "live_secret_context"),
        ),
    ),
)
