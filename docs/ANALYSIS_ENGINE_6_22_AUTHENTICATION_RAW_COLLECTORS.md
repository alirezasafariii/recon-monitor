# Analysis Engine 6.22 — Authentication / Account Enumeration raw collectors

Analysis 6.22 physically decomposes `authentication_session` and `account_enumeration` from the alert-orchestrator monolith.

Both families retain the mandatory four-layer grounding contract:

- OWASP WSTG defines the testing semantics.
- OWASP Top 10:2025 / API Security Top 10:2023 provides risk taxonomy.
- MITRE CWE provides weakness taxonomy.
- Real security write-ups provide concrete lessons and confounders.

`authentication_session` is grounded in WSTG-ATHN-04 and WSTG-SESS-01, OWASP A07:2025 plus API2:2023, CWE-287, and the exact GHSL ruby-saml authentication-bypass advisory. Authentication route names, tokens, or session terminology are only surfaces. Promotion requires stored target evidence of an authentication/session lifecycle failure such as a boundary regression, session validation failure, token rotation failure, missing state, or token exposure.

`account_enumeration` is grounded in WSTG-IDNT-04, OWASP A07:2025 plus API2:2023, CWE-204, and the Laravel timing-enumeration advisory CVE-2022-40482. The detector lesson is deliberately narrow: identity inputs are only lookup surfaces. Promotion requires controlled present-versus-absent identity observations with a material response, error, body-length, or repeatable timing discrepancy. Uniform responses remain hidden hypotheses and do not promote.

The collector is metadata-only. It never turns WSTG, OWASP, CWE, a write-up, a route name, or the absence of a visible control into target evidence. Target evidence continues to come only from stored passive execution/reconstruction artifacts and must satisfy family admission.

No active password guessing, credential stuffing, account probing, token forgery, session hijacking, or external requests are introduced by this change.
