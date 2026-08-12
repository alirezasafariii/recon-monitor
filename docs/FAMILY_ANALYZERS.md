# Dedicated Family Analyzer Architecture

This document describes the dedicated vulnerability-family reasoning layer used by Recon Monitor. Family analyzers consume stored target evidence, apply family-specific false-positive and confirmation rules, and feed the existing hypothesis/admission/candidate workflow. External knowledge, taxonomy and public write-up patterns are reasoning context only and never create target evidence.

## Core principles

- A signal is not a vulnerability.
- Potential Finding and analyst-confirmed finding remain distinct states.
- Each canonical family has an explicit Family Reasoning contract and an independently versioned dedicated analyzer.
- Unknown families fail closed.
- Write-up similarity, CWE/OWASP/WSTG context, historical feedback, correlation and LLM advice remain non-evidentiary.
- Direct evidence must come from stored target observations and satisfy the family-specific safety/ownership constraints.
- Analyzers do not perform exploit execution or destructive/state-changing validation.

## Family analyzer framework

`app/family_analyzers/base.py` provides the common analyzer context and metadata contract. `app/family_analyzers/router.py` explicitly registers canonical families; there is no generic analyzer fallback.

The public Candidate Engine compatibility layer remains `app/bug_candidates.py`, while the historical implementation remains in `app/bug_candidates_core.py`. Dedicated analyzers are additive reasoning modules layered before promotion/admission decisions.

## 1. BOLA / IDOR

`family_analyzers.bola.BolaFamilyAnalyzer`

Primary reasoning references:

- CWE-639 — Authorization Bypass Through User-Controlled Key
- OWASP API1 — Broken Object Level Authorization
- WSTG-ATHZ-02 / WSTG-ATHZ-04 / WSTG-APIT-02

Object identifiers, path parameters and response status are structural evidence only. Confirmation requires target-specific cross-identity, cross-tenant, unauthorized-object or authorization-differential evidence. Public/shared-object context and observed ownership enforcement are false-positive controls.

## 2. Broken Function Level Authorization

`family_analyzers.bfla.BflaFamilyAnalyzer`

Primary reasoning references:

- CWE-862 — Missing Authorization
- related CWE-285 / CWE-863 / CWE-269
- OWASP API5:2023
- WSTG-APIT-04 / WSTG-ATHZ-02

Privileged-looking routes and HTTP status do not prove BFLA. Direct target evidence requires stored behavior such as unauthorized privileged-function success or a role authorization differential. Observed role enforcement, permission checks and lower-privilege denial are contradictions.

## 3. Mass Assignment / Object Property Authorization

`family_analyzers.mass_assignment.MassAssignmentFamilyAnalyzer`

Primary reasoning references:

- CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes
- OWASP API3:2023 / API6:2019
- WSTG-INPV-20

Writable request bodies plus privileged-looking fields remain a hypothesis. Direct evidence requires target behavior showing a protected property was accepted/mutated or a property-authorization differential. Rejected/ignored sensitive fields and observed server allow-lists are contradictions.

## 4. Authentication / Session

`family_analyzers.authentication_session.AuthenticationSessionFamilyAnalyzer`

Primary reasoning references:

- CWE-287 — Improper Authentication
- related CWE-613 / CWE-384 / CWE-640
- OWASP A07:2021
- WSTG-ATHN-04 / WSTG-SESS-01

Authentication-looking surfaces are separated from lifecycle/state violations. Direct evidence includes session reuse after logout, explicitly expected token rotation failure, recovery bypass or an authentication-state violation. Session rotation, recovery verification and expired-session rejection are contradictions.

## 5. Account Enumeration

`family_analyzers.account_enumeration.AccountEnumerationFamilyAnalyzer`

Primary reasoning references:

- CWE-204 / CWE-208
- WSTG-IDNT-04

The analyzer compares only explicitly controlled known-existing and deliberately non-existing test identities. Direct response or timing differentials require stable, repeated stored evidence; one timing sample is never direct. Uniform responses/timing and rate-limit confounding prevent promotion.

## 6. DOM-based XSS

`family_analyzers.dom_xss.DomXssFamilyAnalyzer`

Primary reasoning references:

- CWE-79
- OWASP A03:2021
- WSTG-CLNT-01; related WSTG-CLNT-02 / WSTG-CLNT-06

Static source-to-sink proximity is one correlated evidence root, not confirmation. Runtime sink reachability proves only reachability. `unsanitized_dom_flow` is the decisive condition and requires stored runtime reachability, a dangerous/executable context and explicit absence of effective neutralization. Sanitization, Trusted Types, safe DOM APIs and runtime unreachability are controls/contradictions. The analyzer performs no live payload execution.

## 7. postMessage Trust / Web Messaging

`family_analyzers.postmessage_trust.PostMessageTrustFamilyAnalyzer`

Primary reasoning references:

- WSTG-CLNT-11 — Testing Web Messaging
- CWE-346 — Origin Validation Error

Message handlers, `event.data` and `postMessage` calls are discovery surface only. Direct target evidence requires stored runtime behavior showing an untrusted sender/origin can reach a sensitive consumer without effective origin/source validation. Strict origin/source checks and effective message validation are contradiction evidence. No cross-origin exploit delivery is performed.

## 8. Open Redirect / Navigation Injection

`family_analyzers.open_redirect.OpenRedirectFamilyAnalyzer`

Primary reasoning references:

- CWE-601
- WSTG-CLNT-04 / WSTG-CLNT-06

A user-influenced value near a navigation sink remains a hidden hypothesis. Direct evidence requires a stored controlled external-destination acceptance or equivalent navigation differential. Trusted allow-lists and blocked external destinations are contradictions.

## 9. Server-Side Request Forgery

`family_analyzers.ssrf.SsrfFamilyAnalyzer`

Primary reasoning references:

- CWE-918
- OWASP SSRF guidance / WSTG server-side request methodology

Remote-destination inputs and server-fetch semantics are structural. Direct evidence is restricted to stored, scope-authorized, controlled callback or server-fetch observations. The analyzer does not probe internal/metadata addresses or generate unrestricted SSRF payloads.

## 10. File Upload / Import

`family_analyzers.file_upload.FileUploadFamilyAnalyzer`

Primary reasoning references:

- CWE-434
- WSTG-BUSL / file upload security guidance

File inputs and upload/import routes are surface only. Promotion requires stored target behavior such as unsafe-file acceptance, a file-policy differential or content-type bypass using safe test material. Executable-upload evidence is never produced by executing uploaded content.

## 11. Path Traversal

`family_analyzers.path_traversal.PathTraversalFamilyAnalyzer`

Primary reasoning references:

- CWE-22 — Improper Limitation of a Pathname to a Restricted Directory
- related CWE-23 / CWE-36
- WSTG-ATHZ-01

Path/filename input plus a file operation shares one structural evidence root. `path_escape_observed` requires stored behavior from an explicitly controlled, non-sensitive test resource. Stronger confirmation requires canonicalization-boundary bypass or out-of-root controlled access/write evidence. Canonicalization/base-directory enforcement are contradictions. No sensitive-path request or filesystem exploit is generated.

## 12. Information Disclosure

`family_analyzers.information_disclosure.InformationDisclosureFamilyAnalyzer`

Primary reasoning references:

- CWE-200
- related CWE-209 / CWE-497 / CWE-1295
- WSTG-ERRH-01 / WSTG-ERRH-02 / WSTG-INFO-05

Debug strings, stack markers, internal-looking paths, versions and sensitive names remain structural. Direct evidence requires stored response behavior showing non-public information outside its intended audience. Intended-public metadata and redaction enforcement are contradictions. Raw sensitive values are not copied into analyzer output.

## 13. Source-map Exposure

`family_analyzers.source_map_exposure.SourceMapExposureFamilyAnalyzer`

Primary reasoning references:

- CWE-200 / CWE-497 / CWE-540
- WSTG-INFO-05

A `sourceMappingURL`, `.map` filename or source-map URL is discovery surface only. Promotion requires stored evidence that the passive collector actually retrieved the map without credentials and that the same map contains meaningful internal source structure, or explicit stored sensitive-source review evidence. The legacy static direct-candidate path is closed.

## 14. Secret Exposure

`family_analyzers.secret_exposure.SecretExposureFamilyAnalyzer`

Primary reasoning references:

- CWE-798 — Use of Hard-coded Credentials
- related CWE-321 / CWE-540 / CWE-200
- WSTG-INFO-05
- OWASP Secrets Management Cheat Sheet

Secret-looking field names are discovery surface only. Stored JavaScript is classified offline; matched material is fingerprinted/redacted and raw credential values are discarded. Complete private-key structures, paired cloud credential material and strong provider-specific secret formats may produce `credential_material_confirmed`. JWT syntax remains a candidate rather than proof of a live or privileged token. Placeholders, templates, provider test credentials and publishable/public client identifiers are filtered before promotion. No online credential validation is performed.

## 15. GraphQL Authorization

`family_analyzers.graphql_authorization.GraphqlAuthorizationFamilyAnalyzer`

GraphQL object identifiers and operations share one static evidence root and remain hidden by themselves. Direct evidence requires controlled test identities and test-owned objects showing `graphql_unauthorized_object_response` or `graphql_authorization_differential`. Resolver authorization and controlled out-of-scope denial are contradictions. The historical GraphQL static direct-insertion path is migrated to hypothesis-first admission.

## 16. GraphQL Data Exposure

`family_analyzers.graphql_data_exposure.GraphqlDataExposureFamilyAnalyzer`

Sensitive-looking GraphQL fields are structural only. Direct evidence requires a controlled role context, an explicit restricted-field policy and stored response-shape evidence such as `sensitive_graphql_response_observed` or `field_authorization_differential`. Raw PII/tokens/financial values are not copied into analyzer output.

## 17. Business Logic

`family_analyzers.business_logic.BusinessLogicFamilyAnalyzer`

Business Logic uses the offline `workflow_intelligence` substrate to correlate stored workflow endpoints, state-changing methods, workflow markers and server-controlled values. Keywords such as checkout, refund, transfer, coupon or confirm are not vulnerabilities. Direct evidence requires a documented expected invariant and reversible controlled test behavior showing `workflow_invariant_violation`, `invalid_transition_accepted` or `server_value_override_observed`. No workflow action is executed by the analyzer.

## 18. Race Condition

`family_analyzers.race_condition.RaceConditionFamilyAnalyzer`

Race reasoning models single-use/idempotency/atomicity semantics from stored workflow context. It never launches concurrent requests. Direct evidence is accepted only from already-authorized stored concurrency observations using test-owned resources, such as `duplicate_operation_observed` or `non_atomic_transition_observed`. Observed idempotency and atomic transitions are contradictions.

## 19. WebSocket Authorization

`family_analyzers.websocket_authorization.WebsocketAuthorizationFamilyAnalyzer`

WebSocket URLs, channel names, topics and subscription messages are discovery surface. Direct evidence requires controlled test identities and test-owned channels/resources showing an unauthorized subscription or channel authorization differential. The analyzer opens no socket, sends no message and performs no channel enumeration. Legacy static WebSocket direct insertion is closed.

## 20. CORS Misconfiguration

`family_analyzers.cors_misconfiguration.CorsMisconfigurationFamilyAnalyzer`

CORS headers are policy surface, not exploitability. Wildcard or reflected-looking ACAO values do not confirm a finding. Promotion requires an independent sensitive/authenticated response context; direct evidence requires already-stored controlled unintended-origin behavior such as `untrusted_origin_allowed` or `credentialed_cross_origin_read`. Trusted-origin-only policy, disabled credentials and browser-blocked reads are contradictions. No credentialed cross-origin request is performed by the analyzer.

## 21. Sensitive Caching

`family_analyzers.sensitive_caching.SensitiveCachingFamilyAnalyzer`

Cacheability metadata is separated from sensitive/user-specific response context. Direct evidence requires redacted, controlled shared-cache behavior such as `shared_cache_sensitive_response` or `cross_user_cache_observed` using controlled test identities. Private/no-store policy, user-specific cache-key separation and shared-cache bypass are contradictions. The analyzer stores no sensitive response body and performs no cache poisoning or cross-user request.

## Shared reasoning substrates

`remaining_common.py` provides normalization and canonical Family Reasoning policy-state evaluation for the final dedicated analyzers. It is not a registered analyzer and cannot create target evidence.

`workflow_intelligence.py` provides offline workflow/sequence correlation for Business Logic and Race Condition. It reads stored analysis results only; it performs no network request or business action. The two families keep separate direct-evidence and contradiction contracts.

## Candidate Engine compatibility

The historical Candidate Engine implementation remains in `app/bug_candidates_core.py`; public `app/bug_candidates.py` is the production integration layer.

All **21 canonical families** now have dedicated analyzers. Static client/intelligence families that formerly had direct legacy insertion paths are routed through dedicated hypothesis/admission handling where migrated. GraphQL and WebSocket static bypasses are closed, and high-priority GraphQL/WebSocket/cache protocol findings remain correlation surfaces instead of bypassing Family Reasoning.

## Write-up pattern library

Family analyzers may use the shared non-evidentiary corpus in `vulnerability_knowledge.py` or family-specific curated pattern records. A matched write-up only indicates resemblance to a known pattern. It never adds support evidence, satisfies admission/confirmation, or raises target-evidence confidence.

## Router status

Production-routed dedicated analyzers: **21 / 21**.

Pending dedicated analyzers: **0**.

Generic Family Analyzer fallback: **disabled**.

Every canonical family in `FAMILY_ORDER` resolves to an independently versioned analyzer. Dedicated Family Analyzer migration is complete; subsequent work is calibration, shared-pipeline cleanup and evidence-quality refinement rather than adding missing family algorithms.
