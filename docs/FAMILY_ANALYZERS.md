# Dedicated Family Analyzers

## Goal

Recon Monitor is migrating from shared heuristic detection to a shared evidence core plus independently versioned analyzers for each vulnerability family.

```text
stored target observations
        ↓
shared normalization / evidence vocabulary
        ↓
explicit family router
        ↓
family-specific analyzer
        ↓
hidden hypothesis
        ↓
Family Reasoning admission
        ↓
Potential Finding
        ↓
family-specific confirmation requirements
```

There is deliberately no generic analyzer fallback. A family is routed to a dedicated analyzer only after its implementation, production integration and regression tests exist.

## Knowledge boundary

CWE, OWASP WSTG, OWASP API Security guidance, CAPEC and vulnerability write-ups may influence what relationships an analyzer models, which evidence it requests next, how it separates neighboring families, which false positives it checks, and how it explains a hypothesis.

They may **not** create supporting target evidence, count as an independent evidence root, satisfy Family Reasoning admission, raise target-evidence confidence, or confirm a vulnerability.

## 1. BOLA / IDOR

`family_analyzers.bola.BolaFamilyAnalyzer`

Primary reasoning references:

- CWE-639 — Authorization Bypass Through User-Controlled Key
- OWASP API1:2023 — Broken Object Level Authorization
- WSTG-ATHZ-04 — Testing for Insecure Direct Object References
- WSTG-ATHZ-02 — Testing for Bypassing Authorization Schema
- WSTG-APIT-02 — API Broken Object Level Authorization

The algorithm separates object reference, expected authorization boundary, horizontal comparison, behavioral authorization failure and contradiction review. An identifier alone remains a hypothesis surface.

## 2. Broken Function Level Authorization

`family_analyzers.bfla.BflaFamilyAnalyzer`

Primary reasoning references:

- CWE-862 — Missing Authorization
- related CWE-285 / CWE-863 / CWE-269 concepts
- OWASP API5:2023 — Broken Function Level Authorization
- WSTG-ATHZ-02
- WSTG-APIT-04

The algorithm separates privileged-function discovery, role/function policy, vertical comparison, method/scope differentials, behavioral success and explicit enforcement controls. An `/admin` route alone is not confirmation.

## 3. Mass Assignment / Object Property Authorization

`family_analyzers.mass_assignment.MassAssignmentFamilyAnalyzer`

Primary reasoning references:

- CWE-915
- OWASP API3:2023 — Broken Object Property Level Authorization
- OWASP API6:2019 — Mass Assignment
- WSTG-INPV-20

The algorithm separates property surface, writable contract, property authorization, behavioral acceptance, persistence and contradiction review. Sensitive property names such as `role` or `is_admin` are only surface clues; direct evidence requires accepted/persisted policy-sensitive mutation or a property authorization differential.

## 4. Authentication / Session

`family_analyzers.authentication_session.AuthenticationSessionFamilyAnalyzer`

Primary reasoning references:

- CWE-287
- related CWE-613 / CWE-384 / CWE-640 lifecycle concepts
- OWASP A07:2021
- WSTG-ATHN-04
- WSTG-SESS-01

The algorithm models authentication state transitions and token/session lifecycle. Direct evidence is limited to stored lifecycle failures such as session reuse after logout, required rotation failure, recovery bypass or an explicit authentication-state violation. Authentication-looking routes, token strings and HTTP 2xx are insufficient by themselves.

## 5. Account Enumeration

`family_analyzers.account_enumeration.AccountEnumerationFamilyAnalyzer`

Primary reasoning references:

- WSTG-IDNT-04
- CWE-204
- CWE-208
- related CWE-203 concepts
- OWASP A07:2021

Direct comparison evidence requires explicitly controlled test identities. Response comparisons normalize status, shape and semantic message class; timing requires repeated controlled samples and rejects rate-limit/challenge confounders. Real-user probing is outside the analyzer contract.

## 6. DOM-based XSS

`family_analyzers.dom_xss.DomXssFamilyAnalyzer`

Primary reasoning references:

- CWE-79 — Improper Neutralization of Input During Web Page Generation
- OWASP A03:2021 — Injection
- WSTG-CLNT-01 — Testing for DOM-Based Cross Site Scripting
- related WSTG-CLNT-02 / WSTG-CLNT-06 client-side execution and resource-manipulation concepts

The algorithm is deliberately source-to-sink and runtime aware:

1. **Source classification** — determine whether the browser value is actually user-influenced.
2. **Flow / transformation** — preserve the source-to-sink relation and distinguish one static flow from independent evidence.
3. **Sink / context** — separate HTML-rendering and executable JavaScript contexts from safe text sinks and neighboring navigation/postMessage families.
4. **Neutralization controls** — model context-appropriate sanitization, encoding, Trusted Types and safe DOM APIs as evidence against the vulnerability condition.
5. **Runtime reachability** — accept only stored observations showing a controlled harmless marker reaching the identified dangerous sink.
6. **Vulnerability condition** — direct DOM-XSS condition evidence requires runtime reachability into an executable/script-capable context plus explicit absence of effective neutralization.

Static source/sink proximity is intentionally **one correlated evidence root**. A row such as `location.search → innerHTML` therefore becomes a hidden hypothesis, not a Potential Finding.

Family-specific direct evidence:

- `runtime_dom_sink_reached` — runtime reachability only; not sufficient for confirmation by itself.
- `unsanitized_dom_flow` — runtime-reachable dangerous/executable context with effective neutralization explicitly absent; decisive family condition.

Contradicting controls include `sanitization_observed` and `runtime_unreachable`.

The Candidate Engine static JavaScript path is migrated for DOM-XSS: legacy direct insertion is filtered out, the flow is first recorded in `analysis_hypotheses`, and a Potential Finding is created only when independent stored runtime condition evidence is present. No payload execution or active browser validation is performed by the analyzer.

## 7. postMessage Trust / Web Messaging

`family_analyzers.postmessage_trust.PostMessageTrustFamilyAnalyzer`

Primary reasoning references:

- WSTG-CLNT-11 — Testing Web Messaging
- CWE-346 — Origin Validation Error

The algorithm separates five independent questions:

1. **Handler surface** — does client code consume `postMessage` / `MessageEvent` data?
2. **Origin/source policy** — which sender origins or source windows are intended to be trusted, and is that trust decision actually enforced?
3. **Message schema** — is `event.data` validated as untrusted input independently of sender trust?
4. **Sensitive consumer** — does accepted message data reach a DOM, navigation, network, storage, authentication or state-changing consumer?
5. **Runtime trust decision** — did stored target evidence show an explicitly untrusted sender being accepted and reaching that sensitive consumer?

Static message-handler and sink proximity is intentionally **one correlated evidence root**. The existence of `addEventListener('message', ...)`, `event.data`, a sensitive-looking sink, or a missing origin check does not by itself confirm a vulnerability.

Family-specific evidence:

- `origin_validation_absent` — stored evidence that an effective origin check was absent; useful support, but not confirmation by itself.
- `untrusted_message_reached_handler` — an explicitly untrusted sender was accepted by the handler, but no sensitive effect is established yet.
- `untrusted_message_accepted` — an explicitly untrusted sender was accepted and reached the identified sensitive consumer without an effective origin/source trust control; this is the decisive direct condition.

Contradicting controls include:

- `origin_check_observed`
- `trusted_origin_only`
- `message_schema_rejected`

Exact origin allow-lists and verified source-window controls are treated as evidence against an unsafe trust decision. A wildcard `targetOrigin` on the sending side is not automatically treated as a receiving-side trust failure. DOM execution is also not inferred from postMessage trust failure alone; DOM-XSS remains a neighboring family with its own confirmation contract.

The Candidate Engine static JavaScript path is migrated for postMessage Trust as well:

```text
postMessage static flow
        ↓
hidden hypothesis
        ↓
dedicated postMessage analyzer
        ↓
Family Reasoning admission
        ↓
independent stored runtime trust failure
        ↓
Potential Finding
```

No automatic cross-origin message injection, exploit payload execution or active browser exploitation is performed by the analyzer.

## Write-up pattern library

Family analyzers may use either the shared non-evidentiary corpus in `vulnerability_knowledge.py` or family-specific curated pattern records. A matched write-up only tells the analyst which known pattern the stored target evidence resembles. It never adds support evidence, satisfies admission, or raises target-evidence confidence.

## Compatibility

`app/bola_intelligence.py` remains the BOLA compatibility import surface.

The historical Candidate Engine implementation remains in `app/bug_candidates_core.py`; public `app/bug_candidates.py` is the additive integration layer. Dedicated alert-family analyzers run before `record_hypothesis → Family Reasoning admission → promotion`. DOM-XSS and postMessage Trust additionally migrate their static JavaScript paths to hypothesis-first handling while non-migrated static families continue through the legacy implementation.

## Router status

Currently production-routed:

1. BOLA / IDOR
2. Broken Function Level Authorization
3. Mass Assignment / Object Property Authorization
4. Authentication / Session
5. Account Enumeration
6. DOM-based XSS
7. postMessage Trust / Web Messaging

Pending dedicated analyzers: **14**.

## Migration order

Next analyzers:

1. Open Redirect
2. SSRF
3. File Upload / Import
4. Path Traversal
5. Information Disclosure
6. Source-map Exposure
7. Secret Exposure
8. GraphQL Authorization
9. GraphQL Data Exposure
10. Business Logic
11. Race Condition
12. WebSocket Authorization
13. CORS
14. Sensitive Caching

Each migration must add a dedicated analyzer, source-specific reasoning rules, false-positive tests, admission/confirmation regression coverage, production routing and green CI before the router is allowed to register that family.
