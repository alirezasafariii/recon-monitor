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

Contradicting controls include `origin_check_observed`, `trusted_origin_only` and `message_schema_rejected`.

Exact origin allow-lists and verified source-window controls are treated as evidence against an unsafe trust decision. A wildcard `targetOrigin` on the sending side is not automatically treated as a receiving-side trust failure. DOM execution is also not inferred from postMessage trust failure alone; DOM-XSS remains a neighboring family with its own confirmation contract.

The Candidate Engine static JavaScript path is migrated for postMessage Trust as well. No automatic cross-origin message injection, exploit payload execution or active browser exploitation is performed by the analyzer.

## 8. Open Redirect / Navigation Injection

`family_analyzers.open_redirect.OpenRedirectFamilyAnalyzer`

Primary reasoning references:

- CWE-601 — URL Redirection to Untrusted Site ('Open Redirect')
- WSTG-CLNT-04 — Testing for Client-side URL Redirect

The algorithm separates five questions:

1. **Input surface** — which user-influenced parameter or browser value controls the candidate destination?
2. **Navigation sink** — does that value reach an actual navigation primitive rather than merely URL parsing, display or logging?
3. **Destination policy** — is navigation constrained by an exact allow-list, same-origin rule, relative-path-only policy, scheme restriction or normalization step?
4. **Runtime destination** — did stored target evidence show the user-controlled destination being accepted and the resulting navigation reaching an external origin?
5. **False-positive review** — do parsed origin semantics, allow-list enforcement or same-origin/relative-only behavior contradict the hypothesis?

Static destination-to-navigation proximity is intentionally **one correlated evidence root**. Parameter names such as `next`, `url`, `returnUrl`, `callback` or `redirect_uri`, and a static `location.href` assignment, do not by themselves create a Potential Finding.

Family-specific evidence:

- `navigation_validation_absent` — stored evidence that effective destination validation was absent; support only, not confirmation.
- `external_navigation_observed` — an external navigation was stored, but user control of its destination has not been established; not direct evidence.
- `external_destination_accepted` — a user-controlled destination was accepted and navigation reached an external origin outside the intended trust boundary; this is the decisive direct condition.

Contradicting controls include:

- `destination_allowlist_observed`
- `same_origin_navigation_enforced`
- `unsafe_scheme_rejected`

Destination comparisons use parsed scheme/hostname/port semantics rather than substring matching, so a host such as `example.com.evil.test` is not treated as trusted merely because it contains `example.com`. Relative paths and same-origin absolute URLs are not external redirect evidence.

The Candidate Engine static JavaScript path is migrated for Open Redirect:

```text
static destination → navigation flow
        ↓
hidden hypothesis
        ↓
dedicated Open Redirect analyzer
        ↓
Family Reasoning admission
        ↓
independent stored external-navigation condition
        ↓
Potential Finding
```

No automatic redirect request, browser navigation, exploit payload or active validation is performed by the analyzer.

## 9. Server-Side Request Forgery (SSRF)

`family_analyzers.ssrf.SsrfFamilyAnalyzer`

Primary reasoning references:

- CWE-918 — Server-Side Request Forgery (SSRF)
- WSTG-INPV-19 — Testing for Server-Side Request Forgery

The algorithm separates five independent questions:

1. **Destination surface** — does the endpoint expose a user-controlled URL/URI/destination field?
2. **Execution location** — is the network request performed by the server/backend rather than by browser JavaScript?
3. **Destination policy** — are scheme/host allow-lists, private-network restrictions, redirect revalidation or egress controls actually enforced?
4. **Stored outbound observation** — does stored target evidence tie the user-controlled destination to an outbound request performed by the server, or to a tester-controlled correlated callback explicitly attributed to server execution?
5. **Boundary failure** — did the same stored observation show an intended destination restriction being bypassed or a destination expected to be restricted being accepted?

A URL-looking field plus webhook/import/preview/proxy semantics is intentionally **one structural evidence root**. It is useful for recall and hunting, but does not by itself create a Potential Finding. Browser-side fetches are explicitly contradictory evidence for SSRF.

Family-specific evidence is deliberately split by certainty:

- `server_fetch_capability_observed` — server-side remote fetching exists, but user control of that destination is not established; not direct SSRF evidence.
- `server_fetch_observed` — stored evidence ties a user-controlled destination to a server-side outbound request. This is sufficient for a **Potential Finding**, but not by itself for family-level confirmation.
- `controlled_callback_observed` — a tester-controlled destination produced a correlated callback that is explicitly attributed to server/backend execution. This may promote a Potential Finding, but still does not by itself prove that a destination trust boundary was bypassed.
- `destination_policy_bypass_observed` — the same direct server-fetch observation establishes bypass of an intended destination restriction; decisive confirmation condition.
- `restricted_destination_accepted` — the same direct server-fetch observation records that a destination expected to be restricted was accepted; decisive confirmation condition.

Contradicting controls include:

- `browser_side_fetch_observed`
- `server_fetch_not_observed`
- `destination_validation_observed`

`destination_validation_observed` covers stored enforcement of destination/host/scheme allow-lists, private-network or metadata blocking, redirect revalidation and egress policy. A missing visible validation branch is only supporting context and cannot confirm SSRF.

Literal IP destinations may be classified offline as public/private/loopback/link-local/reserved using parsing only. The analyzer performs **no DNS resolution**, no internal or metadata endpoint probing, no arbitrary third-party request, and no automatic active validation.

The Candidate Engine alert/endpoint path is now hypothesis-first for SSRF:

```text
remote destination + server-fetch semantics
        ↓
hidden hypothesis
        ↓
dedicated SSRF analyzer
        ↓
Family Reasoning admission
        ↓
independent stored server-side outbound observation
        ↓
Potential Finding
        ↓
stored destination-boundary failure
        ↓
family confirmation-ready state
```

This preserves recall while preventing `url`, `webhook`, `preview`, `import`, `proxy` or HTTP 2xx clues from becoming findings without server-side execution evidence.

## Write-up pattern library

Family analyzers may use either the shared non-evidentiary corpus in `vulnerability_knowledge.py` or family-specific curated pattern records. A matched write-up only tells the analyst which known pattern the stored target evidence resembles. It never adds support evidence, satisfies admission, or raises target-evidence confidence.

## Compatibility

`app/bola_intelligence.py` remains the BOLA compatibility import surface.

The historical Candidate Engine implementation remains in `app/bug_candidates_core.py`; public `app/bug_candidates.py` is the additive integration layer. Dedicated alert-family analyzers run before `record_hypothesis → Family Reasoning admission → promotion`. DOM-XSS, postMessage Trust and Open Redirect additionally migrate their static JavaScript paths to hypothesis-first handling. SSRF migrates its alert/endpoint surface through the dedicated analyzer before admission, so structural remote-fetch semantics remain hidden until independent stored server-side outbound evidence exists. Non-migrated families continue through the legacy implementation until their dedicated migration is complete.

## Router status

Currently production-routed:

1. BOLA / IDOR
2. Broken Function Level Authorization
3. Mass Assignment / Object Property Authorization
4. Authentication / Session
5. Account Enumeration
6. DOM-based XSS
7. postMessage Trust / Web Messaging
8. Open Redirect / Navigation Injection
9. Server-Side Request Forgery (SSRF)

Pending dedicated analyzers: **12**.

## Migration order

Next analyzers:

1. File Upload / Import
2. Path Traversal
3. Information Disclosure
4. Source-map Exposure
5. Secret Exposure
6. GraphQL Authorization
7. GraphQL Data Exposure
8. Business Logic
9. Race Condition
10. WebSocket Authorization
11. CORS
12. Sensitive Caching

Each migration must add a dedicated analyzer, source-specific reasoning rules, false-positive tests, admission/confirmation regression coverage, production routing and green CI before the router is allowed to register that family.
