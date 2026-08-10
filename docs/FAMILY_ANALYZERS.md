# Dedicated Family Analyzers

## Goal

Recon Monitor is migrating from shared heuristic detection to a shared evidence core plus independently versioned analyzers for each vulnerability family.

The architecture is:

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

There is deliberately no generic analyzer fallback. A family is routed to a dedicated analyzer only after its implementation and regression tests exist.

## Knowledge boundary

CWE, OWASP WSTG, OWASP API Security guidance, CAPEC and vulnerability write-ups may influence:

- what relationships the analyzer models;
- what evidence it looks for next;
- how it distinguishes neighboring families;
- which false positives and contradictions it checks;
- how it explains a hypothesis;
- which real-world patterns are similar.

They may **not** create supporting target evidence, count as an independent evidence root, satisfy Family Reasoning admission, raise target-evidence confidence, or confirm a vulnerability.

## Reference implementation: BOLA / IDOR

The first dedicated analyzer is `family_analyzers.bola.BolaFamilyAnalyzer`.

Primary reasoning references:

- CWE-639 — Authorization Bypass Through User-Controlled Key
- OWASP API1:2023 — Broken Object Level Authorization
- WSTG-ATHZ-04 — Testing for Insecure Direct Object References
- WSTG-ATHZ-02 — Testing for Bypassing Authorization Schema
- WSTG-APIT-02 — API Broken Object Level Authorization

The BOLA algorithm separates object reference, expected authorization boundary, horizontal comparison, behavioral authorization failure and explicit contradiction/false-positive checks. An identifier alone remains a hypothesis surface and cannot confirm BOLA.

## Dedicated analyzer: BFLA

The second production-routed analyzer is `family_analyzers.bfla.BflaFamilyAnalyzer`.

Primary reasoning references:

- CWE-862 — Missing Authorization
- CWE-285 / CWE-863 / CWE-269 as related authorization and privilege concepts
- OWASP API5:2023 — Broken Function Level Authorization
- WSTG-ATHZ-02 — Testing for Bypassing Authorization Schema
- WSTG-APIT-04 — API Broken Function Level Authorization

The BFLA algorithm separates privileged-function discovery, role/function policy, vertical comparison, method/scope differentials, behavioral success and contradiction/false-positive review. An `/admin` route or privileged-looking label alone is not confirmation.

## Dedicated analyzer: Mass Assignment / Object Property Authorization

The third production-routed analyzer is `family_analyzers.mass_assignment.MassAssignmentFamilyAnalyzer`.

Primary reasoning references:

- CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes
- OWASP API3:2023 — Broken Object Property Level Authorization
- OWASP API6:2019 — Mass Assignment
- WSTG-INPV-20 — Mass Assignment

The Mass Assignment algorithm separates six questions:

1. **Property surface** — does a client-controlled write contract expose a security-sensitive or policy-controlled object property?
2. **Writable contract** — what fields is the server intended to accept for this exact operation?
3. **Property authorization** — may this caller modify this specific property on an otherwise writable object?
4. **Behavioral decision** — was a protected/non-writable property actually accepted contrary to policy?
5. **Persistence** — was the property merely echoed/parsed, or was it actually persisted/changed in stored target evidence?
6. **Contradictions/confounders** — was the field rejected, ignored, excluded by a server allow-list, or is the case better explained by BOLA, BFLA or business logic?

A body field such as `role`, `is_admin`, `status`, `permissions`, `owner_id` or `tenant_id` is only a surface clue. Direct evidence is represented by family-specific observations such as:

- `protected_property_accepted`
- `protected_property_mutated`
- `property_authorization_differential`

Explicit controls include:

- `protected_property_rejected`
- `sensitive_property_ignored`
- `server_allowlist_observed`

A 2xx response by itself is not property-mutation confirmation; persisted/read-back or explicit property-policy evidence is preferred.

### Mass Assignment real-world pattern library

The current non-evidentiary pattern library includes the adjacent Wekan custom-field manipulation lesson from GHSL-2026-044: writable privileged/custom-field behavior is only meaningful when the server applies a property outside the caller's intended property policy. Pattern similarity never becomes target evidence.

## Write-up pattern library

Family analyzers may use either the shared non-evidentiary corpus in `vulnerability_knowledge.py` or family-specific curated pattern records. A matched write-up only tells the analyst which known pattern the stored target evidence resembles. It never adds support evidence, satisfies admission, or raises target-evidence confidence.

## Compatibility

`app/bola_intelligence.py` remains the BOLA public compatibility import surface.

For Candidate Engine integration, the historical implementation is preserved in `app/bug_candidates_core.py`; public `app/bug_candidates.py` is an additive compatibility/integration wrapper. BFLA and Mass Assignment target evidence are enriched by their dedicated analyzers before the existing `record_hypothesis → Family Reasoning admission → promotion` flow. Other families remain delegated unchanged until their dedicated analyzer migration is complete.

## Router status

Currently production-routed:

1. BOLA / IDOR
2. Broken Function Level Authorization
3. Mass Assignment / Object Property Authorization

Pending dedicated analyzers: 18.

## Migration order

Next analyzers will be added independently for:

1. Authentication / Session
2. Account Enumeration
3. DOM XSS
4. postMessage Trust
5. Open Redirect
6. SSRF
7. File Upload / Import
8. Path Traversal
9. Information Disclosure
10. Source-map Exposure
11. Secret Exposure
12. GraphQL Authorization
13. GraphQL Data Exposure
14. Business Logic
15. Race Condition
16. WebSocket Authorization
17. CORS
18. Sensitive Caching

Each migration must add a dedicated analyzer, source-specific reasoning rules, false-positive tests, admission/confirmation regression coverage, production routing and CI before the router is allowed to register that family.
