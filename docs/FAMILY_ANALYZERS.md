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

They may **not**:

- create supporting target evidence;
- count as an independent evidence root;
- satisfy Family Reasoning admission;
- raise target-evidence confidence;
- confirm a vulnerability.

## Reference implementation: BOLA / IDOR

The first dedicated analyzer is `family_analyzers.bola.BolaFamilyAnalyzer`.

Primary reasoning references:

- CWE-639 — Authorization Bypass Through User-Controlled Key
- OWASP API1:2023 — Broken Object Level Authorization
- WSTG-ATHZ-04 — Testing for Insecure Direct Object References
- WSTG-ATHZ-02 — Testing for Bypassing Authorization Schema
- WSTG-APIT-02 — API Broken Object Level Authorization

The BOLA algorithm separates five questions:

1. **Object reference** — Is a client-influenced identifier actually selecting an object, and what operation is being performed?
2. **Authorization boundary** — What identity, tenant, role, sharing, parent/child, or secondary-guard relationship is expected for that object?
3. **Comparable context** — Is there stored, explicitly authorized comparison context for a different identity/object or tenant/object relationship?
4. **Behavioral decision** — Did a context that should not have object access successfully read or mutate that object?
5. **Contradiction / false-positive check** — Is the object public/shared, is ownership/scope enforcement observed, was the mismatched context denied, or is the issue actually authentication/function authorization rather than object authorization?

An identifier alone remains a hypothesis surface and cannot become a BOLA Potential Finding.

## Dedicated analyzer: BFLA

The second production-routed analyzer is `family_analyzers.bfla.BflaFamilyAnalyzer`.

Primary reasoning references:

- CWE-862 — Missing Authorization
- CWE-285 / CWE-863 / CWE-269 as related authorization and privilege concepts
- OWASP API5:2023 — Broken Function Level Authorization
- WSTG-ATHZ-02 — Testing for Bypassing Authorization Schema
- WSTG-APIT-04 — API Broken Function Level Authorization

The BFLA algorithm separates six questions:

1. **Function inventory** — Is the surface actually role-, group-, permission-, scope-, or administration-sensitive?
2. **Role/function matrix** — Which role or permission is expected to invoke the exact function and HTTP operation?
3. **Vertical comparison** — What happens for explicitly authorized lower- and higher-privilege test contexts?
4. **Method/scope differential** — Can a weaker permission or alternate method reach a more privileged effect?
5. **Behavioral decision** — Did a context explicitly expected to be denied successfully invoke the function, and did the privileged effect occur when that distinction matters?
6. **Contradiction / false-positive check** — Is server-side role/permission enforcement observed, is the lower role denied, is the function intentionally shared/no-op, or is the signal better explained by BOLA or property authorization?

An `/admin` route, privileged-looking label, UI visibility, or authentication hint alone is not BFLA confirmation.

### BFLA real-world pattern library

Current non-evidentiary patterns include:

- a group-membership function guarded by a weaker update permission instead of a manage-users permission;
- an alternate POST function with a weaker permission than the stricter administrative permission used for the equivalent destructive action;
- a sensitive function whose handler omits the expected server-side authorization call.

These patterns are derived from public security research/write-ups and are used only to shape reasoning, false-positive review and next-evidence planning. They never become supporting target evidence.

## Write-up pattern library

Family analyzers may use either the shared non-evidentiary corpus in `vulnerability_knowledge.py` or family-specific curated pattern records.

A matched write-up only tells the analyst which known pattern the stored target evidence resembles. It never adds support evidence, satisfies admission, or raises target-evidence confidence.

## Compatibility

`app/bola_intelligence.py` remains the BOLA public compatibility import surface.

For Candidate Engine integration, the historical implementation is preserved in `app/bug_candidates_core.py`; public `app/bug_candidates.py` is an additive compatibility/integration wrapper. BFLA target evidence is enriched by the dedicated analyzer before the existing `record_hypothesis → Family Reasoning admission → promotion` flow. Other families remain delegated unchanged until their dedicated analyzer migration is complete.

## Router status

Currently production-routed:

1. BOLA / IDOR
2. Broken Function Level Authorization

Pending dedicated analyzers: 19.

## Migration order

Next analyzers will be added independently for:

1. Mass Assignment / Property Authorization
2. Authentication / Session
3. Account Enumeration
4. DOM XSS
5. postMessage Trust
6. Open Redirect
7. SSRF
8. File Upload / Import
9. Path Traversal
10. Information Disclosure
11. Source-map Exposure
12. Secret Exposure
13. GraphQL Authorization
14. GraphQL Data Exposure
15. Business Logic
16. Race Condition
17. WebSocket Authorization
18. CORS
19. Sensitive Caching

Each migration must add a dedicated analyzer, source-specific reasoning rules, false-positive tests, admission/confirmation regression coverage, production routing and CI before the router is allowed to register that family.
