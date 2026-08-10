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

## Write-up pattern library

The analyzer reuses the non-evidentiary write-up corpus from `vulnerability_knowledge.py`. The current BOLA patterns include examples such as:

- missing secondary ownership/access guard;
- missing group/role object guard;
- parent/child identifier not bound to the authorized parent;
- tenant/object mismatch across organizational boundaries.

A matched write-up only tells the analyst which known pattern the stored target evidence resembles. It never adds support evidence.

## Compatibility

`app/bola_intelligence.py` remains the public compatibility import surface. Existing Candidate Engine callers still use `analyze_bola_signal`; that symbol now routes through the dedicated BOLA analyzer while preserving historical BOLA engine and rule versions.

## Migration order

After the BOLA reference implementation is stable, analyzers will be added independently for:

1. Broken Function Level Authorization
2. Mass Assignment / Property Authorization
3. Authentication / Session
4. Account Enumeration
5. DOM XSS
6. postMessage Trust
7. Open Redirect
8. SSRF
9. File Upload / Import
10. Path Traversal
11. Information Disclosure
12. Source-map Exposure
13. Secret Exposure
14. GraphQL Authorization
15. GraphQL Data Exposure
16. Business Logic
17. Race Condition
18. WebSocket Authorization
19. CORS
20. Sensitive Caching

Each migration must add a dedicated analyzer, source-specific reasoning rules, false-positive tests, admission/confirmation regression coverage, and CI before the router is allowed to register that family.
