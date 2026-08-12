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

## Completed analyzer set

The production router covers all canonical vulnerability families in `FAMILY_ORDER`:

1. BOLA / IDOR
2. Broken Function Level Authorization
3. Mass Assignment / Object Property Authorization
4. Authentication / Session
5. Account Enumeration
6. DOM-based XSS
7. postMessage Trust / Web Messaging
8. Open Redirect / Navigation Injection
9. Server-Side Request Forgery (SSRF)
10. File Upload / Import
11. Path Traversal
12. Information Disclosure
13. Source-map Exposure
14. Secret Exposure
15. GraphQL Authorization
16. GraphQL Data Exposure
17. Business Logic
18. Race Condition
19. WebSocket Authorization
20. CORS Misconfiguration
21. Sensitive Caching

## Completion status

Production-routed analyzers: **21 / 21**.

Pending dedicated analyzers: **0**.

Generic Family Analyzer fallback: **disabled**.

Business Logic and Race Condition use the offline `workflow_intelligence` substrate for stored workflow correlation, but retain separate family-specific direct-evidence and contradiction contracts. `remaining_common` provides shared normalization and policy-state handling only and is not itself a registered analyzer.

Static GraphQL and WebSocket direct-candidate bypasses are closed and routed through hypothesis-first handling. GraphQL/WebSocket/cache protocol findings remain correlation surfaces instead of bypassing Family Reasoning.

Knowledge/write-up similarity remains non-evidentiary for every family. Dedicated Family Analyzer migration is complete; subsequent work is calibration, shared-pipeline cleanup and evidence-quality refinement rather than adding missing family algorithms.
