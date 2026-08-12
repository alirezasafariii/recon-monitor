# Analysis Engine 6.24 — Specialized Static Physical Collectors

Analysis 6.24 physically decomposes the remaining static-family ownership from `bug_candidates._static_candidates()` for Source Map Exposure, Secret Exposure, GraphQL Authorization, GraphQL Data Exposure, and WebSocket Authorization.

Unlike the raw collectors, these collectors legitimately extract target evidence from persisted static-intelligence tables (`source_map_intelligence`, `secret_intelligence`, `graphql_intelligence`, and `js_dataflows`). WSTG, OWASP, CWE, and write-ups remain knowledge only and never become target evidence.

Promotion boundaries remain strict:

- Source maps: a `.map` reference or internal-looking paths remain a hypothesis until meaningful source content and verified public reachability are present. Grounding includes WSTG-CONF-04, OWASP A01:2025, CWE-200, and CVE-2024-27257 (IBM OpenPages source-map information exposure).
- Secrets: a redacted pattern in production client JavaScript requires non-placeholder credential evidence; placeholder classification blocks promotion. Grounding includes WSTG-CONF-04, OWASP A07:2025, CWE-798/CWE-200, and GHSL-2026-037 Wekan.
- GraphQL authorization: operation + identifier are only surfaces; resolver/object authorization failure is required. Grounding includes WSTG-APIT-02/ATHZ-02, API1:2023/A01:2025, CWE-862/863, and the concrete Sentry cross-organization authorization failure GHSL-2025-130 as an adjacent object-boundary case.
- GraphQL data exposure: sensitive fields in client operations are schema clues only; actual data crossing the caller's field policy is required. Grounding includes WSTG-APIT-03, API3:2023/A01:2025, CWE-200, and GHSL-2026-035 Wekan.
- WebSocket authorization: WebSocket construction is only a channel surface; channel/identity scope plus observed authorization failure is required. Grounding includes WSTG-CLNT-10/ATHZ-02, A01:2025, CWE-862/863, and the exact GHSL-2025-118 Outline WebSocket authentication-bypass case.

No active subscription, credential validation, object probing, cross-tenant access, or network requests are introduced by this change.
