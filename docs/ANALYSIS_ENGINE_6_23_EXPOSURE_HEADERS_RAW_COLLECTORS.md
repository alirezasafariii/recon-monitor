# Analysis Engine 6.23 — Information Disclosure / CORS / Sensitive Caching raw collectors

Analysis 6.23 physically decomposes the final three inline exposure/header families from the alert-orchestrator monolith: `information_disclosure`, `cors_misconfiguration`, and `sensitive_caching`.

All three retain the mandatory four-layer grounding contract: OWASP WSTG testing semantics, OWASP Top 10 risk taxonomy, MITRE CWE weakness taxonomy, and a real vulnerability write-up. None of these knowledge sources count as target evidence.

- Information disclosure: WSTG-ERRH-01/02, OWASP A01:2025, CWE-200, and GHSL-2026-037 Wekan. Sensitive-looking names are hypothesis surfaces only; actual public/unauthorized/unintended response exposure is required.
- CORS: WSTG-CLNT-07, OWASP A02:2025, CWE-942, and GHSL-2024-162 rembg. An unsafe origin pattern is insufficient without credentialed/authenticated or observed sensitive cross-origin exposure.
- Sensitive caching: WSTG-ATHN-06, OWASP A06:2025, CWE-524/CWE-525, and CVE-2024-45314 Flask-AppBuilder. Analysis 6.23 adds an explicit `browser_cache_no_store_missing` condition so the engine models the WSTG/CWE browser-cache weakness directly. Missing `no-store` is not enough by itself; the stored response must be sensitive or authenticated. `no-store`, `private`, and auth-aware `Vary` are retained as blocking controls.

The collector is metadata-only. Target evidence remains owned by passive execution/reconstruction and family admission. No cross-origin requests, cache poisoning, credential use, or active exploitation are introduced.
