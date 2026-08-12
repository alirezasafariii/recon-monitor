# Analysis Engine 6.23 Seal

Analysis 6.23 seals the physical decomposition of Information Disclosure, CORS Misconfiguration, and Sensitive Caching after collector, routing-boundary, raw-reconstruction, full-unit, Golden benchmark, and integration validation.

Sealed production lineage:

- Analysis Engine: `6.23.0`
- Candidate Engine: `6.23.0`
- Security Reasoning Engine: `6.23.0`
- Rule lineage: `2026.08.12.6.23`
- Exposure/header collector lineage: `2026.08.12.6.23`

All 31 vulnerability families retain mandatory WSTG + OWASP + CWE + real-write-up grounding. Standards and write-ups remain detector knowledge only and never target evidence.

The seal additionally locks two precision boundaries: route/category words such as `token` do not create Information Disclosure without a stored response/source artifact, and browser-cache promotion requires sensitive/authenticated response context plus an actual cache-isolation weakness such as missing `no-store`; protected `no-store` remains blocking evidence.
