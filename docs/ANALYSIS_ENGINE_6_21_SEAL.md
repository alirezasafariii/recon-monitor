# Analysis Engine 6.21 — Seal

Analysis 6.21 seals the Business Logic / Race Condition physical-collector cutover.

- Analysis Engine: `6.21.0`
- Candidate Engine: `6.21.0`
- Security Reasoning Engine: `6.21.0`
- Shared rule lineage: `2026.08.12.6.21`
- Business Logic collector rule lineage: `2026.08.12.6.21`

The two families remain explicitly grounded in WSTG, OWASP Top 10:2025, MITRE CWE, and the exact GHSL-2025-038 Branch Deploy Action primary advisory. External knowledge remains detector knowledge only and cannot become target evidence.

Business Logic requires observed workflow/value/state invariant failure; Race Condition requires observed duplicate/atomicity/concurrency effects. Mere endpoint names, business-flow semantics, or single-use operations remain hidden hypotheses until decisive target evidence exists.

Full unit regression, strict Golden benchmark, and integration validation are required before the seal commit is created.
