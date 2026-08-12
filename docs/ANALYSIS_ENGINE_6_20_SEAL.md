# Analysis Engine 6.20 — Seal

Analysis 6.20 seals the API/configuration physical-collector cutover on a single production lineage:

- Analysis Engine: `6.20.0`
- Candidate Engine: `6.20.0`
- Security Reasoning Engine: `6.20.0`
- Analysis/Candidate/Reasoning rule lineage: `2026.08.12.6.20`
- API/configuration collector rule lineage: `2026.08.12.6.20`

The sealed batch covers OWASP API Security Top 10 API4/API6/API8/API9/API10 families while retaining the global 31-family requirement for WSTG + OWASP + CWE + real write-up grounding.

External standards and write-ups remain knowledge only. They never count as target evidence, satisfy independent-source requirements, or override target-side contradictions. Promotion remains dependent on stored passive target evidence and family-specific admission.

The seal also preserves the earlier raw-routing precision boundary: ordinary API versioning such as `/api/v1` is not, by itself, an inventory-management hypothesis. Inventory routing requires legacy/non-production semantics or explicit target evidence of inventory drift.

Full unit regression, strict Golden analysis benchmark, and integration validation are required before the seal commit can be emitted.
