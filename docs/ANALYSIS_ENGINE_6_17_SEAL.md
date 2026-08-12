# Analysis Engine 6.17 — Seal

Analysis 6.17 is sealed after the physical raw-collector cutover for Broken Function Level Authorization and Mass Assignment / Broken Object Property Level Authorization.

## Sealed version lineage

- Analysis engine: `6.17.0`
- Candidate engine: `6.17.0`
- Security reasoning engine: `6.17.0`
- Rule lineage: `2026.08.12.6.17`
- Authorization collector rule lineage: `2026.08.12.6.17`

The application release version remains independent from the Analysis Engine version.

## End-to-end seal contract

The seal requires both migrated authorization families to travel through the physical authorization collector into the hidden-hypothesis/admission path and, when decisive stored target evidence is present, into a promoted candidate. The resulting hypothesis and candidate must retain `raw-collector-authorization-v1` in rule lineage.

The seal also requires surface-only cases to remain non-admitted under the existing family-specific admission contract. No admission thresholds, detector conditions, ranking weights, or active-validation behavior are changed by sealing.

## Validation boundary

The seal is a regression and architecture claim, not a new accuracy claim. It is validated by the dedicated 6.17 seal test, the authorization collector contract, the full unit suite, the strict Golden analysis benchmark, and the integration runner. A new fresh raw holdout is intentionally deferred until further physical collector decomposition is complete.

## Next migration boundary

The next physical decomposition batch should target the remaining file/remote-resource raw collectors, beginning with File Upload, Path Traversal, and SSRF while preserving their existing detector-execution and admission contracts.
