# Analysis Engine 6.18 — Seal

Analysis 6.18 is sealed after the physical raw-collector cutover for SSRF, File Upload, and Path Traversal.

## Sealed lineage

- Analysis engine: `6.18.0`
- Candidate engine: `6.18.0`
- Security reasoning engine: `6.18.0`
- Analysis rule lineage: `2026.08.12.6.18`
- File/remote-resource collector rule lineage: `2026.08.12.6.18`

## Security-knowledge boundary

The three families remain grounded in their physical detector specifications. Each detector must retain WSTG identifiers, CWE identifiers, a family principle, admission-condition signals, and at least one real-world write-up. External standards and write-ups define the detector model but never count as target evidence.

## Validation boundary

The seal requires the dedicated 6.18 collector contract, recall-preserving surface-hypothesis regressions, the complete unit suite, strict Golden benchmark, and integration runner to pass. This is an architecture/regression seal and does not create a new fresh-holdout accuracy claim.

The next collector batch is client-side analysis. That batch will additionally make explicit OWASP category grounding mandatory alongside WSTG, CWE, and write-up grounding.
