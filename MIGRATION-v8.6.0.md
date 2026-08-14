# Recon Monitor v8.6.0 Migration

## Scope

v8.6.0 completes the raw-first Vulnerability Intelligence path and the intended baseline/Alert lifecycle. Database schema remains 18; no destructive migration or historical-data rewrite is required.

## Analysis behavior

Analysis no longer requires an Alert row. Every successful run resolves its target from the source run and processes stored raw Recon observations, semantic JavaScript intelligence, behavioral history, dedicated family analyzers, family admission, Potential Findings, reasoning, and workspace synchronization.

Raw endpoint, HTTP/TLS fingerprint, and DNS CNAME context is routed conservatively. The router is bounded and offline-only. It may create hidden hypotheses, but it never synthesizes bypass, execution, claimability, or other decisive evidence. OWASP/WSTG/CWE/CAPEC and write-up knowledge remain classification/retrieval context only.

## Alert lifecycle

- First successful scan: full Recon and Analysis, baseline saved, no Alert rows, no Alert notifications.
- A failed or partial first attempt does not activate Alerting; the target remains in baseline mode until one target pipeline finishes successfully.
- Second and later scans: Alerts are created only from new or materially changed observations emitted by the run-to-run comparison.
- Existing `ALERT_ON_BASELINE` configuration is intentionally ignored and has been removed from the example configuration because baseline Alert creation is no longer supported.

## Compatibility

- Application: 8.6.0
- Database schema: 18
- Analysis engine: 6.0.0
- Candidate engine: 6.0.0
- Candidate family integration: 4.0.0
- Canonical vulnerability families: 74
- Generic family-analyzer fallback: disabled
