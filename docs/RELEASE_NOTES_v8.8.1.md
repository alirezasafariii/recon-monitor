# Recon Monitor 8.8.1 — Correctness, Replay Integrity & Multi-target Reporting

Recon Monitor 8.8.1 is a correctness-focused patch over 8.8.0. It tightens dependency semantics, cloud-storage evidence transport, backup portability, replay determinism, notification lease ownership, bounded raw-analysis coverage, and multi-target reporting without changing the platform's authorization or vulnerability-confirmation boundaries.

## Dependency and cloud evidence correctness

npm partial hyphen ranges now follow npm/node-semver semantics for incomplete endpoints. For example, `1.2 - 2.3` admits stable `2.3.x` releases but excludes `2.4.0`; prereleases remain fail-closed unless explicitly admitted.

S3/GCS public-listing evidence no longer treats generic XML success responses or metadata subresources as proof of listing. The normal httpx fingerprint path now extracts only the first XML body element at the HTTP body boundary and persists it as `response_xml_root`, allowing a real `ListBucketResult` to survive collection → fingerprint storage → Analysis without retaining the full body.

## Portable backup restore

Restoring a backup into a different project root rebases persisted JavaScript and evidence blob paths to the destination root. Restore fails closed when a referenced path cannot be mapped safely. Content-addressed object-store paths remain relative.

## Deterministic replay and calibration

Replay preserves `evaluation_role` and `source_corpus_id`, snapshots `entity_tags`, and rejects legacy snapshots that would otherwise mix historical raw inputs with live business context.

Behavioral comparison baselines are bound to the original source run and target scope, so replay cannot silently compare a run to its own previous analysis and erase a historical boundary regression.

Calibration now uses a consistent Decision Readiness score space and corrected bin boundaries.

## Delivery lease ownership

Finding notification and Recon Change Alert workers must still own the current lease before finalizing outbox state, mutating delivery/event state, or incrementing delivery counters. Stale workers fail closed.

## Bounded raw Analysis and multi-target reporting

The 5,000-surface guard remains an operational limit, but selection is source-balanced and coverage now distinguishes eligible input, loaded input, selected surfaces, and analyzer execution.

Multi-target reports persist and expose target-scoped routing and budget telemetry. Replay comparisons are restricted to the same source run and Analysis scope. Shared analyzer-budget capacity is reported from analysis-wide consumption while target-local consumption remains separate.

Budget telemetry explicitly distinguishes `target_exhausted` from `analysis_exhausted`; the legacy `exhausted` field remains for backward compatibility and is accompanied by `exhausted_scope`.

## Compatibility

- Application version: **8.8.1**
- Core database schema: **18**
- Upgrade from 8.8.0: backward-compatible core schema; additive feature compatibility updates
- Legacy Analysis snapshots predating immutable entity-tag capture must be regenerated before replay
- httpx must support `-er` for the fingerprint XML-root evidence path
- No destructive core migration required
- Python CI matrix: 3.11 and 3.13

Release publication should use the exact commit that passes strict manifest validation, release consistency, dependency-range coverage, the complete unit suite, and integration tests.
