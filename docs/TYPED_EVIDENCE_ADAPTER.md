# Typed Evidence Adapter

The Typed Evidence Adapter is the explicit offline boundary between bounded Validation Runner observations and canonical target evidence.

## Trust boundary

`validation runner-execute` remains observation-only. It may perform only the already-approved passive-live request contract and stores bounded, redacted metadata. It does not emit typed evidence, satisfy Admission, or promote a Potential Finding.

`validation runner-adapt` performs no network I/O. It reads one completed `VEX-*` execution from the target run directory, validates that the artifact matches the originating run/target/analysis/hypothesis/family, enforces freshness and redaction invariants, derives narrowly defined family-scoped evidence, and persists provenance in `evidence_records`.

```bash
./recon-monitor.sh validation runner-adapt \
  --run-id RUN_ID \
  --target example.com \
  --execution-id VEX-...
```

The adapter does not confirm vulnerabilities. A Potential Finding can be created only after the derived evidence is passed through the existing Family Reasoning / Canonical Admission path.

## Core passive-live family coverage

Version 1.1 covers all nine `passive_live` families in the core Family Reasoning catalog:

- `cors_misconfiguration`: a controlled Origin accepted by the stored CORS policy can become `untrusted_origin_allowed`; credentialed cross-origin readability is never inferred.
- `source_map_exposure`: `source_map_publicly_reachable` is emitted only when the approved anonymous `.map` observation has source-map structure and independent stored evidence already establishes internal source structure.
- `sensitive_caching`: cache headers, sensitive response-shape markers, private/no-store controls, and user-specific `Vary` controls are typed, but shared-cache or cross-user exposure is never synthesized.
- `information_disclosure`: redacted sensitive-key/category markers enrich the hypothesis, but visibility-boundary exposure is not inferred from field names alone.
- `authentication_session`: authentication surfaces, concrete operations, and anonymous 401/403 boundaries are typed; lifecycle violations, token-rotation failures, recovery bypasses, and post-logout reuse are never inferred.
- `account_enumeration`: authentication/account surface and operation context are typed; identity lookup and response/timing differential require controlled identities and are never synthesized from one request.
- `open_redirect`: stored 3xx `Location` behavior can establish navigation/sink context; acceptance of a user-controlled external destination is never inferred.
- `secret_exposure`: redacted credential-like field/category metadata can establish `secret_pattern` and contextual evidence; credential completeness or liveness is never inferred or validated online.
- `graphql_data_exposure`: redacted sensitive-looking fields on a GraphQL endpoint can establish structural field/operation evidence; excessive exposure or field-authorization differential is never inferred without an explicit policy boundary.

Only CORS and source-map adapters remain promotion-capable in version 1.1, and only when Canonical Admission is satisfied. The other seven adapters are enrichment/contradiction-only and cannot create a new Potential Finding through this adapter.

## Evidence identity and independence

Every signal derived from one Validation Runner execution uses a single evidence root (`validation_execution:<execution_id>`). Multiple signal types from the same request sequence therefore cannot manufacture independent-source count.

Typed `evidence_records` use deterministic IDs and retain the execution ID, contract ID, observation sequence, timestamp, method, URL, adapter/rule versions, and an integrity hash. Raw response bodies and raw sensitive values are not copied into typed evidence.

Applying an unchanged execution twice is idempotent. If an already-adapted execution artifact later changes, adaptation fails closed rather than accepting mutable evidence.

## Freshness and failure behavior

By default, an execution must be no older than 24 hours when it is adapted. Stale, malformed, duplicated, mismatched, non-completed, non-redacted, or unsupported-family artifacts fail before typed evidence is persisted.

The feature uses an additive compatibility table, `typed_evidence_adapter_runs`, with independent metadata key `typed_evidence_adapter_schema_version`. It does not change the core SQLite `SCHEMA_VERSION`.
