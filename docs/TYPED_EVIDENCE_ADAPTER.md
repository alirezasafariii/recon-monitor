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

## Differential Evidence v2

Some families require expected-vs-observed evidence that cannot be inferred safely from one passive metadata response. `validation differential-adapt` is a separate offline path for analyst-verified Differential Evidence v2 artifacts.

The first supported differential promotion path is `open_redirect`. It requires an existing structural hypothesis containing both a redirect source and navigation sink, plus a fresh verified artifact showing the reserved controlled destination was accepted. The differential adapter does not generate requests, follow redirects, connect to the destination, or mark a vulnerability confirmed. It only adds a separate provenance root and then delegates the decision to Canonical Admission. See `docs/DIFFERENTIAL_EVIDENCE_V2.md`.

## Evidence identity and independence

Every signal derived from one Validation Runner execution uses a single evidence root (`validation_execution:<execution_id>`). Multiple signal types from the same request sequence therefore cannot manufacture independent-source count.

Typed `evidence_records` use deterministic IDs and retain the execution ID, contract ID, observation sequence, timestamp, method, URL, adapter/rule versions, and an integrity hash. Raw response bodies and raw sensitive values are not copied into typed evidence.

Applying an unchanged execution twice is idempotent. If an already-adapted execution artifact later changes, adaptation fails closed rather than accepting mutable evidence.

Differential Evidence v2 uses its own stable `DEV-*` identity and evidence root. Reapplying an unchanged differential artifact is idempotent; changing an already-applied artifact fails closed.

## Freshness and failure behavior

By default, an execution must be no older than 24 hours when it is adapted. Stale, malformed, duplicated, mismatched, non-completed, non-redacted, or unsupported-family artifacts fail before typed evidence is persisted.

Differential artifacts use the same default 24-hour freshness window and additionally require explicit analyst verification, structural hypothesis context, no stored raw body, and an assertion that the external redirect was neither followed nor contacted.

The typed adapter uses additive compatibility table `typed_evidence_adapter_runs`. Differential Evidence v2 uses `differential_evidence_adapter_runs`. Both maintain independent schema metadata and do not change the core SQLite `SCHEMA_VERSION`.
