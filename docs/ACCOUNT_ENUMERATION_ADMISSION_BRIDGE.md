# Account Enumeration Admission Bridge

This component is an offline bridge between previously reviewed controlled-identity evidence and the existing Canonical Admission path for `account_enumeration`.

## Trust boundary

The bridge does not execute network requests, generate identities, submit authentication or recovery requests, or inspect real-user identifiers. It accepts only a `CID-*` record that has already passed the controlled-identity differential reviewer and whose persisted evidence integrity still matches the reviewed artifact.

Eligible review evidence must be direct `controlled_identity_response_difference` support from `analyst_verified_controlled_identity`. Uniform or confounded comparisons remain ineligible.

## Admission requirements

The linked hypothesis must already be an `account_enumeration` hypothesis and contain independent structural context for an identity lookup plus an authentication/client operation. Existing `uniform_identity_response`, `uniform_identity_timing`, or `rate_limit_confounded` contradictions block the bridge.

When eligible, the bridge adds a family-scoped `identity_response_differential` signal with a distinct provenance group and recomputes Canonical Admission. A Potential Finding is created only if Canonical Admission returns `admitted=true`.

The output never claims a confirmed vulnerability. Analyst confirmation remains a separate lifecycle state.

## Persistence and idempotency

`account_enumeration_admission_bridge_runs` is an additive, self-versioned ledger keyed by `comparison_id`. Reapplying the same reviewed comparison is exactly-once and returns the existing result. The core SQLite `SCHEMA_VERSION` is unchanged.

Candidate evidence is linked back to the reviewed `evidence_records` row so provenance remains auditable.
