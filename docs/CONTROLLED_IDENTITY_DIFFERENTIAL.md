# Controlled Identity Differential Review

This feature is an offline evidence-quality boundary for comparing two explicitly controlled test identities. It is intentionally non-promoting: it does not satisfy Canonical Admission, create a Potential Finding, confirm a vulnerability, or perform any live request.

## Trust boundary

The reviewer accepts only analyst-verified, redacted JSON artifacts. Both observations must be test-controlled, identity values must not be stored, real-user data must not be used, raw response bodies must not be stored, and the artifact must link back to an existing run / analysis / target / hypothesis.

The stored comparison contains only response-profile metadata such as HTTP status, a bounded semantic response class, and a response-shape hash. It never stores username, email, phone number, account ID, or another concrete identity value.

Rate-limit or challenge/captcha confounding is preserved explicitly. A confounded comparison is stored as contextual/contradicting review evidence rather than direct support.

## Offline entrypoint

```bash
python3 tools/review_controlled_identity_differential.py \
  --evidence-file /path/to/controlled-identity-review.json
```

The command opens the local Recon Monitor database only. It has no network transport, credentials, live-execution flag, retry loop, or target mutation path.

## Artifact contract

The artifact uses `version: 1.0.0`, a stable `CID-*` comparison ID, run/analysis/target/hypothesis identity, an operation fingerprint, and two observations:

- `existing_test_identity` with `identity_class: owned_test_existing`
- `absent_test_identity` with `identity_class: synthetic_test_absent`

Both require `controlled_identity: true` and `identity_value_stored: false`. Top-level `controlled_identities_only` must be true, while `real_user_data_used`, `identity_values_stored`, and `raw_body_stored` must be false.

A response-profile difference can be recorded when status, semantic response class, or response-shape hash differs. The reviewer does not decide that this proves a vulnerability; it persists provenance-preserving evidence for later family-specific reasoning.

## Persistence and idempotency

The feature uses the additive table `controlled_identity_differential_runs` with independent metadata key `controlled_identity_differential_schema_version=1`. Core SQLite `SCHEMA_VERSION` is unchanged.

Evidence records use deterministic IDs and retain an integrity hash. Re-applying an unchanged comparison is idempotent. If a previously reviewed artifact changes, the reviewer fails closed.

The review result always reports:

- `affects_admission: false`
- `affects_candidate_promotion: false`
- `network_requests_executed: 0`
- `vulnerability_confirmed: false`
