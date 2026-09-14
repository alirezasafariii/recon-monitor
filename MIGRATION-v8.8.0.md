# Recon Monitor 8.8.0 Migration

Recon Monitor 8.8.0 is a backward-compatible application upgrade from 8.7.0. The core database schema remains **18**. New reliability, reviewed-evidence, and notification tables use additive, independently versioned feature schemas and are initialized idempotently by normal startup paths.

## What changes

- Recon comparison state is protected by successful-snapshot and explicit baseline/lifecycle boundaries.
- Volatile change confirmation is keyed by observed state version rather than raw event count.
- Passive-live observations can be adapted offline into family-specific typed evidence without new target traffic.
- Controlled reviewed-evidence flows can enter canonical Admission through the generic reviewed-evidence dispatcher.
- Potential Finding notifications use a durable outbox with retry, leases, worker scheduling/watch operation, diagnostics, and dead-letter recovery.
- Recon Change Alerts and Finding notifications share the public notification transport layer while keeping separate lifecycle semantics.

## Database compatibility

No destructive core migration is required. `SCHEMA_VERSION` remains **18**. Feature schemas are additive and self-versioned in compatibility metadata/tables; existing Recon history, baselines, Analysis state, Potential Findings, Alert workflow state, and evidence remain preserved.

Normal startup/setup compatibility checks may create missing additive feature tables or metadata. Failed or interrupted runs do not become canonical comparison baselines.

## Evidence and safety semantics

- Typed and reviewed adapters are offline boundaries; they do not authorize new target-side execution.
- Canonical Admission remains the decision authority for Potential Finding creation/promotion.
- Potential Findings are not automatic vulnerability confirmations.
- Controlled review artifacts remain redaction-first and reject disallowed raw credentials, session material, identities, response bodies, or secret values according to their contract.
- Finding notification delivery failures, retries, and dead-letter operations do not mutate Candidate or Admission truth.
- Recon Change Alerts remain outside the Finding notification outbox.

## Notification worker operations

After upgrade, operators can inspect or run the Finding notification worker with the existing delivery CLI, including `status`, `run`, `watch`, `failed`, `retry`, `drain`, and `configure` operations. Enabling a recurring worker policy remains an explicit operational choice.

## Upgrade

Use the normal Recon Monitor update workflow or update the checkout to the eventual `v8.8.0` release, then run:

```bash
./recon-monitor.sh doctor
./recon-monitor.sh test
```

No manual core database migration command is required beyond normal startup/setup compatibility checks.
