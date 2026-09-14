# Recon Monitor 8.9.0 Migration

## Compatibility

- Upgrade target: 8.8.0 → 8.9.0
- Core database schema remains 18.
- No destructive migration is required.

## Operational Changes

8.9.0 adds operational capabilities around notification delivery:

- Recon Alert durable delivery
- Unified Notification Supervisor
- Delivery SLO monitoring
- Operations Center delivery health visibility

Existing Finding, Admission and Recon lifecycle state is preserved.
