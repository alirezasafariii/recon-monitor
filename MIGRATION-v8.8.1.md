# Recon Monitor 8.8.1 Migration

Recon Monitor 8.8.1 is a backward-compatible correctness and reliability update from 8.8.0. The core database schema remains **18**. New or revised feature metadata remains additive and independently versioned.

## What changes

- npm partial hyphen ranges now follow npm/node-semver incomplete-bound semantics.
- S3/GCS public-listing evidence is fail-closed and the XML root required for a real listing survives the normal httpx fingerprint path without storing full response bodies.
- backup restore rebases persisted artifact paths when restoring into a different project root.
- Analysis replay preserves corpus/evaluation metadata, uses immutable input snapshots, includes entity tags, and keeps behavioral comparison baselines stable across replay.
- calibration uses one consistent Decision Readiness score space and corrected bin boundaries.
- Finding and Recon Alert delivery finalization requires current lease ownership.
- raw-surface selection remains bounded but is source-balanced, with explicit eligible/loaded/selected coverage telemetry.
- multi-target Analysis quality, replay comparison, analyzer-budget capacity, and exhaustion telemetry are target/scope aware.

## Database and replay compatibility

No destructive core migration is required. `SCHEMA_VERSION` remains **18**.

Analysis input snapshots now use the newer compatibility snapshot contract that includes `entity_tags`. Legacy snapshots that predate immutable tag capture are intentionally rejected for historical replay instead of silently mixing old raw inputs with current live business-context tags. Run a fresh scan to create a current replayable snapshot when this occurs.

Additional compatibility tables/columns and metadata used by replay, fingerprint evidence, notification leases, and reporting are initialized idempotently through normal startup/database initialization.

## Tool compatibility

The normal fingerprint path now relies on httpx regex extraction support (`-er`) to retain bounded XML-root structure for XML responses. `./recon-monitor.sh doctor` checks this capability. If doctor reports an incompatible httpx build, update httpx before relying on S3/GCS listing evidence through the fingerprint path.

No additional target-side request is introduced by this change; the XML root is derived from the existing fingerprint response.

## Backup and notification behavior

Cross-root restores rebase persisted artifact/evidence paths to the destination root and fail closed if a referenced path cannot be mapped safely.

Finding and Recon Alert outbox workers may contact a transport while holding a lease, but they cannot finalize event/delivery state after losing that lease.

## Upgrade

Use the normal Recon Monitor update workflow or update the checkout to the `v8.8.1` release, then run:

```bash
./recon-monitor.sh doctor
./recon-monitor.sh test
```

No manual core database migration command is required beyond normal startup/setup compatibility checks.
