# Recon Monitor 8.9.0 — Delivery Reliability & Operational Intelligence

## Highlights

Recon Monitor 8.9.0 completes the notification reliability path introduced after 8.8.0.

### Durable Recon Change Alert Delivery

- Recon Change Alerts use a durable outbox path independent from Finding notifications.
- Added retry, leases, worker history, bounded drain, retry operations and dead-letter recovery.
- Preserved baseline suppression, cooldown, score threshold, confirmed-only filtering and alert lifecycle semantics.

### Unified Notification Operations

- Added a Notification Supervisor coordinating Finding and Recon Alert workers.
- Added single-instance ownership, heartbeat tracking, crash recovery and worker failure isolation.
- Operations Center exposes combined delivery visibility while keeping worker state independent.

### Delivery SLO Monitoring

- Added healthy/warning/critical delivery health states.
- Added monitoring for backlog age, queue growth, dead letters, stale heartbeat and repeated failures.
- Added durable breach lifecycle with deduplication and cooldown.

## Compatibility

- Core database schema remains 18.
- No destructive migration is required from 8.8.0.
- Finding, Admission and Recon lifecycle semantics remain unchanged.
