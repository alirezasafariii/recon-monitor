# Operations Center

The Operations Center groups daily operational information by decision importance.

## Program health

Health combines:

- SQLite integrity and foreign-key status
- Failed stage history
- Backup availability and verification
- Latest run operational completeness
- Engine quality warnings
- Plugin health
- Storage status

## Scope Center

Scope snapshots show roots, inclusions, exclusions, active modules, request limits, and authorization confirmation. Active modules still require runtime authorization gates.

## Run completeness

Completeness reports whether expected pipeline stages completed. It is an operational collection score, not an estimate of the percentage of the internet or target that was discovered.

## Schedule and notification policy

The platform stores per-target cadence, request budget, maximum runtime, quiet hours, and event notification mode. Actual recurring execution continues to use the existing Service/LaunchAgent workflow.

## Storage

Storage Health reports database, object store, outputs, reports, logs, and backups. Retention preview protects confirmed evidence and recommends a dry run before deletion.

## Delivery workers

Operations Center includes one control-plane view for durable Finding and Recon Alert delivery. It shows queue depth, due-now work, retry backlog, dead letters, worker policy, and the latest worker run for both queues. Operators can configure, run, bounded-drain, and retry each worker independently. The two outboxes and their domain lifecycle semantics remain separate. See `docs/NOTIFICATION_OPERATIONS_CENTER.md`.

## Notification supervisor

The Unified Notification Supervisor is the execution coordinator above those two independent workers. It has a database-backed single-instance lease, renewable heartbeat, crash/restart recovery, per-cycle history, failure isolation, and earliest-next-due visibility. Operations Center consumes this supervisor health alongside the existing worker diagnostics. See `docs/NOTIFICATION_SUPERVISOR.md`.


## Delivery SLOs

Operations Center evaluates configurable delivery SLOs for oldest pending age, queue backlog, dead letters, supervisor heartbeat freshness, and consecutive worker/supervisor failures. Breaches have durable open/resolved lifecycle state, severity, duration, occurrence counts, transition history, deduplication, and cooldown. SLO state is operational only and never rewrites Finding, Admission, Recon Alert, retry, or successful-delivery truth. See `docs/NOTIFICATION_DELIVERY_SLO.md`.
