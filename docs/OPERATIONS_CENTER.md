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
