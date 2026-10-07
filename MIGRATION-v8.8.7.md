# Recon Monitor 8.8.7 — DNS Observation Integrity

Application version: **8.8.7**. Database schema: **18**, unchanged.

This release prevents DNS records from being falsely retired when dnsx exits successfully but returns no observation for a host. Finalization is scoped to explicitly observed host/record-type pairs. Empty output, warning-only output, SERVFAIL/REFUSED, malformed values and missing hosts preserve previous records. Explicit NOERROR/NODATA and NXDOMAIN permit retirement only for the queried pair.

Collection metrics distinguish process completion from semantic coverage. Zero observations result in partial collection and are ineligible to replace a successful baseline. Plain wildcard-filter omissions are ambiguous: previous wildcard state is preserved and classification is reported incomplete rather than guessing from missing lines.

Install through the normal updater with a full backup and checksum verification. No timeout increase, external-tool upgrade or database migration is required. Existing httpx header fixes and dashboard behavior remain included.

Historical false removals and incorrect wildcard flags are not automatically repaired. Preserve raw artifacts and backups for a separately reviewed recovery; immutable Analysis snapshots remain historical evidence. No target scan is required for installation.

Validation includes offline zero-output and warning-only 100-host failures, 99/100 coverage, explicit negative answers, resolver failures, malformed values, scoped retirement, preserved wildcard state and baseline exclusion.
