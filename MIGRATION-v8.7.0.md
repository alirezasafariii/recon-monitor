# Recon Monitor 8.7.0 Migration

Recon Monitor 8.7.0 is an application-only upgrade. The database schema remains **18**, so no destructive or structural database migration is required from 8.6.0.

## What changes

- Recon and Analysis gain live progress/health visibility in the Dashboard.
- New Analysis runs record an independent heartbeat and phase-aware progress state under `state/progress/`.
- Recon progress reuses existing stage heartbeats and real counters where denominators are known.
- Evidence completion now includes Collection Quality, Evidence Coverage, an Evidence Completion Planner, a Validation Eligibility Gate, Validation Runner dry-run contracts, and an explicitly approved bounded passive-live executor.

## Existing running Analysis jobs

An Analysis process that was already running before the 8.7.0 code was installed cannot gain the new in-process heartbeat retroactively. It is shown as a conservative `legacy` run: recent persisted database activity may be used as a liveness hint, but the dashboard will not fabricate a precise late-stage percentage. New or restarted Analysis runs receive full progress/heartbeat instrumentation.

## Safety and evidence semantics

- Progress is observability only and does not alter Recon results, Analysis evidence, hypotheses, Alerts, Admission, or Candidate promotion.
- Collection completeness informs uncertainty; it never satisfies Admission.
- `not_collected` and `unknown` are not negative target evidence.
- The passive-live executor remains limited to eligible `passive_live` contracts with explicit operator confirmation and `--allow-live`.
- Executor observations are redacted and are not typed evidence; canonical Admission remains the only authority that can admit a Potential Finding.

## Upgrade

Use the normal Recon Monitor update workflow or update the checkout to the `v8.7.0` release, then run:

```bash
./recon-monitor.sh doctor
./recon-monitor.sh test
```

No database migration command is required beyond the normal startup/setup compatibility checks.
