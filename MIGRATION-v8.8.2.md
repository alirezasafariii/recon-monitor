# Recon Monitor 8.8.2 Migration

Recon Monitor 8.8.2 is a reliability update from 8.8.1. The core database schema remains **18**. Feature compatibility metadata and legacy PostgreSQL mirror-key migration initialize through the normal startup paths.

## Upgrade

Use the existing authenticated GitHub update workflow to install `v8.8.2`, or update the checkout to that release. The packaged assets are `recon-monitor-v8.8.2.zip` and its matching `.zip.sha256` sidecar. Keep the normal Update backup and staged-install workflow in place.

Update remote workers with their coordinator before resuming distributed work. Older workers can fail the newer scope/result/artifact compatibility checks instead of returning misleading successful work.

## Saved Runs and Analysis

Partial collector output remains usable by downstream stages, but partial Runs do not establish a successful comparison baseline. Resume refreshes Analysis input snapshots and affected downstream stages when collection changes.

Analysis snapshots that predate immutable entity-tag capture still require regeneration before historical replay. New input snapshots exclude tags produced by Analysis itself. Legacy Runs without `run_targets` records can continue Analysis/platform synchronization, but their data-quality result is explicitly unavailable.

JavaScript and source-map work resume independently. Missing or invalid worker artifacts are not accepted solely because the work item was previously marked complete.

## API lifecycle and read responses

New local API instances stop through their instance-specific control channel on Linux and macOS. Legacy instances require validated Linux pidfd handling; non-Linux legacy instances are not stopped by signalling an unverified PID. Start a new API instance after updating to use the portable control path.

Clients reading `/case`, `/evidence/export`, or `/api/v1/suite/data-quality` should handle HTTP 400/404 request/no-data responses. Valid requests retain their normal HTML, ZIP, and JSON formats.

## Checks

After installation, run the existing local checks:

```bash
./recon-monitor.sh --version
./recon-monitor.sh doctor
./recon-monitor.sh test
```

The reported version should be `8.8.2`. No manual core database migration or new target scan is required by this upgrade. Existing authorization, target scope, and configured timeout settings remain in effect.
