# Stability and Recovery — Recon Monitor 4.5.1

Recon Monitor 4.5.1 is a schema-compatible stabilization release for 4.5.0. It does not add active scanning or automatic vulnerability confirmation.

## Defensive legacy-data handling

Stored JSON can originate from older releases, interrupted writes, external plugins, or manual imports. Core analysis, reporting, evidence export, plugin health, API work queues, and resume paths now use defensive decoding for NULL, malformed JSON, and unexpected container types. The original row is preserved for investigation.

## Analysis failure finalization

Unexpected parser or engine failures now mark the corresponding `analysis_runs` row as `failed`, set `finished_at`, save a bounded error message, and write an `analysis_failed` audit event. Partial analysis evidence remains available for diagnosis.

## State repair

Preview only:

```bash
./recon-monitor.sh repair --dry-run --json-health
```

Repair entries older than 24 hours:

```bash
./recon-monitor.sh repair --max-age-hours 24
```

The repair command can finalize stale analysis/stage/run rows and return interrupted persistent work items to `retry_pending`. It refuses to modify state while a live recon process owns the run lock unless `--force` is explicitly supplied. A successful repair also runs SQLite optimization and a passive WAL checkpoint.

## Backup verification and restore drill

```bash
./recon-monitor.sh backup verify latest
./recon-monitor.sh backup drill latest
```

Verification checks the outer archive hash, safe member paths, manifest presence, every declared file hash, SQLite integrity, and foreign-key consistency. The drill extracts the backup to an isolated temporary directory and opens the restored database without changing the active installation.

Actual restore still requires an explicit backup ID and `--force`:

```bash
./recon-monitor.sh backup restore BACKUP_ID --force
```

Before replacement, Recon Monitor creates a safety backup, closes the live WAL-backed database connection, atomically installs the restored database, removes stale WAL/SHM files, reopens the database, and validates integrity and foreign keys.

## Doctor additions

Doctor now checks the current schema version, full and quick database integrity, foreign-key violations, stale execution state, and a sample of stored JSON fields.

## Schema

Schema remains **11**. All tables and historical data are retained.
