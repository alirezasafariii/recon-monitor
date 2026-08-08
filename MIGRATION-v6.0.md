# Migration to Recon Monitor 6.0.0

## Supported source versions

The release patch accepts Recon Monitor `5.0.1`, `5.1.0`, `5.1.1` and `6.0.0`.

## Database migration

Schema moves additively to version `15`. Existing runs, alerts, candidates, analyst decisions, cases, validation plans, evidence, reports, users, tokens, policies and plugins are preserved.

New records include validation intelligence, revalidation policies, data-quality snapshots, review rankings, Burp round-trip packages/results, story links, schedule jobs, notification events, retention state, performance samples, template applications, report-quality snapshots, security-posture snapshots and audit-integrity hashes.

## Recommended procedure

```bash
cd ~/Downloads/recon-monitor
./recon-monitor.sh backup create --include-objects
./recon-monitor.sh backup verify latest
```

Run the supplied patch, then verify:

```bash
./recon-monitor.sh --version
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
./recon-monitor.sh suite security-posture
./recon-monitor.sh dashboard restart --open
```

Expected version: `6.0.0`  
Expected schema: `15`

## Post-migration initialization

Refresh all platform snapshots:

```bash
./recon-monitor.sh platform sync
```

Review data quality and ranking:

```bash
./recon-monitor.sh suite data-quality
./recon-monitor.sh suite review-queue --apply
```

Create a schedule only after reviewing its existing target policy:

```bash
./recon-monitor.sh platform schedule-set \
  --target example.com \
  --cadence 3h \
  --quiet-hours 22:00-07:00

./recon-monitor.sh suite schedule-sync --target example.com
```

Applying the generated LaunchAgent requires macOS and an explicit `--apply`.

## Security defaults

The upgrade preserves `config.env`; it does not silently enable authentication, active modules or network validation. New installations use the hardened example configuration. Run `suite security-posture` to identify settings requiring attention.

## Rollback

The supplied patch creates program and SQLite backups before replacement. If compile, schema, integrity, foreign-key, test or integration checks fail, it restores the previous program and database.
