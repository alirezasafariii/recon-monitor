# Migration to Recon Monitor 4.5.0

Version 4.5.0 upgrades Recon Monitor 4.3.1 to the Behavioral Intelligence Engine.

## Database

SQLite schema changes from **10 to 11**. The migration is additive and creates:

```text
behavioral_observations
authentication_boundary_diffs
response_shape_diffs
protocol_findings
identity_entities
identity_relations
```

Existing runs, alerts, candidates, analyst decisions, notes, tags, evidence packages, users, API tokens, policies, and configuration are preserved.

## Important behavior

Behavioral comparison requires at least two completed analysis snapshots containing the same endpoint or response shape. The first analysis after installation may establish only the current behavioral snapshot. Replay the same stored run or analyze a later run to produce cross-analysis diffs.

No new network request is required:

```bash
./recon-monitor.sh analysis replay --run RUN_ID --profile balanced
```

## Verification

```bash
./recon-monitor.sh --version
# 4.5.0

sqlite3 state/recon-v2.db \
  "SELECT value FROM schema_meta WHERE key='schema_version';"
# 11

./recon-monitor.sh test --verbose
# Ran 62 tests ... OK
```

## Rollback

The patch creates a program backup and a SQLite snapshot under:

```text
state/upgrades/v4.5.0-<timestamp>/
```

If compilation, migration, integrity validation, tests, or smoke tests fail, the patch restores both program files and the previous database snapshot.
