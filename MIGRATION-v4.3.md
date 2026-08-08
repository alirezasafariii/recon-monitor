# Migration to 4.3.0

Recon Monitor 4.3.0 combines Candidate Reliability Engine 4.2 and Semantic Candidate Intelligence 4.3. It upgrades SQLite schema from 9 to 10.

## Migration behavior

The migration is additive. It preserves existing:

- targets and policies;
- runs and stage results;
- assets, URLs, JavaScript, endpoints, DNS, HTTP/TLS, and evidence;
- alerts, incidents, notes, tags, and workflow history;
- analysis runs, hypotheses, clusters, and Bug Candidates;
- candidate analyst decisions;
- users, API tokens, Dashboard settings, and audit records.

Existing `bug_candidates` rows gain reliability, lifecycle, profile, evidence-group, and bundle fields. New semantic, calibration, feedback, evaluation, and bundle tables are created.

## Offline re-analysis

Old completed runs can be replayed without new network activity:

```bash
./recon-monitor.sh analysis replay \
  --run RUN_ID \
  --profile balanced
```

A replay creates a new analysis record. Existing analysis records and candidate decisions remain in the database. Stable candidate fingerprints are used to carry compatible analyst decisions forward.

## Verification

```bash
./recon-monitor.sh --version
sqlite3 state/recon-v2.db \
  "SELECT value FROM schema_meta WHERE key='schema_version';"
./recon-monitor.sh test --verbose
```

Expected values:

```text
4.3.0
10
Ran 54 tests
OK
```

## Rollback note

The supplied patch creates a program backup and a SQLite snapshot before migration. Program rollback to a release that only understands schema 9 should use the matching pre-upgrade SQLite snapshot as well as the previous program files.
