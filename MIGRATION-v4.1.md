# Migration to 4.1.0

Recon Monitor 4.1.0 adds Bug Candidate Engine and upgrades the SQLite schema from 8 to 9.

The migration is additive. Existing runs, alerts, notes, tags, evidence, users, tokens, policies, reports, and analysis results are retained.

A new `bug_candidates` table and indexes are created. Existing completed runs can be processed without network activity:

```bash
./recon-monitor.sh analysis replay --run RUN_ID
```

Candidate generation is automatic during `analyze` and `analysis replay`. Prior analyst decisions are carried into later replays when the stable candidate fingerprint matches.
