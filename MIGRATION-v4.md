# Migration to 4.0.0

- Database schema upgrades from 7 to 8 automatically when the CLI, dashboard or API opens the database.
- Migration is additive: no existing table or row is removed.
- The patch takes a program backup and SQLite snapshot before replacing files.
- Existing configuration, policies, output, reports, logs, objects, plugins, secrets, users, alerts, notes, tags and evidence remain in place.
- Analysis of old runs is optional and offline:

```bash
./recon-monitor.sh analysis replay --run RUN_ID
```
