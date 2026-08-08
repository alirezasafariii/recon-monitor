# Migration to Recon Monitor 8.2.0

Recon Monitor 8.2.0 is a Dashboard/decision-workflow upgrade. The database schema remains **16**.

## What changes

- Command Center becomes a ranked Decision Inbox.
- The highest-value next action is surfaced explicitly.
- Material re-check changes and recent run activity are visible without opening specialist tools.
- Four primary workspaces remain Recon, Analysis, Potential Findings and Alerts.

## Upgrade

```bash
./recon-monitor.sh update check
./recon-monitor.sh update install
```

The updater creates backups before replacement and retains rollback behavior.
