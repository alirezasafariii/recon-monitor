# Migration to Recon Monitor 4.5.1

Version 4.5.1 is a stabilization update for 4.5.0. Database schema remains 11.

## Preserved data

Runs, alerts, candidates, analyst decisions, behavioral snapshots, notes, tags, users, tokens, reports, evidence, policies, configuration, Telegram settings, and object storage are preserved.

## After upgrade

```bash
./recon-monitor.sh --version
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
./recon-monitor.sh doctor --no-network
./recon-monitor.sh repair --dry-run --json-health
./recon-monitor.sh backup verify latest
```

Expected version: `4.5.1`  
Expected schema: `11`  
Expected unit tests: `71`

## New commands

```bash
./recon-monitor.sh repair --dry-run --json-health
./recon-monitor.sh repair --max-age-hours 24
./recon-monitor.sh backup verify latest
./recon-monitor.sh backup drill latest
```

No network recon or active security testing is performed by repair, backup verification, or restore drill.
