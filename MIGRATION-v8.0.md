# Migration to Recon Monitor 8.0.0

Recon Monitor 8.0.0 is a product/UX release built on the v7 intelligence and safety architecture.

## What changes

- The Dashboard primary navigation is organized into four workspaces: Recon, Analysis, Potential Findings, and Alerts.
- Recon findings use unified search/filter controls.
- Analysis findings use structured severity/confidence/target/score filters.
- Potential Findings is the analyst-facing candidate triage surface.
- Alerts compares later successful recon runs against a target baseline and surfaces new or materially changed attack-surface elements.

## Compatibility

- Database schema remains `16`.
- Existing v7 workspace commands and the `workspace_v7` compatibility module remain supported.
- No destructive database migration is required.
- Existing targets, runs, cases, evidence, candidates, and validation records are retained.

## Verify after upgrade

```bash
./recon-monitor.sh --version
./recon-monitor.sh doctor
./recon-monitor.sh workspace sync
./recon-monitor.sh dashboard restart --open
```

Expected application version: `8.0.0`. Expected schema: `16`.
