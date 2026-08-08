# Recon Monitor 7.0 Migration

## Scope

Recon Monitor 7.0 upgrades the application to schema 16. The migration is additive: existing runs, candidates, cases, validation plans, evidence, configuration, scope policy, plugins and artifacts remain intact.

## Before upgrading

```bash
cd ~/Downloads/recon-monitor
./recon-monitor.sh backup create --include-objects
./recon-monitor.sh backup verify latest
./recon-monitor.sh dashboard stop
```

## After upgrading

```bash
./recon-monitor.sh --version
./recon-monitor.sh doctor --no-network
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
./recon-monitor.sh workspace sync
./recon-monitor.sh workspace diagnostics
./recon-monitor.sh workspace safety
./recon-monitor.sh dashboard restart --open
```

Expected version: `7.0.0`. Expected schema: `16`.

## New schema objects

The migration adds persisted workspace intelligence for evidence gaps, autopilot tasks, auth-context profiles, differential findings, recon coverage, change snapshots, target memory, learning statistics, smart plans, report claims, browser-capture metadata, operator diagnostics, error events and recovery actions. Two additive case metrics are also added: evidence-gap score and autopilot score.

## Safety invariants

- Active modules are not enabled by migration.
- Smart Recon plans require explicit user confirmation.
- BOLA/BFLA and sensitive families remain manual-only/controlled.
- Workspace Autopilot creates investigation tasks, not exploit actions.
- Browser capture is metadata-only; raw cookies, Authorization values and sensitive bodies are not persisted.
- Evidence-linked reports do not convert unconfirmed candidates into confirmed vulnerabilities.

## Rollback

Use the patch-generated backup or the existing updater rollback mechanism. A rollback must restore both application files and the pre-migration SQLite database copy.
