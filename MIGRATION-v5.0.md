# Migration to Recon Monitor 5.0.0

Recon Monitor 5.0 is a cumulative production-platform upgrade. It contains the previously delivered 4.5 Behavioral Intelligence, 4.5.1 Stabilization, and 4.6 Security Reasoning features, plus the planned 4.7 Engine Quality Platform, 4.8 Investigation Workspace, 4.9 Operations Center, and 5.0 production foundations.

## Supported source versions

The self-contained upgrade patch accepts:

- `4.5.1` — upgrades schema 11 directly to schema 13 and installs Security Reasoning plus the 5.0 platform.
- `4.6.0` — upgrades schema 12 to schema 13.
- `5.0.0` — idempotent verification/reinstall.

The migration is additive. Existing runs, alerts, candidates, analyst decisions, notes, tags, evidence, policies, users, API tokens, backups, and configuration are preserved.

## Schema

- Previous: 11 or 12
- New: 13

New records include engine-quality snapshots, rule governance, noise budgets, target learning profiles, security cases and stories, validation packages, report drafts, operational completeness, scope snapshots, schedule and notification policies, storage snapshots, incremental checkpoints/cache, and plugin health history.

## Before upgrading

```bash
cd ~/Downloads/recon-monitor
./recon-monitor.sh --version
./recon-monitor.sh backup create --include-objects
./recon-monitor.sh backup verify latest
```

A catalogued backup is recommended. The patch also creates an online SQLite snapshot and a code backup before changing the installation.

## Install

```bash
PATCH=$(find "$HOME/Downloads" -maxdepth 1 \
  -name 'apply-recon-monitor-v5.0.0-production-platform*.sh' \
  -print -quit)

bash "$PATCH" "$HOME/Downloads/recon-monitor"
```

## Validate

```bash
cd ~/Downloads/recon-monitor
./recon-monitor.sh --version
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
./recon-monitor.sh platform sync
./recon-monitor.sh dashboard restart --open
```

Expected version and schema:

```text
5.0.0
13
```

## Scheduling boundary

The Operations Center stores target schedule policy, runtime budget, quiet hours, and notification policy. Existing Service/LaunchAgent commands remain responsible for actual scheduled execution. Version 5.0 does not silently install or modify a system scheduler when a policy is saved.

## Security boundary

Version 5.0 does not add exploit automation, payload generation, authorization bypass, destructive concurrency tests, or automatic vulnerability confirmation. Validation packages contain context, prerequisites, evidence requirements, and stop conditions for an authorized analyst.
