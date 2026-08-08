# Migration to Recon Monitor 8.1.0

Recon Monitor 8.1.0 is an operational upgrade release. Database schema remains **16**, so no destructive database migration is required from 8.0.x.

## What changes

- Automatic private GitHub Release discovery and download through authenticated `gh`.
- Checksum verification before installation.
- Automatic data backup and program backup before replacement.
- Stronger post-update validation: init, compile, unit tests, and integration test.
- Automatic rollback of program files and the database when validation fails.
- Manual `--package` installation and `RECON_UPDATE_MANIFEST` remain compatible.

## One-time prerequisite

Install and authenticate GitHub CLI on the machine that will update Recon Monitor:

```bash
brew install gh
gh auth login --web
gh auth setup-git
```

## Upgrade flow

```bash
./recon-monitor.sh backup create
./recon-monitor.sh backup verify latest
./recon-monitor.sh update check
./recon-monitor.sh update install
./recon-monitor.sh doctor
```

The explicit backup commands are optional because `update install` creates a pre-update backup automatically; they are useful when an operator wants an additional verified restore point.

## Rollback

```bash
./recon-monitor.sh update rollback
```

After an update or rollback, restart the Dashboard if it was running.
