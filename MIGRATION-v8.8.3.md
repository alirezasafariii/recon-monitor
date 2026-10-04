# Recon Monitor 8.8.3 Migration

Recon Monitor 8.8.3 is a macOS process-cleanup correction for 8.8.2. The core database schema remains **18**. Existing configuration, saved Runs, and collection limits remain in effect.

## Upgrade from 8.8.1 or 8.8.2

Use the existing installation directory and authenticated GitHub CLI account. Finish active Runs and stop running dashboard/API/worker instances before updating. Keep existing backups. The normal update path downloads and verifies the ZIP/SHA-256 pair and runs post-install validation.

```bash
./recon-monitor.sh --version
./recon-monitor.sh update check --repo alirezasafariii/recon-monitor
./recon-monitor.sh update install --repo alirezasafariii/recon-monitor
./recon-monitor.sh --version
./recon-monitor.sh doctor
./recon-monitor.sh dashboard start --open
```

After a successful update, the version must be `8.8.3`. A failed 8.8.2 update that reported rollback can retry through the same path; verify the installed version before retrying. No new scan, manual core schema migration, Python downgrade, or skipped validation is required by this fix.

## Process cleanup

CommandRunner preserves its bounded cleanup when macOS denies a group signal after the direct child has exited. The denied signal is recorded, output is retained, and Timeout/Next remain explicit interrupted outcomes. Live-child permission failures and unexpected signal errors remain visible failures. Detached processes are not treated as members of the original process group.

All previous 8.8.2 compatibility notes continue to apply; see `MIGRATION-v8.8.2.md`.
