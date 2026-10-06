# Recon Monitor 8.8.4 Migration

Core database schema: **18**, unchanged. Upgrade from 8.8.3 through the existing installation directory. Finish active Runs and stop dashboard/API/workers first. Keep a data backup. This release requires no new scan or manual database migration.

```bash
./recon-monitor.sh dashboard stop
./recon-monitor.sh backup create --include-objects
./recon-monitor.sh update check --repo alirezasafariii/recon-monitor
./recon-monitor.sh update install --repo alirezasafariii/recon-monitor
./recon-monitor.sh --version
./recon-monitor.sh doctor
./recon-monitor.sh dashboard start --open
```

The installed version should be 8.8.4. The normal updater verifies the ZIP/SHA-256 pair, preserves local configuration/state and rolls back if post-install validation fails. Existing macOS process-cleanup fixes remain included. The redesign preserves records, filters and specialist controls; no changes to Katana timeout or collection limits are part of this release.
