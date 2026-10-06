# Recon Monitor 8.8.6 Migration

Core database schema: **18**, unchanged. Finish active Runs and stop dashboard/API/workers before updating. Keep a data backup. No new scan or manual database migration is required to install this release.

```bash
./recon-monitor.sh dashboard stop
./recon-monitor.sh backup create --include-objects
./recon-monitor.sh update check --repo alirezasafariii/recon-monitor
./recon-monitor.sh update install --repo alirezasafariii/recon-monitor
./recon-monitor.sh --version
./recon-monitor.sh doctor
./recon-monitor.sh dashboard start --open
```

The installed version should be 8.8.6. ZIP/SHA-256 verification and full post-install validation remain enabled. Existing data and configuration are preserved and validation failures roll back normally. Previous macOS cleanup, installed-layout and dashboard fixes remain included.

The header parser fix applies to newly parsed httpx output. Existing empty response_headers_json values cannot reconstruct the discarded policy. Retained raw fingerprint output can support offline reprocessing followed by a new Analysis; existing immutable snapshots and candidates are not rewritten by installation. Without raw output, use a future authorized collection rather than inferring policy values from an HSTS technology tag. Katana timeout and collection budgets are unchanged.
