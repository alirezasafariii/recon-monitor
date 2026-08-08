# Migration to Recon Monitor 8.3.0

Recon Monitor 8.3.0 is a Recon information-architecture and intelligence upgrade. The database schema remains **16** and no destructive migration is required.

## What changes

- Recon now opens into **Overview / Categories / Raw Data**.
- Existing inventory pages and routes remain available for compatibility and drill-down, but they are no longer duplicated in the System menu.
- Recon categories are multi-label and are derived from existing stored observations; they do not confirm vulnerabilities.
- Interest scoring prioritizes analyst review only.
- Change state uses existing run-comparison intelligence where available.
- Provenance is preserved from stored source fields where available; otherwise the UI labels the item as a stored observation rather than inventing a tool source.
- The old duplicate-heavy **More Tools** navigation is replaced by **System**, which contains only cross-cutting operations, safety, governance, quality, and configuration pages.

## Upgrade

```bash
./recon-monitor.sh update check
./recon-monitor.sh dashboard stop
./recon-monitor.sh update install
./recon-monitor.sh doctor
./recon-monitor.sh dashboard start --open
```

No target, database, credential, finding, case, or target-memory reset is required.
