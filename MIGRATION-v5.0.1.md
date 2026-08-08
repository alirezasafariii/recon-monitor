# Migration to Recon Monitor 5.0.1

Recon Monitor 5.0.1 is a dashboard-performance release for installations running 5.0.0.
It keeps database schema 13 and does not change reconnaissance or security reasoning behavior.

## Main changes

- Dashboard GET routes no longer rebuild security cases or stories.
- Engine quality, run completeness, and storage summaries are served from persisted snapshots and short-lived process caches.
- Full SQLite integrity checks and recursive storage scans run only during explicit deep refresh/platform sync.
- Security cases are paginated at 50 records per page.
- Security stories default to 50 records instead of rendering hundreds at once.
- Scope views no longer write a new scope snapshot on every page request.
- Plugin-health results are cached briefly.

## Upgrade

```bash
PATCH=$(find "$HOME/Downloads" -maxdepth 1 \
  -name 'apply-recon-monitor-v5.0.1-dashboard-performance*.sh' \
  -print -quit)

bash "$PATCH" "$HOME/Downloads/recon-monitor"
```

## Verification

```bash
cd "$HOME/Downloads/recon-monitor"
./recon-monitor.sh --version
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
./recon-monitor.sh dashboard restart --open
```

Expected version: `5.0.1`  
Expected schema: `13`  
Expected unit tests: `94`

The Operations Center uses cached snapshots in normal mode. Use **Run deep refresh** when you intentionally want a full database integrity check and recursive storage measurement.
