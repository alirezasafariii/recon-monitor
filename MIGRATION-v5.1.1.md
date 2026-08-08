# Migration to Recon Monitor 5.1.1

Recon Monitor 5.1.1 reorganizes the dashboard navigation and adds consistent multi-dimensional filters to the analyst workspace. The database schema remains **14**.

## Supported upgrade sources

The release patch accepts:

- `5.0.1`
- `5.1.0`
- `5.1.1`

Upgrading directly from 5.0.1 installs the Safe Validation capabilities from 5.1.0 together with the 5.1.1 dashboard changes.

## What changes

- Five collapsible navigation groups: Workspace, Analysis, Quality, Operations and Inventory.
- Advanced tools split into Signals & Change, Research Tools and Administration.
- Active navigation state and open/closed groups persist locally in the browser.
- Unified filter panels with result counts, active-filter chips and a reset action.
- Expanded filters for cases, review queue, candidates, safe validation, stories, engine quality, runs, alerts, assets, endpoints, URLs, JavaScript and HTTP/TLS intelligence.
- Case and candidate sorting by analyst-relevant scores and workflow state.
- Existing dashboard snapshot/caching behavior from 5.0.1 remains in place.

## Data and compatibility

- Schema remains `14`.
- Runs, alerts, candidates, cases, validation plans, analyst decisions and evidence are preserved.
- `config.env`, target policy and custom plugins are preserved by the patch.
- No validation policy or active-testing gate is weakened.

## Install

```bash
PATCH=$(find "$HOME/Downloads" -maxdepth 1 \
  -name 'apply-recon-monitor-v5.1.1-dashboard-navigation-filters*.sh' \
  -print -quit)

bash "$PATCH" "$HOME/Downloads/recon-monitor"
```

## Verify

```bash
cd ~/Downloads/recon-monitor
./recon-monitor.sh --version
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
```

Expected version: `5.1.1`

Expected schema: `14`
