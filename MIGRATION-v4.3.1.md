# Migration to Recon Monitor 4.3.1

Version 4.3.1 is a dashboard-only compatibility release.

## Database

SQLite schema remains **10**. No migration or data rewrite is required.

## Preserved data

The patch preserves:

- `config.env` and target policies;
- runs, assets, URLs, JavaScript, endpoints, fingerprints, alerts, incidents, candidates, bundles, and analysis records;
- analyst decisions, notes, tags, users, sessions, API tokens, evidence exports, reports, and object-store files.

## Interface changes

- `/` becomes the decision-focused Command center.
- `/workbench` becomes the Review queue.
- `/bug-candidates` defaults to card view and supports `display=table`.
- Advanced pages remain available at their existing URLs.
- Browser density and focus-mode preferences are new and local to each browser.

## Rollback

The upgrade patch creates a program backup under:

```text
state/upgrades/v4.3.1-<timestamp>/
```

Because schema 10 is unchanged, rollback only restores program files.
