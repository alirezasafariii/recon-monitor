# Dashboard Performance Architecture — 5.0.1

## Problem fixed

Recon Monitor 5.0.0 performed several write-heavy or full-scan operations while rendering ordinary dashboard pages:

- rebuilding cases and stories;
- recalculating engine quality from all candidates;
- writing completeness and scope snapshots;
- running full SQLite integrity and foreign-key checks;
- recursively walking state/output/report/log directories;
- rendering hundreds of case and story cards.

These operations were correct but belonged to analysis completion, explicit synchronization, or maintenance workflows—not HTTP GET requests.

## New request model

Normal page request:

```text
HTTP GET
→ bounded indexed queries
→ persisted summary snapshot
→ short-lived in-process cache
→ HTML render
```

Explicit refresh or analysis completion:

```text
Platform sync / Deep refresh
→ rebuild cases and stories
→ recalculate engine quality
→ calculate completeness
→ scan storage
→ persist fresh snapshots
→ invalidate process cache
```

## Cache behavior

- Engine quality: persisted snapshot + 5-minute process cache.
- Run completeness: persisted snapshot + 2-minute process cache.
- Storage: persisted snapshot + 5-minute process cache.
- Operations summary: 30-second process cache.
- Plugin health: 60-second process cache.

Caches contain derived summaries only. Candidate decisions, scope rules, evidence, alerts, and raw intelligence remain in SQLite as the source of truth.

## Deep refresh

The normal Operations Center intentionally does not run `PRAGMA integrity_check` or recursively measure every managed directory. Use:

```text
Operations Center → Run deep refresh
```

Deep refresh recalculates the operational snapshots and performs full database checks.

## Pagination

Security Cases render 50 records per page. Security Stories render at most 50 cards in the main view. Technical data remains available through filters and drill-down pages.
