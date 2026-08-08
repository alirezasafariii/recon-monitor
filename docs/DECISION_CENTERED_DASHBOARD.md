# Decision-Centered Dashboard — Recon Monitor 4.3.1

Recon Monitor 4.3.1 reorganizes the local dashboard around analyst decisions instead of raw inventory volume. No collection, analysis, authorization, or database behavior changes in this release. SQLite schema remains version 10.

## Information architecture

The primary navigation now contains only the routes needed during normal review:

- **Focus:** Command center, Review queue, Recent changes, Change stories.
- **Investigate:** Bug candidates, Candidate bundles, Alerts, Analysis.
- **Explore:** Assets, Endpoints, JavaScript, HTTP/TLS.
- **Operations:** Runs, Targets, Health.

Specialized pages remain available under **Advanced tools**. They are not removed and all previous URLs remain compatible.

## Command center

The `/` page answers four questions first:

1. What needs review now?
2. Which candidates need more evidence?
3. How much work remains unreviewed?
4. Does the collection platform need attention?

The decision inbox prioritizes current candidates. Supporting alerts are collapsed below them. Inventory totals are moved to a lower coverage snapshot so they do not compete with analyst decisions.

## Review queue

`/workbench` is now the primary analyst queue. It has five focused views:

- `Review now`
- `Needs evidence`
- `Watchlist`
- `Confirmed`
- `All active`

Each candidate card shows:

- candidate and analyst states;
- investigation value;
- likelihood, evidence strength, impact, and observation quality;
- why the candidate exists;
- why it might be wrong;
- missing evidence;
- the next safe analyst action.

Unresolved alerts are retained as supporting evidence and are collapsed by default.

## Candidate browsing

`/bug-candidates` uses a card view by default. A compact table view remains available for bulk scanning. Both views preserve filters for target, bug family, candidate state, and analyst decision.

## Progressive disclosure

The interface follows three levels:

1. **Decision:** Candidate or alert requiring attention.
2. **Reasoning:** Scores, supporting and contradicting evidence, missing information, and next action.
3. **Raw evidence:** Endpoint, JavaScript, HTTP/TLS, graph, and historical records.

Technical inventory is never deleted or hidden permanently; it is moved behind deliberate drill-down paths.

## Navigation aids

- Breadcrumbs on candidate, alert, and asset detail pages.
- Current page context in the top bar.
- Target-focus chip when a target query is active.
- Collapsible Advanced tools section.
- Persistent compact-density preference.
- Persistent focus mode that hides the sidebar.
- Existing dark/light theme and global search shortcuts remain available.

## Browser-local preferences

These preferences are stored only in browser local storage:

```text
recon-theme
recon-density
recon-focus-mode
```

They do not alter the database or recon configuration.

## Compatibility

- Database schema: 10, unchanged.
- Existing dashboard routes: preserved.
- Existing candidates, alerts, decisions, notes, tags, evidence, runs, reports, policies, and users: preserved.
- Active testing gates and authorization policy: unchanged.
