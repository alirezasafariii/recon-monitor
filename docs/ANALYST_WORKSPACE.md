# Analyst Workspace — Recon Monitor 4.5.0

The dashboard is organized as a decision workspace rather than a flat collection of reports.

## Daily workflow

```text
Command center → Review queue → Candidate or alert detail → Technical evidence
```

The first two pages deliberately hide most raw inventory until it becomes relevant to a decision.

## Command center

The Command center is the default route `/`. It prioritizes:

- strong candidates and urgent alerts;
- candidates that need more evidence;
- unreviewed analyst decisions;
- collection or database health requiring attention;
- correlated candidate bundles and change incidents.

Coverage totals remain available below the decision inbox.

## Review queue

The Review queue at `/workbench` provides five views:

- Review now;
- Needs evidence;
- Watchlist;
- Confirmed;
- All active.

Candidate cards present investigation value, likelihood, evidence strength, impact potential, observation quality, supporting reasoning, contradicting reasoning, missing evidence, and the next safe action. Supporting alerts are collapsed by default.

## Navigation

Normal work is grouped into Focus, Investigate, Explore, and Operations. Specialized pages remain in a collapsible Advanced tools section. Existing URLs are preserved.

## Detail pages

Candidate, alert, and asset pages use breadcrumbs and retain full evidence, workflow, notes, tags, history, and export functions.

## Local display preferences

Dark/light theme, comfortable/compact density, and sidebar focus mode are stored in browser local storage. They do not change the recon database or target policy.

## Safety and compatibility

The workspace does not perform active validation or confirm vulnerabilities automatically. Version 4.5.0 uses database schema 11 and preserves all existing data.
