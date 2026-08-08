# Dashboard navigation and filters — Recon Monitor 5.1.1

## Information architecture

The sidebar is organized by analyst intent rather than by database table.

### Workspace

- Command center
- Review queue
- Security cases
- Safe validation
- Security stories

### Analysis

- Bug candidates
- Analysis engine
- Security reasoning
- Behavioral intelligence
- Semantic intelligence

### Quality

- Engine quality
- Candidate quality
- Rule governance

### Operations

- Operations center
- Scope center
- Run history
- System health
- Storage health

### Inventory

- Assets
- Endpoints
- JavaScript
- HTTP / TLS
- URLs
- Asset graph

Less frequently used views are retained under **More tools**, divided into Signals & Change, Research Tools and Administration.

Navigation groups are collapsible. The group containing the current page opens automatically, and the browser remembers the user's open/closed preferences locally.

## Filter design

Filter panels share one pattern across the dashboard:

- Search field first.
- High-value dimensions before technical dimensions.
- Explicit result count.
- Active filters displayed as removable-at-a-glance chips.
- One-click reset.
- Query-string based state so filtered views can be bookmarked or shared locally.

## Main filter coverage

### Security cases

Search, target, workflow state, bug family, owner, validation state, scope state, minimum priority, minimum report readiness and sort order.

### Review queue and bug candidates

Target, family, candidate state, analyst decision, lifecycle/reachability, minimum likelihood, evidence, exploitability and investigation value.

### Safe validation

Case, target, family, case state, validation state, plan level, plan status and validation result.

### Security stories

Search, target, status, priority threshold, time window and ordering.

### Engine quality

Target, family, rule, parser, minimum sample size and attention-only mode.

### Operations and inventory

Runs: target, run state, error presence, time window and ordering.

Alerts: target, state, severity, priority, owner, tag, minimum risk and time window.

Assets: target, resolution state, lifecycle, wildcard state, tag, minimum confidence and recency.

Endpoints: target, class, kind, source, minimum confidence and recency.

URLs: target, kind, source, recency and sorting.

JavaScript: target, indicator kind, redaction state, recency and search.

HTTP / TLS: target, exact status, status class, server, technology, CDN, TLS state and recency.

## Performance boundaries

- Case pages remain paginated.
- Queries are bounded.
- Dashboard reads quality and operations snapshots instead of recalculating them on ordinary page loads.
- Filter changes do not trigger platform synchronization or deep integrity scans.
