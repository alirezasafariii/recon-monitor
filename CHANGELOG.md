# 8.0.2 — Dashboard Port Preflight Reliability Fix

- Fixed a race/reliability issue in Dashboard occupied-port preflight discovered by the v8.0.1 regression suite on macOS.
- Replaced connection-based occupancy probing with a non-connecting bind probe, preventing the preflight itself from consuming a listener backlog.
- Repeated port checks now reliably report `host:port already in use` before spawn and retain PID/command/cwd diagnostics plus alternate-port guidance.
- Full unit and integration suites remain required; database schema stays 16 and no migration is required from 8.0.1.

# 8.0.1 — Signal Quality & Dashboard Polish

- Simplified the visible sidebar to four direct workspaces: Recon, Analysis, Potential Findings, and Alerts; moved detailed tools under More Tools.
- Added consistent quick-view presets for high-volume Recon, Analysis, Potential Findings, and Alerts datasets.
- Made Potential Findings default to an Actionable view so weak, insufficient-evidence, rejected, duplicate, and out-of-scope noise does not dominate review.
- Added an Attention view for Alerts that hides low-priority metadata changes by default while preserving a complete All Changes view.
- Added an explainable Why this confidence? panel to candidate detail, separating calibrated likelihood from evidence strength, coverage, observation quality, and exploitability context.
- Collapsed raw engine traces behind an Advanced reasoning section to improve decision-first readability.
- Improved Dashboard startup diagnostics: occupied-port detection, PID/command/cwd reporting when available, alternate-port guidance, readiness enforcement, stale PID cleanup, and recent log excerpts on failure.
- Corrected stale visible 7.0 dashboard labels and installer/help text to follow the current application version.
- Added regression tests for the simplified workspace navigation, confidence explanation, and dashboard port-conflict handling.
- Database schema remains 16; no migration is required from 8.0.0.

# 8.0.0 — Four-Workspace Research Console

- Reorganized the primary Dashboard around four analyst workspaces: Recon, Analysis, Potential Findings, and Alerts.
- Added a unified Recon workspace with cross-surface search and filters spanning hosts, endpoints, URLs, ports/services, and JavaScript findings.
- Added structured search, target, severity, confidence, score, and sorting controls to the main Analysis workspace.
- Promoted bug candidates into the clearer Potential Findings workflow while preserving analyst-confirmation semantics.
- Added baseline-aware run-to-run Change Alerts for new or materially changed endpoints, subdomains, URLs, ports/services, JavaScript, technologies, response fingerprints, authentication boundaries, and response shapes.
- Added alert priority scoring and direct Analyze actions from each change alert.
- Refreshed the Dashboard with a deep-navy visual system, stronger hierarchy, simplified navigation, polished cards/tables, and responsive interaction states.
- Preserved v7 workspace commands and compatibility modules while bumping the product version to 8.0.0.
- Database schema remains 16; no destructive migration is required.
- Automatic exploitation, authorization bypass, destructive testing, and automatic vulnerability confirmation remain excluded.

# 7.0.0 — Unified Security Research Workspace

- Added Evidence Gap Engine with family-aware requirements, explicit missing evidence and safest next analyst actions.
- Added Case Autopilot that creates evidence/decision/report tasks only; it never exploits or confirms a vulnerability automatically.
- Added authentication-context profiles sourced from behavioral evidence, identity graph, redacted HTTP observations and metadata-only browser capture.
- Added Differential Intelligence 2.0 for authorization-boundary, status, field, type and sensitive-field changes.
- Added Attack Surface Graph with target, host, endpoint, JavaScript, candidate and authorization-context relationships.
- Added Recon Coverage/Confidence with explicit blind spots for JavaScript, API, response-shape, authenticated and role coverage.
- Added Change Intelligence, Target Memory, human-supervised False Positive Learning, Smart Recon Planner and Stage Value analysis.
- Added evidence-linked Report Builder; unconfirmed cases are blocked from confirmed-vulnerability wording and impact is never auto-inferred.
- Enhanced Burp round-trip packages with evidence gaps, next actions and authorized context labels while excluding raw credentials/bodies.
- Added metadata-only Browser Capture via CLI and Dashboard; sensitive query values and secret headers are redacted/ignored.
- Replaced the dashboard home with an analyst Cockpit, added Universal Search, Command Palette and workspace navigation.
- Added structured Error IDs, diagnostics, browser compatibility checks and preview-first safe repair.
- Added Safety Center and consistent local Safari `Origin: null` handling only for exact loopback/same-origin conditions.
- Analysis completion now refreshes v7 workspace intelligence without allowing workspace failures to fail the core analysis.
- Upgraded SQLite schema from 15 to 16 with additive migrations.
- Automatic live validation, cross-user enumeration, credential replay, destructive testing and automatic vulnerability confirmation remain excluded.

# 6.0.4

- Fixed Safari local Safe Validation forms that send the literal `Origin: null` with `Sec-Fetch-Site: same-origin`.
- The exception is restricted to `/validation/` POSTs with loopback client/server sockets, loopback Host and the exact real dashboard port.
- `Origin: null` remains rejected for same-site/cross-site requests, non-validation actions, remote binds, wrong ports and trusted-proxy mode.
- Session and CSRF validation remain mandatory when dashboard authentication is enabled.
- Suppressed harmless browser-disconnect `BrokenPipeError` and connection-reset tracebacks while sending dashboard responses.
- Added exact HTTP regression coverage for an auth-disabled BOLA `manual_only` plan matching the observed Safari headers.
- Full unit suite contains 141 tests; schema remains 15.

# 6.0.3

- Fixed Safari local form POSTs that omit `Origin` and `Referer` while sending `Sec-Fetch-Site: same-site`.
- Allows the narrow missing-Origin case only when both the browser client and dashboard listener are loopback and the per-session CSRF token is valid.
- Continues rejecting explicit cross-site metadata, remote clients, remote binds, different ports, malformed origins, and invalid CSRF tokens.
- Added safe diagnostic logging for Origin/Fetch-Site/loopback context without logging cookies or CSRF values.
- Validation-plan policy errors now render a readable HTTP 400 page instead of closing the connection.
- Added unit and real HTTP regression coverage for Safari-style manual-only plan creation.
- Schema remains 15.

# 6.0.2

- Fixed Safe Validation Origin rejection when Safari or a local privacy/proxy layer rewrites the Host header.
- Added actual loopback socket validation with exact port and scheme matching.
- Kept external origins, remote binds, different ports, malformed origins, and invalid CSRF tokens blocked.
- Added regression and real HTTP tests for rewritten Host headers.
- Schema remains 15.

# 6.0.1 — Dashboard Origin and CSRF Compatibility Fix

- Embeds CSRF tokens in every session-authenticated POST form on the server instead of depending only on browser JavaScript.
- Treats `localhost`, `127.0.0.1`, and `::1` as equivalent loopback origins only when scheme and port match.
- Continues rejecting external origins, `Origin: null`, malformed origins, different ports, and stale or missing CSRF tokens.
- Adds optional explicit reverse-proxy settings: `DASHBOARD_ALLOWED_ORIGINS` and `DASHBOARD_TRUST_PROXY_HEADERS`.
- Adds separate diagnostics for Origin failures and CSRF failures.
- Adds end-to-end coverage for the Safe Validation approval and plan workflow.
- Schema remains 15.

# 6.0.0 — Intelligence, Automation and Hardening Platform

- Added explainable Validation Intelligence with reliability, context coverage, response comparability, identity/scope confidence, freshness, historical baselines and explicit limitations.
- Added trigger-aware revalidation policies and automatic offline-only processing with zero network requests.
- Added run Data Quality and Coverage snapshots with explicit blind-spot detection.
- Added cost-aware case ranking using expected information gain and analyst effort.
- Added redacted Burp round-trip packages and structured result import without raw bodies or credentials.
- Added Security Story Correlation v2 with persisted member links and transparent correlation dimensions.
- Added quiet-hour-aware macOS scheduled workflows, smart notification classification, policy thresholds and 24-hour deduplication.
- Added scoped/expiring API tokens, login lockout, lead-analyst RBAC, security posture checks, safe permission repair and tamper-evident audit chaining.
- Added preview-first retention with exact confirmations and permanent protection for confirmed/case evidence.
- Added dashboard and platform performance sampling, slow-operation diagnostics, WAL/database metrics and largest-table visibility.
- Added safe target templates that never modify scope or grant authorization.
- Added automatic report-quality scoring and missing-section checks.
- Extended Evidence ZIP exports with relevant version-6 case intelligence.
- Added Intelligence dashboard group and pages for validation confidence, data quality, review priority, automation, report quality, performance, retention, templates and platform security.
- Preserved bounded queries, dashboard snapshots, unified filters and grouped navigation from 5.1.1.
- Upgraded SQLite schema from 13/14 to 15 with additive migrations.
- Automatic exploitation, cross-user object enumeration, credential replay, destructive validation and automatic vulnerability confirmation remain excluded.

# 5.1.0 — Safe Validation and Analyst Feedback

- Added a policy-driven Safe Validation Engine with four eligibility levels: offline, passive live, controlled-plan-only, and manual-only.
- Added candidate-specific test plans, exact approval phrases, three-gate live authorization checks, request budgets, stop conditions, and redacted observations.
- Limited executable live validation to in-scope `GET`, `HEAD`, and `OPTIONS` requests with no cookies, no credential replay, no redirect following, no query replay, concurrency 1, bounded response size, and no retries.
- Kept BOLA/BFLA, cross-tenant, mass-assignment, GraphQL/WebSocket authorization, SSRF, executable XSS, uploads, path traversal, race, payment, recovery, role-change, and destructive workflows out of automatic live execution.
- Added offline and passive checks for reachability, authentication boundaries, redacted response shapes, security/cache/CORS headers, redirect locations, and source-map presence.
- Added HAR and Burp XML evidence import with scope filtering, credential/header redaction, raw-body exclusion, file-size limits, and XML entity/DTD rejection.
- Added structured analyst validation feedback and reason codes without automatic candidate confirmation.
- Added Safe Validation CLI, dashboard, local API, audit events, unified-evidence integration, case status summaries, and Evidence ZIP records.
- Upgraded SQLite schema from 13 to 14 using additive tables and case validation fields.
- Added ten Safe Validation regression tests; the full unit suite now contains 104 tests.

# 5.0.1 — Dashboard Performance

- Removed implicit case/story synchronization from dashboard GET routes.
- Added persisted snapshot and short-lived cache reads for engine quality, run completeness, storage, operations, and plugin health.
- Moved full SQLite integrity checks and recursive storage scans behind explicit deep refresh.
- Added bounded pagination for Security Cases and reduced default Security Story rendering.
- Stopped scope and quality snapshot writes during ordinary page views.
- Added five dashboard-performance regression tests (94 total tests).
- Schema remains 13.

# 5.0.0 — Production Platform and Case-First Dashboard

- Consolidated the delivered 4.5, 4.5.1, and 4.6 engines with the planned 4.7, 4.8, and 4.9 platform layers.
- Added Engine Quality metrics, rule governance, noise budgets, and explainable target-specific learning profiles.
- Added security cases, case ownership, lifecycle events, validation-context packages, report drafts, and report-readiness scoring.
- Added correlated Security Stories that group related changes and candidates around a shared boundary.
- Added Scope, Operations, Storage, Plugin Health, and Audit dashboard centers.
- Added operational run-completeness scoring, schedule/notification policy records, and storage snapshots.
- Added incremental reasoning reuse and incremental analysis checkpoints.
- Added plugin manifest contracts and persistent plugin health history; this is validation/governance, not an OS sandbox.
- Rebuilt the dashboard information hierarchy around decisions, cases, quality, and operations; technical inventory is progressive drill-down.
- Extended Evidence ZIP exports with cases, stories, quality snapshots, scope snapshots, target learning, validation packages, and report drafts.
- Added versioned local API and CLI operations for the production platform.
- Upgraded SQLite schema from 11/12 to 13 using additive migrations.
- Added nine production-platform regression tests; full suite now contains 89 tests.

# 4.6.0 — Security Reasoning Core

- Added a unified evidence and provenance model with integrity hashes, parser versions, source trust, and root lineage.
- Added family-specific required, supporting, contradictory, and missing-evidence schemas.
- Added formal positive, contradictory, and unknown evidence states.
- Added falsification traces and explicit strengthen/weaken/reject conditions.
- Added Top-3 vulnerability-family rankings and alternative-family storage.
- Added calibrated likelihood, exploitability confidence, evidence coverage, precondition state, and reachability state.
- Added causal/context/business-operation reasoning from semantic and behavioral observations.
- Added Golden Dataset evaluation, per-family calibration, Brier score, and precision proxies.
- Added isolated shadow-rule results that cannot affect the primary review queue.
- Added a reasoning regression gate with family-quality, evidence-coverage, noise-budget, and same-run confirmed-retention checks.
- Added Security Reasoning dashboard, Candidate Detail trace, CLI, local API, and Evidence ZIP integration.
- Upgraded SQLite schema from 11 to 12 using additive migrations.
- Added eight reasoning regression tests; full suite now contains 80 tests.

# 4.5.1 — Stabilization and Recovery

- Fixed Doctor incorrectly expecting database schema 7 instead of the current schema 11.
- Added defensive JSON decoding for legacy, NULL, malformed, and wrong-shape stored values.
- Ensured unexpected analysis failures finalize `analysis_runs` as `failed` with an audit record.
- Added stale-state preview and repair for analysis runs, stages, persistent work items, and parent runs.
- Added live-run-lock protection for destructive repair operations.
- Added database quick-check, foreign-key, stale-state, and stored-JSON checks to Doctor.
- Added deep backup verification: archive checksum, safe members, manifest hashes, SQLite integrity, and foreign keys.
- Added isolated `backup drill latest` restore testing without modifying the active installation.
- Fixed database restore to close the WAL-backed connection before atomically replacing the database.
- Added SQLite indexes for run, analysis, work-queue, and backup operational queries.
- Added passive database optimization and WAL checkpoint after state repair.
- Preserved database schema 11 and all existing data.
- Added nine stabilization regression tests; full suite now contains 71 tests.

# 4.5.0 — Behavioral Intelligence Engine

- Added cross-analysis authentication-boundary diffs.
- Added redacted structural response diffs with status, key, type, and sensitive-field transitions.
- Added protocol-specific REST, GraphQL, WebSocket, OAuth/OIDC, and cache findings.
- Added identity and authorization entities and relationships.
- Added stored context-observation normalization; no automatic active testing is performed.
- Integrated behavioral evidence into Bug Candidate reliability and direct unverified candidates.
- Added Behavioral Intelligence dashboard, CLI actions, API endpoints, and evidence-export records.
- Upgraded SQLite schema from 10 to 11 with additive tables.
- Added six behavioral tests; full suite now contains 62 tests.

# 4.3.1 — Decision-Centered Dashboard

- Reorganized navigation around Focus, Investigate, Explore, and Operations.
- Moved specialist routes into a collapsible Advanced tools section without removing any existing URLs.
- Replaced the inventory-heavy landing page with a decision-first Command center.
- Added Review now, Needs evidence, Watchlist, Confirmed, and All active queue views.
- Added card-first candidate review with investigation value, score triad, reasoning, missing evidence, and next safe action.
- Added a compact candidate table toggle for bulk scanning.
- Added breadcrumbs, current-view context, target-focus indication, compact density, and sidebar focus mode.
- Preserved schema 10 and all existing collection, analysis, candidate, and authorization behavior.
- Added command-center and progressive-disclosure regression tests.
- Unit-test count: 56.

# 4.3.0 — Candidate Reliability & Semantic Intelligence

This release combines the planned 4.2 Candidate Reliability Engine and 4.3 Semantic Candidate Intelligence work.

## Candidate Reliability Engine (4.2)

- Added bug-family-specific evidence schemas with required evidence gates.
- Added independent evidence grouping to suppress correlated double counting.
- Added Observation Quality, Investigation Value, Novelty, and Historical Noise scores.
- Added `quiet`, `balanced`, and `research` analysis profiles.
- Added candidate lifecycle tracking across replays, including recurring and stale behavior.
- Added structured analyst feedback reason codes.
- Added per-family calibration and candidate evaluation reports.
- Added gold-label support for replay evaluation datasets.
- Added Candidate Quality dashboard and local API output.

## Semantic Candidate Intelligence (4.3)

- Added endpoint contract extraction from stored endpoint and analysis evidence.
- Added authentication-boundary mapping.
- Added redacted response-shape fingerprinting based on keys and value types.
- Added semantic JavaScript units for API calls, routes, storage keys, authorization checks, WebSocket channels, postMessage handlers, and feature flags.
- Added feature-flag history records.
- Added parameter-relationship mapping for tenant, account, user, order, invoice, and related identifiers.
- Added candidate bundles that group related probable vulnerability variants around a shared boundary or semantic change.
- Added Candidate Bundles and Semantic Intelligence dashboard pages and API endpoints.
- Added all new reliability and semantic records to evidence exports.

## Platform

- Upgraded SQLite schema from 9 to 10 with an additive migration.
- Preserved existing runs, alerts, candidates, decisions, notes, tags, users, tokens, evidence, and policies.
- Added regression tests for evidence independence, migration, reliability scores, lifecycle, calibration, endpoint contracts, response shapes, feature flags, parameter relationships, and bundles.
- Unit-test count: 54.
- No AI/LLM layer, exploit automation, or automatic vulnerability confirmation was added.

# 4.1.0 — Bug Candidate Engine

- Added evidence-linked probable vulnerability families.
- Added independent likelihood, evidence-strength, impact-potential, and priority scores.
- Added automatic candidate states with analyst-only confirmation.
- Added BOLA/IDOR, BFLA, mass assignment, authentication/session, account-enumeration, DOM XSS, postMessage, open redirect, SSRF, file handling, data exposure, GraphQL, business-logic, race-condition, WebSocket, CORS, and caching candidate rules.
- Added multi-signal gating so a single keyword cannot create a candidate.
- Added supporting, contradicting, and missing-evidence records.
- Added safe next actions that remain within authorized testing boundaries.
- Added candidate decision carry-forward across analysis replay.
- Added dashboard candidate queue, candidate detail, and candidate sections on alert pages.
- Added CLI and local API candidate operations.
- Added candidate records to evidence exports and global search.
- Upgraded database schema from 8 to 9.
- Added Bug Candidate Engine regression and replay tests.
