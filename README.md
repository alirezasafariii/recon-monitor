# Recon Monitor 8.1.0



## Automatic Private GitHub Updates in 8.1.0

Recon Monitor 8.1.0 adds a private-release update path built around the authenticated GitHub CLI. The default repository is `alirezasafariii/recon-monitor`; credentials stay with `gh`/the operating-system credential store rather than being copied into Recon Monitor configuration.

```bash
./recon-monitor.sh update check
./recon-monitor.sh update install
./recon-monitor.sh update rollback
```

`update install` now downloads the matching release ZIP and SHA-256 sidecar automatically, verifies the checksum, creates a data backup and a program backup, installs the release, then runs initialization, Python compilation, the full unit suite, and the integration test. If validation fails, the updater restores both the program files and the pre-update database backup. Manual `--package` installs and the legacy `RECON_UPDATE_MANIFEST` path remain supported. Database schema remains **16**.

See `MIGRATION-v8.1.md` for the 8.0.x → 8.1 transition.

## Four-Workspace Research Console in 8.0.2

Recon Monitor 8.0 simplifies the analyst experience around four primary workspaces without removing the underlying engines: **Recon**, **Analysis**, **Potential Findings**, and **Alerts**. Recon consolidates discovered attack-surface data with unified search and filtering. Analysis centralizes engine output and reasoning. Potential Findings presents reviewed candidates with confidence-oriented triage. Alerts compares later recon runs with the target baseline and surfaces newly discovered or materially changed attack-surface elements such as endpoints, subdomains, URLs, ports/services, JavaScript, technologies, response fingerprints, authentication boundaries, and response shapes.

Version 8 keeps the same database schema **16** and preserves the v7 safety model: it does not automatically confirm vulnerabilities, bypass authorization gates, or enable active modules. Existing v7 workspace commands and compatibility modules remain available.


### 8.0.2 dashboard port-preflight reliability fix

- Dashboard occupied-port detection now uses a non-connecting bind probe, so repeated checks do not consume a listener backlog or produce a false "port free" result.
- Preserves PID/command/working-directory diagnostics and alternate-port guidance from 8.0.1.
- Database schema remains 16; no migration is required from 8.0.1.

### 8.0.1 usability and signal-quality polish

- The primary sidebar now exposes only the four core workspaces; detailed tools live under **More Tools**.
- Potential Findings opens in an **Actionable** view by default, while weak/insufficient/rejected candidates remain available through filters.
- Alerts opens in an **Attention** view that suppresses low-priority metadata noise while preserving an All Changes view.
- Recon, Analysis, Potential Findings, and Alerts now expose consistent quick-view presets alongside detailed filters.
- Candidate detail includes an explainable **Why this confidence?** panel separating calibrated likelihood from evidence quality, coverage, observation quality, and exploitability context.
- Dashboard startup now detects occupied ports before spawning, reports the owning PID/command/working directory when available, suggests an alternate port, and includes recent log lines for startup failures.

```bash
./recon-monitor.sh dashboard restart --open
./recon-monitor.sh workspace sync
./recon-monitor.sh workspace cockpit --target example.com
```

See `MIGRATION-v8.0.md` for the 7.0 → 8.0 transition.


## Unified Security Research Workspace in 7.0

Recon Monitor 7.0 turns the existing recon, reasoning, case and validation platform into an analyst-oriented research workspace. It adds Evidence Gap analysis, investigation Autopilot, authentication-context profiles, differential intelligence, attack-surface graphs, change intelligence, reconnaissance confidence, target memory, human-supervised false-positive learning, smart recon planning, stage value analysis, evidence-linked report building, metadata-only browser capture, a cockpit home, universal search, Command Palette, structured Error IDs, narrow safe repair and a consolidated Safety Center. Database schema is **16**.

The v7 workspace does **not** automatically confirm vulnerabilities or enable active modules. BOLA/BFLA and other sensitive validation families remain manual-only/controlled as defined by Safe Validation. Browser capture and Burp round-trip paths remain metadata/redaction oriented and do not persist raw cookies, authorization values or sensitive response bodies.

```bash
./recon-monitor.sh workspace sync
./recon-monitor.sh workspace cockpit --target example.com
./recon-monitor.sh workspace evidence-gap --case-id CASE_ID
./recon-monitor.sh workspace autopilot --case-id CASE_ID
./recon-monitor.sh workspace coverage --target example.com
./recon-monitor.sh workspace safety
./recon-monitor.sh dashboard restart --open
```

See `MIGRATION-v7.0.md` and `docs/UNIFIED_SECURITY_RESEARCH_WORKSPACE.md`.

## Intelligence, automation and hardening in 6.0

Version 6 closes the operational loop between recon, analysis, bounded validation and analyst feedback. It adds validation reliability, data-quality blind spots, cost-aware review priority, Burp round-trip packages, correlation v2, offline revalidation, quiet-hour-aware macOS schedules, smart notifications, scoped/expiring API tokens, audit hash chaining, safe retention, performance diagnostics, target templates and report-quality checks. Database schema is 15. See `docs/RECON_MONITOR_6_PLATFORM.md` and `MIGRATION-v6.0.md`.

```bash
./recon-monitor.sh platform sync
./recon-monitor.sh suite data-quality
./recon-monitor.sh suite review-queue --apply
./recon-monitor.sh suite security-posture
```

Recon Monitor is a local-first, authorization-gated attack-surface change-monitoring platform for assets you own or are explicitly permitted to assess.

Recon Monitor 6.0 combines:

- scope-aware planning and dry runs;
- persistent SQLite work queues, budgets, item-level resume, and a single-writer path;
- multi-source asset, DNS, URL, JavaScript, endpoint, HTTP/TLS, lifecycle, and change-correlation intelligence;
- content-addressed evidence storage with integrity manifests;
- plugin discovery and health checks;
- session-authenticated RBAC dashboard and token-authenticated local API;
- restricted remote workers;
- macOS Keychain secrets;
- backups, restore verification, local/checksummed and optionally OpenSSL-signed updates, rollback, integration tests, and benchmarks;
- an optional PostgreSQL analytics mirror while SQLite remains the primary database.

```bash
./install.sh
./recon-monitor.sh setup
./recon-monitor.sh doctor
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
./recon-monitor.sh run --target example.com --dry-run
./recon-monitor.sh run --target example.com
```

Dashboard setup:

```bash
./recon-monitor.sh dashboard auth-set --username admin
./recon-monitor.sh dashboard start --open
```

Active modules remain disabled unless all authorization gates are satisfied. Endpoint validation is also disabled by default and, when enabled, performs only in-scope `HEAD` requests. See `README_FA.md`, `docs/ARCHITECTURE.md`, and `docs/SECURITY.md`.





## Safe Validation and Analyst Feedback in 5.1

Version 5.1 adds candidate-specific safe-validation plans, exact approvals, authorization and scope gates, strict budgets, redacted observations, and structured analyst feedback. Executable validation is restricted to offline analysis and low-risk in-scope `GET`, `HEAD`, or `OPTIONS` requests. Controlled authorization families receive plans only, while SSRF, executable XSS, uploads, traversal, races, payment, recovery, role changes, and destructive workflows remain manual-only. HAR and Burp XML imports are scope-filtered and redacted, and no imported or live response body is stored raw. Database schema is 14. See `docs/SAFE_VALIDATION_ENGINE.md` and `MIGRATION-v5.1.md`.

```bash
./recon-monitor.sh validation eligibility --case-id CASE_ID
./recon-monitor.sh validation plan --case-id CASE_ID --level offline
./recon-monitor.sh validation run --plan-id PLAN_ID
```

## Production Platform in 5.0

Version 5.0 adds an Engine Quality Platform, case-first Investigation Workspace, Scope and Operations centers, target-specific learning, noise budgets, incremental reasoning reuse, plugin manifest governance, and a decision-centered dashboard. Database schema is 13. See `MIGRATION-v5.0.md` and the `docs/*PLATFORM.md` guides.

## Security Reasoning Core in 4.6.0

Version 4.6 introduces an explainable security-reasoning layer over the existing candidate, semantic, and behavioral engines. It adds unified evidence provenance, independent evidence roots, family-specific preconditions, formal unknown states, falsification, Top-3 vulnerability-family ranking, calibrated likelihood, exploitability confidence, evidence coverage, Golden Dataset evaluation, per-family calibration, shadow rules, and a regression gate. Database schema is 12. See `docs/SECURITY_REASONING_CORE.md` and `MIGRATION-v4.6.md`.

## Stabilization release in 4.5.1

Version 4.5.1 keeps database schema 11 and focuses on reliability. It finalizes failed analysis runs instead of leaving them permanently `running`, adds defensive decoding for legacy/corrupt JSON, repairs stale run/stage/work-item state, corrects Doctor schema validation, deepens backup verification, and adds an isolated restore drill.

```bash
./recon-monitor.sh repair --dry-run --json-health
./recon-monitor.sh repair --max-age-hours 24
./recon-monitor.sh backup verify latest
./recon-monitor.sh backup drill latest
```

See `docs/STABILITY_AND_RECOVERY.md` and `MIGRATION-v4.5.1.md`.

## Version 3.1 dashboard

Version 3.1 adds a redesigned analyst console and `/workbench`. See `docs/ANALYST_WORKSPACE.md`. Schema 7 remains unchanged.

## Analysis Engine 4.0

Recon Monitor now includes an offline evidence and hypothesis engine. It adds target-specific baselines, analyst-feedback learning, evidence-for/evidence-against, duplicate clustering, replay, endpoint schemas, review playbooks, deployment signatures, static JavaScript data-flow candidates, source-map intelligence, GraphQL intelligence, secret confidence, API relationships, business context and quality calibration.

```bash
./recon-monitor.sh analyze --run RUN_ID
./recon-monitor.sh analysis replay --run RUN_ID
./recon-monitor.sh analysis quality
./recon-monitor.sh analysis calibration
```

Dashboard pages: `/analysis`, `/hypotheses`, `/clusters`, `/dataflows`, and `/analysis-quality`.

Analysis and replay are offline and do not send new requests to the target. Static candidates and hypotheses do not confirm a vulnerability. The optional AI layer is not included.

See `docs/ANALYSIS_ENGINE.md` for the complete model and safety boundaries.

## Bug Candidate Engine 4.1

Analysis replay now maps evidence to probable vulnerability families without active exploitation. Each candidate has separate likelihood, evidence-strength, impact-potential, state, missing evidence, and a safe next action. Automatic analysis never marks a vulnerability as confirmed.

```bash
./recon-monitor.sh analyze --run RUN_ID
./recon-monitor.sh analysis candidates --limit 100
```

See `docs/BUG_CANDIDATE_ENGINE.md` and `MIGRATION-v4.1.md`.


## Candidate Reliability & Semantic Intelligence 4.3

Version 4.3 combines the planned 4.2 reliability and 4.3 semantic upgrades. It adds family-specific evidence gates, independent-evidence grouping, observation-quality and investigation-value scoring, analysis profiles, candidate lifecycle, structured feedback, per-family calibration, endpoint contracts, authentication boundaries, response-shape fingerprints, semantic JavaScript units, feature flags, parameter relationships, and candidate bundles.

```bash
./recon-monitor.sh analysis replay --run RUN_ID --profile balanced
./recon-monitor.sh analysis candidate-calibration
./recon-monitor.sh analysis candidate-evaluate
./recon-monitor.sh analysis bundles --limit 100
./recon-monitor.sh analysis semantic --limit 200
```

Dashboard pages: `/candidate-quality`, `/candidate-bundles`, and `/semantic-intelligence`. Schema version is 10. Replay remains offline and does not contact the target. See `docs/CANDIDATE_RELIABILITY_ENGINE.md`, `docs/SEMANTIC_CANDIDATE_INTELLIGENCE.md`, and `MIGRATION-v4.3.md`.


## Behavioral Intelligence Engine in 4.5.0

Recon Monitor 4.5 compares stored analysis snapshots without sending additional requests. It detects authentication-boundary transitions, redacted response-structure changes, protocol-specific REST/GraphQL/WebSocket/OAuth/cache evidence, and identity/authorization relationships. Behavioral evidence is added to candidates, but candidates remain unverified until an analyst records a decision.

```bash
./recon-monitor.sh analysis replay --run RUN_ID --profile balanced
./recon-monitor.sh analysis behavioral
./recon-monitor.sh analysis boundary-diffs
./recon-monitor.sh analysis response-diffs
./recon-monitor.sh analysis protocols
./recon-monitor.sh analysis identity-graph
```

Dashboard: `/behavioral-intelligence`  
Documentation: `docs/BEHAVIORAL_INTELLIGENCE_ENGINE.md`  
Migration: `MIGRATION-v4.5.md`

## Decision-centered dashboard in 4.3.1

The primary workflow is now `Command center → Review queue → technical drill-down`. Daily navigation is reduced to Focus, Investigate, Explore, and Operations; specialist pages remain under Advanced tools. The Review queue separates Review now, Needs evidence, Watchlist, Confirmed, and All active candidates. Candidate cards expose investigation value, the four quality scores, reasoning, missing evidence, and the next safe action. Schema remains 10. See `docs/DECISION_CENTERED_DASHBOARD.md`.


## 5.0.1 dashboard performance

See `docs/DASHBOARD_PERFORMANCE.md` for snapshot caching, bounded pagination, and explicit deep-refresh behavior.
