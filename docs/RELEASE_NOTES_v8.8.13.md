# Recon Monitor 8.8.13 — dig Configuration Isolation

Application version: **8.8.13**. Database schema: **18**, unchanged.

Remove HOME only from the dig child environment instead of checking user .digrc before execution. Apple/BIND dig therefore skips implicit user configuration without the unsupported -r option. The parent environment and user files are unchanged. This closes the configuration check-before-execution race and permits bounded fallback even when a user .digrc exists.

Primary DNS retirement, resolved-host coverage, baseline eligibility, scope, budgets, rate, timeout, runtime/operator checks and strict response validation are unchanged. Real subprocess regressions verify configuration isolation, environment-removal precedence and preservation of the parent environment.

Correct the stale Persian release heading and the claim that wildcard detection is unpublished. Full live detector acceptance on the installed macOS release remains pending; offline and CI evidence do not substitute for that acceptance. No schema migration or automatic historical data repair is required.

Publication requires successful CI for the exact main commit, source/manifest/archive verification, fixture integration, actual legacy/current updater installation and downloaded asset verification.
