# Recon Monitor 8.8.12 — macOS dig Compatibility

Application version: **8.8.12**. Database schema: **18**, unchanged.

Apple dig 9.10.6 rejects -r and exited before sending wildcard fallback queries. Remove the unsupported option. Fallback runs only when ~/.digrc is provably absent; existing files, symlinks or unreadable configuration yield an audited unknown without sending a query or consuming DNS budget. User configuration is never changed.

The bounded explicit-negative DNS parser, scope, budgets, rate, timeout, runtime/operator checks and audit artifacts are retained. Primary DNS retirement, resolved hosts and baseline eligibility are unchanged. A real CommandRunner regression executes an offline producer that rejects the unsupported flag and validates the remaining arguments; configuration absence/file/symlink/permission regressions are also covered.

The captured macOS NXDOMAIN response is accepted by the strict parser. Full live detector acceptance on the installed release remains pending. Documentation headings were refreshed. No schema migration or automatic historical data repair is required.

Publication requires successful CI for the exact main commit, source/manifest/archive verification, fixture integration, actual legacy/current updater installation and downloaded asset verification.
