# Recon Monitor 8.8.11 — Migration

Application version: **8.8.11**. Database schema: **18**, unchanged.

Some dnsx 1.2.3 invocations omit NXDOMAIN and empty requested RRsets despite rcode filtering. Wildcard enrichment now retries clean omissions using optional system dig against the explicit resolver 8.8.8.8. Primary DNS collection is unchanged.

Only complete matching DNS replies are accepted. Negative observations require an explicit NXDOMAIN or empty NOERROR with authority SOA evidence. Warning, failed, malformed or conflicting dnsx responses, missing dig, truncated replies and timeouts remain unknown and preserve existing flags. Stable explicit negative controls can clear previous wildcard flags; positive wildcard controls remain supported.

Each additional attempt respects scope, runtime/operator interruption, DNS budget and rate. Fallback is capped at 128 attempts per detector invocation, with one attempt per query and a process deadline at most five seconds. Production timeout configuration, primary DNS integrity, baseline independence and downstream host preservation are unchanged. Raw fallback replies and normalized outcomes are retained for audit. There is no automatic historical data repair.

Offline validation covers the full omission-to-explicit-negative classification path, strict reply parsing, budget/scope/cap/interruption guards and timeout preservation. Live macOS acceptance with the new release remains pending.

Publication requires successful CI for the exact main commit, archive/manifest verification, fixture integration, actual legacy/current updater installs and downloaded asset verification before publishing Latest.

Install with the standard updater and verified checksum. No schema migration is required. dig is optional; without it omitted control responses remain unknown.
