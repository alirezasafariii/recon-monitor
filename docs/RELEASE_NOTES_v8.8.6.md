# Recon Monitor 8.8.6 — httpx Security Header Integrity

Application version: **8.8.6**. Core database schema: **18**, unchanged.

ProjectDiscovery httpx JSON replaces hyphens in response header names with underscores. The fingerprint parser now restores canonical hyphenated names before its security-header allowlist, preserving valid HSTS, CSP and other allowed policies instead of generating false missing-header evidence.

- Keep sensitive-header exclusions, value bounds and support for ordinary HTTP header names.
- Preserve the distinction between observed headers without a security policy and unavailable header output. HSTS technology tags do not substitute for a direct policy value.
- Add offline producer-format regressions through parsing, database persistence, passive evidence and Analysis; valid policies do not produce false HSTS/security-header candidates, including updates with an unchanged fingerprint hash.
- Synchronize short-deadline test fixtures with their emitted output and Safari native navigation with the real pointer target. Runtime timeout values are unchanged.

## Upgrade and historical data

Use the normal verified Update path. No schema migration or new scan is required for installation. Existing configuration, records and immutable Analysis snapshots are preserved. Previously discarded header values cannot be recovered from an empty stored mapping or technology tag. Reprocess retained raw httpx output, where available, before regenerating affected Analysis; otherwise a future authorized collection is needed. This release does not silently rewrite historical candidates. See MIGRATION-v8.8.6.md.
