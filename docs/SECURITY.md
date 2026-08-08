# Security notes — Recon Monitor 3.0

## Authorization and scope

- Use the program only for assets you own or are explicitly authorized to assess.
- Dry-run should be reviewed before a new or modified target policy is executed.
- Nuclei and port monitoring remain protected by global configuration, target-policy confirmation, and the `--allow-active` CLI gate.
- Endpoint validation is separate from active vulnerability scanning, is disabled by default, uses only in-scope `HEAD` requests, and obeys budgets/rate limits.

## Dashboard and API

- Dashboard and API default to loopback.
- Dashboard uses sessions, RBAC, CSRF tokens, HttpOnly/SameSite cookies, expiration, and login throttling.
- API tokens are stored only as SHA-256 hashes; the plaintext token is displayed once at creation.
- Neither service provides TLS by itself. Use an SSH tunnel, VPN, or trusted TLS reverse proxy for remote access.
- A non-loopback bind requires explicit remote enablement.

## Secrets

- Prefer macOS Keychain for Telegram tokens, provider keys, webhooks, and other credentials.
- Keep `config.env` mode `0600`.
- Never include Keychain values, API tokens, or `config.env` in public issue reports or repositories.

## Workers and plugins

- Remote workers support only explicitly implemented task types and do not run arbitrary shell commands.
- Workers validate declared roots before network access.
- External plugins are code and must be reviewed before enabling. Plugin manifests and health checks are not a sandbox.

## Evidence and storage

- JavaScript diffs redact common secret patterns before persistence, but no detector is perfect.
- Evidence exports may contain sensitive metadata and should be encrypted in transit and at rest.
- Evidence manifests and content-addressed object hashes help detect modification but are not a legal digital-signature system.
- Backup archives may contain configuration, database history, notes, and evidence.

## Updates and restore

- Verify release SHA-256 before installation.
- The updater accepts a local package or a configured trusted manifest; trust of the source remains the operator's responsibility.
- Restore requires `--force` and creates a safety backup first.

## PostgreSQL

- PostgreSQL is an optional analytics mirror. Secure the DSN and network path.
- Do not expose the PostgreSQL service publicly.

## Operational recommendations

- Keep request budgets conservative.
- Use stable, tested versions of external reconnaissance tools.
- Run `doctor`, unit tests, and integration tests after updates.
- Inspect audit logs after administrative or active-module changes.
