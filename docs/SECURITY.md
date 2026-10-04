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
- Remote work carries a versioned snapshot of the effective target roots and
  `include`/`exclude` rules, without target headers or credentials. Workers
  enforce those rules within the declared roots before DNS or network access
  and on every redirect hop for both `HEAD` and downloads.
- Update the API server and remote workers together. The API leases scoped work
  only to workers advertising the supported scope version and rejects malformed,
  out-of-scope, or target-mismatched tasks. Legacy roots-only work is not leased
  remotely; it can still be processed by local Resume. New workers reject
  roots-only payloads, and new payloads omit `allowed_roots` so old workers cannot
  silently fall back to a broader policy.
- Workers and the receiving API classify transport results against the leased
  task. Connection errors and timeouts stay `retry_pending`; safety stops and
  incomplete downloads become `failed`. A valid HEAD response (including 404)
  completes an observation; downloads require 2xx. HTTP 429 is retryable for
  either kind, and download HTTP 408/425/5xx responses are also retryable.
  The API retains failure metadata in `result_json` and enforces a five-second
  minimum retry delay (60 seconds for 429), extended by `Retry-After` when
  supplied as seconds or an HTTP date. The controller records its decision in
  `_worker_outcome`; older workers cannot mark transport failures completed
  simply by sending `ok=true`.
- External plugins are code and must be reviewed before enabling. Plugin manifests and health checks are not a sandbox.

## Evidence and storage

- JavaScript diffs redact common secret patterns before persistence, but no detector is perfect.
- Evidence exports may contain sensitive metadata and should be encrypted in transit and at rest.
- Evidence manifests and content-addressed object hashes help detect modification but are not a legal digital-signature system.
- Backup archives may contain configuration, database history, notes, and evidence. Referenced CAS/evidence artifacts are included even without `--include-objects`; verification fails if a database reference cannot be recovered from the archive.

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
