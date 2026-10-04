# Recon Monitor 8.8.2 — Collection Integrity & Operational Reliability

Recon Monitor 8.8.2 publishes the collection, Resume, worker, update, API, and data-integrity fixes merged after 8.8.1. It also includes bounded JavaScript validation tools and the per-run execution review introduced during that period.

## Collection truth and Resume

- Incomplete DNS collection preserves stored DNS records instead of treating missing observations as deletions. Subdomain, DNS, Wayback, and Katana outcomes retain their actual exit status, interruption reason, timing, and partial output.
- Katana processes small, sequential batches of authorized origins. Completed and pending origins, per-batch tool evidence, and shared request/rate/runtime accounting survive interruption and Resume. Partial collection cannot refresh a successful comparison baseline.
- Operator Next saves a partial checkpoint and stops new queued requests. Resume processes pending work and refreshes affected downstream stages.
- Large stdin is fed under the same timeout/cancellation supervision as stdout and stderr. Pipe cleanup and process-group shutdown retain collected output without waiting indefinitely.
- Analysis input snapshots refresh when resumed collection changes the inputs. Derived Analysis tags are excluded from those inputs, preserving deterministic replay.

## JavaScript and worker reliability

- JavaScript selection is balanced across hosts, and selection/backlog diagnostics explain absent artifacts. Source-map work items resume independently from their parent JavaScript downloads.
- Literal-aware JavaScript normalization preserves meaningful string/regex changes while ignoring formatting-only differences.
- Versioned worker scope is checked for each request and redirect. Transport errors, retry cooldowns, and HTTP 429 outcomes remain incomplete rather than becoming successful empty work.
- Verified worker artifact transfer retains JavaScript files with integrity and path checks. Resume validates the retained artifact before reusing completed work.
- Opt-in bounded JavaScript validation and isolated replay tools reuse saved URL evidence and explicit authorization/budget controls. Interrupted replay does not silently re-request previously selected inputs.

## Update, API, notifications, and storage

- Update prepares the complete program copy before activation and restores the previous program tree after activation/validation failures. Copy failures leave the installed program intact.
- Local API shutdown uses an instance-specific control channel on Linux and macOS. Legacy Linux process handling validates identity through pidfd; unsupported legacy stop paths fail closed. Loopback binding avoids reverse-DNS startup stalls.
- Scheduled-run and revalidation API requests load project configuration for each request.
- Finding notifications split long output into bounded batches and retain per-batch delivery receipts instead of silently truncating findings.
- PostgreSQL mirror identity handles composite/text primary keys and migrates legacy mirror keys without collapsing distinct records.

## Controlled empty states

- `/case` and `/evidence/export` return HTTP 400 for missing required selectors and HTTP 404 for unknown case/alert IDs. Valid alert-only Evidence ZIP downloads remain supported.
- `/api/v1/suite/data-quality` returns HTTP 404 with an explicit error code when the requested Run or target data is unavailable. It does not fabricate a zero-score snapshot.
- Platform sync continues other Analysis, case, and validation work for legacy Runs without quality inputs, with an explicit unavailable quality result. Unexpected internal failures remain visible.

## Compatibility and release assets

- Application version: **8.8.2**.
- Core database schema: **18**; upgrade from 8.8.1 uses additive, idempotent compatibility initialization.
- Legacy Analysis snapshots predating immutable entity-tag capture still require regeneration before replay. The fingerprint XML-root path still requires httpx `-er` support.
- Update coordinator and remote workers together so scope, result, and artifact contracts agree.
- The release includes `recon-monitor-v8.8.2.zip` and `recon-monitor-v8.8.2.zip.sha256`, compatible with the authenticated GitHub update path.

Publication is gated by strict manifest validation, canonical release metadata, dependency-range coverage, the full 1,586-test suite on Python 3.11 and 3.13, fixture integration, and macOS API lifecycle checks. The downloadable ZIP is checked against the exact tested source tree. No target scan is performed to build or publish this release.
