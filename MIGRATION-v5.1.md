# Migration to Recon Monitor 5.1.0

Recon Monitor 5.1.0 upgrades the Safe Validation and Analyst Feedback layer while preserving the 5.0 case-first platform and dashboard-performance changes.

## Supported direct upgrade

The release patch accepts Recon Monitor `5.0.1` and `5.1.0` installations. Upgrade from an earlier release through 5.0.1 first.

## Database migration

Schema changes are additive:

```text
13 → 14
```

New records cover validation plans, approvals, runs, observations, feedback, and imported HTTP evidence. Security Cases receive validation status, summary, and last-validation fields. Existing runs, alerts, candidates, cases, decisions, notes, evidence, policies, users, tokens, artifacts, custom plugins, and configuration remain in place.

## Safety boundary

Version 5.1 is a validation engine, not an exploitation engine.

Executable live plans are restricted to low-risk, in-scope `GET`, `HEAD`, and `OPTIONS` requests. The executor does not replay cookies or credentials, does not follow redirects, strips query strings from candidate URLs, does not store response bodies raw, uses concurrency one, and applies strict request, runtime, and response-size limits.

BOLA/BFLA, cross-tenant, mass assignment, GraphQL/WebSocket authorization, and other controlled families can produce plans but are not executed automatically. SSRF, executable XSS, file upload, path traversal, races, payment/refund, account recovery, role changes, webhooks, and destructive operations are manual-only.

## Recommended upgrade

```bash
cd ~/Downloads/recon-monitor
./recon-monitor.sh backup create --include-objects
./recon-monitor.sh backup verify latest

PATCH=$(find "$HOME/Downloads" -maxdepth 1 \
  -name 'apply-recon-monitor-v5.1.0-safe-validation*.sh' \
  -print -quit)

bash "$PATCH" "$HOME/Downloads/recon-monitor"
```

## Verification

```bash
./recon-monitor.sh --version
./recon-monitor.sh test --verbose
./recon-monitor.sh test --integration
./recon-monitor.sh validation --help
```

Expected version and schema:

```text
Version: 5.1.0
Schema: 14
```

## Rollback

The provided patch snapshots the program files and uses SQLite online backup before migration. If compilation, schema, integrity, tests, integration, or the offline validation smoke test fails, the patch restores the previous program and database.
