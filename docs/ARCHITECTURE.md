# Recon Monitor architecture

<!-- recon-monitor-current: app=8.8.1 schema=18 -->

Recon Monitor is a local-first, authorization-gated attack-surface monitoring and vulnerability-reasoning platform. The canonical application version and core database schema version are defined in `app/core.py` as `APP_VERSION` and `SCHEMA_VERSION`. For the current build they are **8.8.1** and **18**.

```text
Target / Policy / Authorization
             |
      Recon Orchestrator
             |
  +----------+-----------+
  |                      |
Collection stages     Work queues / budgets
  |                      |
  +----------+-----------+
             |
      Single-writer SQLite
             |
   Working Recon observations
             |
     Collection completeness
             |
  +----------+------------------------------+
  |                                         |
Successful Recon snapshot             Downstream processing
(canonical comparison state)                 |
  |                                   Analysis / reasoning
  |                                         |
Change detection + stable confirmation   Potential Findings
  |                                         |
Recon Change Alerts                  Finding Notifications
  |                                         |
  +------------------+----------------------+
                     |
            Reports / Dashboard / API
```

## Version and schema contract

`app/core.py` is the source of truth for the release-facing metadata:

- `APP_VERSION = "8.8.1"`
- `SCHEMA_VERSION = 18`

`SCHEMA_VERSION` identifies the **core SQLite schema** created and maintained by `Database.migrate()`. Reliability features added after the core schema-18 migration use additive, independently versioned compatibility schemas rather than pretending to be a new core migration. Their metadata is stored in `schema_meta`, including `successful_snapshot_schema_version`, `stable_confirmation_schema_version`, `finding_notification_schema_version`, and the explicit target-lifecycle metadata key.

This distinction is deliberate: a release may add backward-compatible feature tables without changing the core schema number, but those feature schemas must remain self-versioned and idempotent. A future change that alters the core schema contract must increment `SCHEMA_VERSION` and provide the corresponding migration documentation.

## Execution and lifecycle model

A target run has separate operational truths rather than one overloaded success flag:

- **collection status**: whether Recon collection completed sufficiently to produce a trustworthy comparison snapshot;
- **analysis status**: whether vulnerability reasoning completed;
- **report status**: whether report generation completed;
- **notification status**: whether Potential Finding delivery completed, was queued, or failed;
- **overall status**: `success`, `partial`, `failed`, or `interrupted` derived from those components.

Baseline eligibility is collection-driven. A complete Recon collection can establish or refresh the canonical comparison snapshot even when Analysis, reporting, or notification later makes the overall target partial. An incomplete collection can never advance the baseline.

## Successful snapshot boundary

The mutable Recon tables remain the working view during a run so existing resume and Analysis behavior stays compatible. Comparison-critical state is separately committed only after collection is trustworthy. The successful snapshot currently covers assets, DNS records, URLs, and HTTP fingerprints.

A fresh run restores the last committed snapshot before collection. Failed or interrupted runs may mutate working rows, but those rows never become the comparison baseline. This prevents a failed run from hiding a later real new asset, DNS rotation, URL, or fingerprint change.

## Stable change confirmation

Volatile DNS and fingerprint changes are confirmed by observed **state version**, not merely by counting emitted change events. For example, `A → B → B` confirms B on the second trustworthy observation, while `A → B → C` starts a new confirmation sequence for C. Provisional confirmation observations are promoted only when Recon collection is baseline-eligible.

## Analysis and Potential Findings

Recon observations feed the analysis/reasoning stack. Potential Findings are evidence-backed security hypotheses and are not equivalent to confirmed vulnerabilities. Canonical Admission remains the authority for determining whether evidence is sufficient to create or promote a Potential Finding.

Typed and reviewed evidence are admitted only through explicit offline boundaries. Passive-live observations are adapted without new target traffic, and controlled differential review artifacts are redacted, integrity-checked, provenance-aware, and fail closed on contradictions or missing structural requirements. Reviewed evidence can reach canonical Admission through the generic dispatcher, but the strongest automatic outcome remains a Potential Finding rather than vulnerability confirmation.

Finding notifications are independent from Recon Change Alerts. New or materially changed Potential Findings are queued into a durable outbox, delivered by the scheduled/retry worker, and tracked through queued, retry-pending, delivering, delivered, failed, and dead-letter operational states. Delivery failures do not mutate Candidate or Admission truth. Recon Change Alerts retain their own lifecycle semantics but share the same public `notification_transports` boundary for Telegram and ProjectDiscovery `notify` delivery.

## Storage and concurrency

SQLite under `state/` remains the transactional source of truth. The database uses WAL mode, busy timeouts, connection-wide transaction locking, and a serialized writer path for queued mutation events. Audit-log and audit-integrity rows are appended under the same SQLite write transaction so concurrent writers cannot fork the hash-chain head. Content-addressed evidence and source objects live under the local object store with SHA-256 integrity metadata. PostgreSQL, when configured, is an analytics mirror rather than the primary transactional store.

## Primary components

- `app/recon_monitor.py` and `app/recon_monitor_core.py`: CLI and orchestration surface.
- `app/core.py`: canonical application/core-schema metadata, policy/configuration, SQLite core schema, audit, lifecycle primitives, and shared models.
- `app/execution.py`: budgets, persistent work queues, workers, and serialized database writer.
- `app/stages.py`: authorized Recon collection and report-stage execution.
- `app/successful_snapshot.py`: successful Recon comparison commit boundary and runtime reliability integration.
- `app/stable_confirmation.py`: state-version confirmation for volatile changes.
- `app/run_lifecycle_state.py` and `app/lifecycle_status.py`: explicit component lifecycle and baseline eligibility.
- `app/analysis_engine.py` and family reasoning modules: evidence-driven vulnerability analysis.
- `app/finding_notifications.py`: idempotent Potential Finding notification event lifecycle.
- `app/finding_notification_outbox.py`: durable queue, retry, lease, delivery, and dead-letter operations for Finding notifications.
- `app/notification_transports.py`: transport-neutral outbound delivery shared by Finding notifications and Recon Change Alerts.
- reviewed-evidence adapters/dispatcher: offline controlled review and canonical Admission orchestration without target-side execution.
- `app/storage.py`: content-addressed object storage.
- `app/dashboard.py`, `app/session_auth.py`, and `app/api_server.py`: local analyst interfaces.
- `app/operations.py`: backup, restore, update, rollback, and benchmark operations.

## Safety boundary

Authorization and target scope are mandatory inputs. Active or live behavior remains explicitly policy- and CLI-gated. Potential Findings are hypotheses, not automatic vulnerability confirmations. Passive-live validation is bounded by its dedicated eligibility and execution gates, and downstream reporting or notification failures do not rewrite the truth of already-completed Recon collection.

## Documentation consistency

`tools/check_release_consistency.py` verifies in CI that the CLI, `app/core.py`, README files, this architecture document, CHANGELOG, current migration guide, and current release notes all agree on the application version and core schema version. Historical sections may retain the version/schema values that were correct for those releases.
