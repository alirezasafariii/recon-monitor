# Recon Monitor 3.0 architecture

```text
Wizard / CLI / Session Dashboard / Token API
                    |
             Scope-aware planner
                    |
            Run orchestrator + budgets
                    |
     +--------------+----------------+
     |                               |
Tool-native batch stages       SQLite work queue
(subdomains, DNS, URLs,        (JavaScript and safe
fingerprints, active gates)     endpoint validation)
     |                               |
     +---------------+---------------+
                     |
          Database writer / transactions
                     |
       SQLite schema 7 (primary database)
                     |
  +------------------+---------------------------+
  |                  |                           |
CAS object store   Intelligence/event engine   Evidence manifests
JS/source maps     confidence/risk/incidents   SHA-256 integrity
  |                  |                           |
  +------------------+---------------------------+
                     |
 Reports / Telegram / Dashboard / API / optional
          PostgreSQL analytics mirror
```

## Primary components

- `app/recon_monitor.py`: CLI and orchestration.
- `app/core.py`: policy, configuration, SQLite schema, audit, lifecycle, correlation, and core models.
- `app/execution.py`: budgets, persistent work queues, workers, and database writer.
- `app/stages.py`: authorized data-collection and analysis stages.
- `app/storage.py`: content-addressed object storage.
- `app/plugins.py`: plugin manifests and health registry.
- `app/dashboard.py` and `app/session_auth.py`: session/RBAC dashboard.
- `app/api_server.py`: role-aware local API.
- `app/remote_worker.py`: restricted worker agent.
- `app/operations.py`: backup, restore, update, rollback, and benchmark.
- `app/postgres_mirror.py`: optional analytics mirror.

## Execution model

A run creates per-target budgets and persistent stage records. JavaScript and endpoint-validation inputs are represented as individual `work_items`, enabling precise retry and resume. Batch-oriented external tools continue to execute as stages because their own internal work partitioning is not safely observable.

The single-writer path serializes queued mutation events. Other read/query operations use short-lived or thread-safe SQLite connections. WAL mode and busy timeouts improve coexistence between CLI, dashboard, API, and background activity.

## Data model additions in schema 7

- work items and run budgets;
- ignore rules;
- correlated change incidents;
- lifecycle state;
- endpoint-validation observations;
- object-store references;
- evidence-integrity manifests;
- audit log;
- saved views;
- dashboard users and API tokens;
- remote workers;
- plugin registry;
- backup catalog.

## Local-first boundary

SQLite and files under the project directory remain the source of truth. PostgreSQL synchronization is one-way analytics mirroring. The API and dashboard bind to loopback by default. Remote workers only receive supported task types and must validate root scope.
