# Durable Recon Change Alert Outbox

Recon Change Alerts keep their existing baseline, confirmation, score, cooldown, ignore/false-positive, and notification-policy semantics. The delivery boundary is durable and independent from the Potential Finding notification outbox.

## Flow

```text
Recon Change
  -> existing Alert eligibility policy
  -> recon_alert_notification_outbox
  -> Recon Alert worker
  -> app/notification_transports.py
  -> alerts.last_notified only after successful external delivery
```

The queue is keyed deterministically by `alert_id + run_id`. Replaying the same report stage cannot create a second delivery event for the same Alert occurrence. If an older occurrence is still queued, retry-pending, delivering, or terminally failed, a later run does not create a competing notification for the same Alert until the unresolved delivery is handled.

## Failure semantics

Transport failure never marks the Alert as notified. A failed attempt moves to `retry_pending` with bounded exponential-style backoff. Delivery uses a lease so a crashed worker can be reclaimed after lease expiry. After the configured maximum attempt count the row moves to `failed` and is mirrored into `recon_alert_dead_letters` for operator recovery and history.

Retrying a dead letter resets the outbox row to retry-pending and records `resolved_at` plus a resolution on the dead-letter row. If the event later fails terminally again, the dead-letter record is reopened with the latest attempt count and error.

The external transport boundary remains at-least-once. A remote service may accept a message immediately before the process loses local state, so downstream receivers should still tolerate duplicates.

## Scheduled worker operations

The worker policy is persisted in `recon_alert_worker_policy`. Its default scheduler interval is 60 seconds and its default batch size is 100; supported intervals are clamped to 60-3600 seconds and batches to 1-500 events. Every executed pass is recorded in `recon_alert_worker_runs` with the trigger, due count, attempted/delivered/retry/failed counts, timestamps, and terminal error if the worker itself fails.

Run one scheduler-aware pass:

```bash
python tools/deliver_recon_alerts.py run
```

Force a pass regardless of the configured scheduler interval:

```bash
python tools/deliver_recon_alerts.py run --force
```

Inspect diagnostics, including queue depth, due-now count, oldest pending age, open dead letters, worker policy, and the latest worker run:

```bash
python tools/deliver_recon_alerts.py status
```

Inspect open dead letters:

```bash
python tools/deliver_recon_alerts.py failed
```

Requeue one dead letter:

```bash
python tools/deliver_recon_alerts.py retry --event-id RAO-...
```

Drain multiple due batches with explicit safety bounds:

```bash
python tools/deliver_recon_alerts.py drain --limit 100 --max-batches 20
```

Run the persisted scheduler loop:

```bash
python tools/deliver_recon_alerts.py watch
```

Configure scheduler policy:

```bash
python tools/deliver_recon_alerts.py configure --enable --interval-seconds 60 --batch-limit 100
python tools/deliver_recon_alerts.py configure --disable
```

`--target` and `--run-id` can constrain manual `run` and `drain` operations. `--target` also scopes diagnostics and dead-letter listing/retry. `--max-cycles` provides a bounded watch loop for supervised execution and tests.

## Operational tables

The operational layer adds three independently versioned tables without changing the core schema version:

- `recon_alert_worker_policy` — persistent enable/interval/batch configuration.
- `recon_alert_worker_runs` — scheduler and manual worker run history.
- `recon_alert_dead_letters` — terminal delivery failures and their recovery history.

These tables are additive compatibility state. They do not redefine the core Recon Monitor schema version.

## Separation from Finding delivery

`recon_alert_notification_outbox` and `finding_notification_outbox` intentionally remain separate. They share only `app/notification_transports.py`. Recon Alert delivery failure therefore cannot rewrite Potential Finding, Candidate, Canonical Admission, or reviewed-evidence truth, and Finding delivery state cannot change Recon Alert lifecycle state.
