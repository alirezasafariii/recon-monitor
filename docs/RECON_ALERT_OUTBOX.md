# Durable Recon Change Alert Outbox

Recon Change Alerts keep their existing baseline, confirmation, score, cooldown, ignore/false-positive, and notification-policy semantics. The delivery boundary is now durable and independent from the Potential Finding notification outbox.

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

Transport failure never marks the Alert as notified. A failed attempt moves to `retry_pending` with bounded exponential-style backoff. Delivery uses a lease so a crashed worker can be reclaimed after lease expiry. After the configured maximum attempt count the row moves to `failed`; an operator can explicitly requeue it.

The external transport boundary remains at-least-once. A remote service may accept a message immediately before the process loses local state, so downstream receivers should still tolerate duplicates.

## Worker

Run one delivery pass:

```bash
python tools/deliver_recon_alerts.py run
```

Inspect queue state:

```bash
python tools/deliver_recon_alerts.py status
```

Requeue failed events:

```bash
python tools/deliver_recon_alerts.py retry --event-id RAO-...
```

Run continuously with a bounded polling interval:

```bash
python tools/deliver_recon_alerts.py watch --interval-seconds 60
```

Filters are available through `--target` and `--run-id`. `--max-cycles` is useful for supervised or test operation.

## Separation from Finding delivery

`recon_alert_notification_outbox` and `finding_notification_outbox` intentionally remain separate. They share only `app/notification_transports.py`. Recon Alert delivery failure therefore cannot rewrite Potential Finding, Candidate, Canonical Admission, or reviewed-evidence truth, and Finding delivery state cannot change Recon Alert lifecycle state.
