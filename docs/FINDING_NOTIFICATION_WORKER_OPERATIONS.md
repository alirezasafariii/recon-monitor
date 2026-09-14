# Finding Notification Worker Operations

Potential Finding delivery is queue-centric and independent from Recon Change Alerts and target scan cadence.

## Operational model

`notification_events` and `finding_notification_outbox` remain the durable delivery boundary. The operational layer adds a worker policy, worker-run history, diagnostics, and a dead-letter registry. It does not change Canonical Admission, Candidate state, reviewed-evidence semantics, or target-side collection.

The default worker policy is enabled with a 60-second interval and a batch limit of 100. The interval is bounded to 60–3600 seconds and the batch limit to 1–500. A worker tick only runs when its policy interval is due unless explicitly forced.

## Operator commands

Inspect queue health:

```bash
python3 tools/deliver_finding_notifications.py status
```

Run one due scheduler tick:

```bash
python3 tools/deliver_finding_notifications.py run
```

Run one tick regardless of the interval:

```bash
python3 tools/deliver_finding_notifications.py run --force
```

Run the queue-centric scheduler loop:

```bash
python3 tools/deliver_finding_notifications.py watch
```

Configure the worker:

```bash
python3 tools/deliver_finding_notifications.py configure --enable --interval-seconds 60 --batch-limit 100
```

List open dead letters:

```bash
python3 tools/deliver_finding_notifications.py failed
```

Retry one terminal failure:

```bash
python3 tools/deliver_finding_notifications.py retry --event-id notify-...
```

Drain all events that are currently due, in bounded batches:

```bash
python3 tools/deliver_finding_notifications.py drain --limit 100 --max-batches 20
```

## Diagnostics

Status reports queue depth, due-now count, queued/retry/delivering/delivered/failed counts, the oldest pending timestamp and age, open dead-letter count, current worker policy, and the last worker run.

Terminal failures are copied into `finding_notification_dead_letters`. Retrying a dead letter resets the outbox event to retry-pending and records a resolution on the dead-letter row. If the event later fails terminally again, the dead-letter entry is reopened with the latest error and attempt count.

## Reliability boundaries

The outbox lease still protects against simultaneous workers claiming the same event. A worker crash leaves an expiring delivery lease that the existing outbox code reclaims. Delivery remains at-least-once across the external transport boundary: a process can still crash after a remote service accepts a message but before the local transaction commits.

The operational worker never mutates Potential Findings, Canonical Admission, or reviewed evidence. Recon Change Alerts remain a separate notification stream with independent state and deduplication semantics.
