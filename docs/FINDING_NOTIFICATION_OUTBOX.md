# Finding Notification Outbox

Potential Finding notification delivery is separated from Analysis, Canonical Admission, Candidate creation, and reviewed-evidence dispatch.

## Pipeline

```text
Reviewed Evidence
  -> Canonical Admission
  -> Potential Finding
  -> notification_events
  -> finding_notification_outbox
  -> delivery worker
  -> configured notification transports
```

`notification_events` remains the stable event identity and transition-deduplication surface. `finding_notification_outbox` stores delivery state only.

## Reliability contract

- Event creation is exactly-once by the existing transition/fingerprint rules.
- Outbox insertion is idempotent by `event_id`.
- Analysis/report/Admission do not perform outbound notification I/O.
- Delivery failure never removes or rolls back a Candidate or reviewed evidence.
- Failed attempts remain durable with `attempt_count`, `last_error`, `last_attempt_at`, and `next_attempt_at`.
- Retry backoff is bounded. After the configured maximum attempts the outbox row and notification event enter terminal `failed` state.
- Terminal failures can be explicitly requeued by an operator.
- Delivered rows are never selected again by the worker.
- Every worker attempt is recorded in `notification_deliveries`; successful delivery changes the event and outbox to `delivered` atomically.

The additive outbox schema has its own schema metadata and does not change the core schema version.

## Modes

The worker supports `immediate`, `digest`, and `system_warning`. `silent` policies suppress event creation before the outbox.

## Bounded messages and delivery receipts

Each target/mode group is split at event boundaries into messages of at most 15,000 characters, including its header. Every event is rendered in full. A successful message acknowledges only the events it contains; failure leaves only those events eligible for retry or terminal failure.

A single event larger than the message limit is sent in consecutive parts. It is acknowledged once, after every part succeeds through at least one common transport channel. A failed part stops the remaining parts of that event, while independent batches can continue. The worker renews the remaining event leases before each transport call and schedules backoff from the completion time of the failed attempt.

Delivery results include each batch's `event_ids`, `message_parts`, `sent_parts`, and `message_lengths`, alongside its transport result. `sent_parts` counts attempted transport calls, including a failed call; attempt counts and delivery receipts remain per event.

Transport delivery is at least once. Retrying a partially sent oversized event sends all of its parts again. A crash after transport success but before the database receipt can also repeat a message; already recorded `delivered` events are excluded from later attempts.

## Worker

Run all due Potential Finding notifications:

```bash
python3 tools/deliver_finding_notifications.py
```

Filter by target or mode:

```bash
python3 tools/deliver_finding_notifications.py --target example.test --mode immediate
```

A terminal failure can be explicitly reset and retried:

```bash
python3 tools/deliver_finding_notifications.py --requeue-failed --event-id notify-...
```

## Transport boundary

`app/notification_transports.py` owns outbound delivery. Telegram and ProjectDiscovery `notify` are exposed through a public transport-neutral interface; the Finding pipeline no longer imports the private `reporting._send_notify_cli` helper.

The worker may perform outbound traffic only to configured notification transports. It does not contact the recon target and it does not collect or validate security evidence.

## Reviewed-evidence dispatcher

The unified reviewed-evidence dispatcher now ends at durable queueing. A successful dispatch can create a Candidate and a queued Potential Finding event, but it does not call Telegram or `notify` itself. Delivery is an independent worker responsibility.

This preserves the existing critical ordering: notification reference state is initialized before a reviewed-evidence bridge can promote a new Candidate, so the new Candidate is not mistaken for historical bootstrap state.
