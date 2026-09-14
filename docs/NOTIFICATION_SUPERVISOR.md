# Unified Notification Supervisor

Recon Monitor runs Finding delivery and Recon Alert delivery as separate durable workers. The Unified Notification Supervisor coordinates when those workers are invoked without merging their queues, identifiers, retry state, dead letters, or domain lifecycle truth.

## Runtime model

The supervisor owns only execution coordination:

- one database-backed single-instance lease prevents two supervisor processes from owning the loop at the same time;
- the lease is renewable through a heartbeat and recoverable after expiry, so a crashed process does not permanently block delivery;
- each cycle invokes the Finding worker and Recon Alert worker independently with their existing scheduler policies;
- a disabled or not-yet-due worker is skipped normally;
- an exception in one worker is recorded but does not prevent the other worker from running;
- each cycle records worker outcomes, supervisor status, timestamps, and error summaries.

The supervisor does not bypass either worker's existing interval, batch, retry, lease, dead-letter, or delivery rules.

## CLI

Run one coordinated cycle:

```bash
python tools/notification_worker.py run
```

Run the persistent supervisor loop:

```bash
python tools/notification_worker.py watch
```

Inspect supervisor health:

```bash
python tools/notification_worker.py status
```

Configure the supervisor:

```bash
python tools/notification_worker.py configure --enable --poll-seconds 15 --lease-seconds 900
```

The existing `tools/deliver_finding_notifications.py` and `tools/deliver_recon_alerts.py` commands remain supported for compatibility and targeted operator workflows.

## Health and recovery

Supervisor status includes:

- enabled/disabled state;
- lease owner and expiry when active;
- heartbeat and heartbeat age;
- last start, finish, full success, and error timestamps;
- last status and error;
- cycle, worker-success, and worker-failure counters;
- each worker's current scheduler due state and the earliest next-due time;
- latest recorded supervisor cycle.

A stale lease becomes claimable after expiry. This provides bounded restart recovery without requiring destructive cleanup.

After each coordinated cycle, the supervisor evaluates Notification Delivery SLOs from the current worker diagnostics and supervisor health. This evaluation records operational breach state only; it does not alter either worker queue or domain truth.

## Truth boundaries

The supervisor is an execution coordinator only.

- Finding delivery failure cannot rewrite Candidate, Admission, reviewed-evidence, or Potential Finding truth.
- Recon Alert delivery failure cannot rewrite baseline, cooldown, confirmation, ignored/false-positive, or alert-policy truth.
- `alerts.last_notified` still changes only after successful Recon Alert delivery.
- External notification delivery remains at-least-once.
