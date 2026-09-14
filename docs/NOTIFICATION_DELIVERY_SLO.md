# Notification Delivery SLOs

Recon Monitor evaluates operational delivery health above the independent Finding and Recon Alert durable workers and the Unified Notification Supervisor. SLO state is operational metadata only; it never changes Candidate, Admission, Potential Finding, Recon Alert eligibility, retry truth, or delivery-success truth.

## Default thresholds

The additive SLO policy starts with conservative defaults:

- oldest pending event: warning at 2 hours, critical at 6 hours;
- queue backlog: warning at 50 events, critical at 200;
- open dead letters: warning at 1, critical at 5;
- supervisor heartbeat while supervision is relevant: warning at 90 seconds, critical at 300 seconds;
- consecutive worker/supervisor failures: warning at 2, critical at 3;
- alert transition cooldown: 15 minutes.

All thresholds are configurable without changing the core database schema.

## Breach lifecycle

Each SLO condition has one stable breach key such as `finding:pending_age_seconds` or `supervisor:heartbeat_age_seconds`.

- crossing the warning threshold opens a breach;
- crossing the critical threshold escalates the same breach instead of creating a duplicate;
- recovery resolves the breach and records its duration;
- a later recurrence reopens the same breach and increments its occurrence count;
- repeated observations of an unchanged breach do not create repeated alert events;
- reopen/escalation events inside the configured cooldown are suppressed to prevent alert storms.

Durable transition history is stored separately from the current breach registry so operators can inspect open, resolved, escalated and recovered conditions.

## Supervisor evaluation

The Unified Notification Supervisor evaluates SLO state after coordinated delivery cycles. Operations Center and the SLO CLI also evaluate current metrics when status is requested, so stale or disabled runtime state is visible even when the persistent supervisor loop is not currently active.

Heartbeat age is only treated as an SLO signal while supervision is relevant: the supervisor is active, work is due, or delivery backlog exists. An idle installation with no delivery work does not become unhealthy simply because no supervisor heartbeat exists.

## CLI

Inspect and evaluate current SLO state:

```bash
python tools/notification_slo.py status
```

Inspect the durable breach registry or event history:

```bash
python tools/notification_slo.py breaches --status-filter open
python tools/notification_slo.py events --limit 50
```

Configure thresholds:

```bash
python tools/notification_slo.py configure \
  --pending-warning-seconds 7200 \
  --pending-critical-seconds 21600 \
  --backlog-warning 50 \
  --backlog-critical 200 \
  --heartbeat-warning-seconds 90 \
  --heartbeat-critical-seconds 300
```

## Alerting boundary

SLO alert events are persisted internally and surfaced through Operations Center and the CLI. They are intentionally not sent through the same Telegram/ProjectDiscovery notification transports being monitored, which avoids a circular failure mode where delivery degradation also prevents delivery-health alerting.

External notification delivery remains at-least-once. SLO state describes operational health; it does not upgrade delivery semantics to exactly-once.
