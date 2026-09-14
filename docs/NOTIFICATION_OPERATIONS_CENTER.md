# Notification Delivery Operations Center

Recon Monitor exposes one operational control plane for the two durable external-delivery workers while keeping their persistence and lifecycle semantics independent.

## Workers

- **Finding delivery** owns Potential Finding notification events and `finding_notification_outbox`.
- **Recon Alert delivery** owns Recon Change Alert occurrences and `recon_alert_notification_outbox`.

The Operations Center reads both diagnostics side by side. It does not merge queues, event identifiers, retry state, dead letters, or domain truth.

## Unified status

The combined view reports, for each worker and in aggregate:

- queue depth;
- events due now;
- open dead letters;
- queued, retry-pending, delivering, delivered, and failed counts;
- oldest pending event age;
- worker policy (enabled, interval, batch limit);
- latest recorded worker run.

A worker is summarized as `healthy`, `work_due`, `paused_with_backlog`, or `degraded`. Open dead letters or a failed latest worker run make the worker degraded.

## Operator controls

From the Operations Center an authenticated Dashboard operator can:

- configure one worker without changing the other;
- run one delivery pass immediately;
- perform a bounded drain;
- retry one dead-letter event or all dead letters belonging to one worker.

These actions use the Dashboard's existing authentication, same-origin, and CSRF checks. Run and drain remain bounded by the underlying worker limits.

## Truth boundaries

External delivery is operational state only.

- Finding transport failure cannot rewrite Candidate, Admission, reviewed-evidence, or Potential Finding truth.
- Recon Alert transport failure cannot rewrite Recon Alert eligibility, baseline, cooldown, confirmation, ignore/false-positive, or risk-policy truth.
- `alerts.last_notified` changes only after successful Recon Alert delivery.

The two workers share notification transports, not lifecycle state.
