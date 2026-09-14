# Recon Monitor 8.8.0 — Evidence-to-Finding Reliability & Durable Delivery

Recon Monitor 8.8.0 closes the reliability and operations gap between Recon observations and externally delivered Potential Finding notifications while preserving the platform's conservative evidence and authorization model.

## Release highlights

The release makes the end-to-end architecture explicit:

`Recon → Analysis → Hypothesis → Evidence Coverage/Planning → Validation Observation → Typed/Reviewed Evidence → Canonical Admission → Potential Finding → Durable Outbox → Worker → Notification Transport`

This is an operational composition, not a claim that every family executes every stage automatically. Canonical Admission remains authoritative and Potential Finding remains distinct from vulnerability confirmation.

## Trustworthy Recon state

Comparison-critical Recon state is committed only from successful/baseline-eligible collection. Failed or interrupted runs can no longer silently advance the comparison baseline. Target lifecycle now separates collection, Analysis, report, notification, overall status, and baseline eligibility.

Volatile changes use state-version confirmation. A stable repeated state can be confirmed, while a different subsequent state restarts confirmation rather than accumulating unrelated observations.

## Typed Evidence Adapter

The passive-live executor remains deliberately narrow and observation-oriented. 8.8.0 adds the missing offline adaptation layer for all nine `passive_live` families so eligible fresh/redacted observations can become family-specific typed evidence without issuing new target requests.

The adapter remains fail-closed and family-aware. Typed evidence does not bypass canonical Admission and does not directly confirm vulnerabilities.

## Controlled reviewed evidence

8.8.0 adds or completes offline controlled review/admission paths for Open Redirect, Account Enumeration, Authentication Session, GraphQL Data Exposure, and Secret/Material Classification.

The generic reviewed-evidence framework checks review integrity, linked hypotheses, direct provenance, required structural groups, blockers/contradictions, and exactly-once orchestration before calling canonical Candidate/Admission paths. Redaction and controlled-test boundaries are part of the contract.

## Durable notification outbox

Potential Finding transitions are queued into a durable outbox. The worker provides bounded retries/backoff, delivery leases, worker-run history, policy-controlled scheduling/watch mode, queue diagnostics, failed/dead-letter inspection, explicit retry, and bounded drain operations.

Transport failures affect delivery state only. They do not roll back or rewrite already-established Candidate/Admission truth. External transports are inherently at-least-once, so downstream receivers should tolerate duplicate delivery attempts.

## Recon Change Alert transport consolidation

Recon Change Alerts keep their existing lifecycle and policy semantics but no longer own duplicate Telegram/ProjectDiscovery delivery code. Both Alert and Finding notification paths now use `app/notification_transports.py` as the transport-neutral outbound boundary.

Recon Change Alerts intentionally do **not** enter the Finding outbox in this release.

## Compatibility

- Application version: **8.8.0**
- Core database schema: **18**
- Upgrade from 8.7.0: backward-compatible, additive feature initialization only
- No destructive core migration required
- Python CI matrix: 3.11 and 3.13

Release publication should use the same commit that passes strict manifest validation, release consistency, the complete unit suite, and integration tests.
