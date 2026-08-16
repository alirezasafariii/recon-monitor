# Recon Monitor 8.7.0 — Evidence Completion & Live Progress

Recon Monitor 8.7.0 extends the 8.6 analysis/admission architecture in two directions: it makes evidence gaps actionable without weakening canonical Admission, and it makes long-running Recon/Analysis work observable instead of opaque.

## Evidence completeness and validation workflow

- Added **Collection Quality** snapshots that distinguish complete, partial/degraded, failed, skipped, unavailable, and unknown collection. Missing collection remains uncertainty; it is never treated as proof that a vulnerability condition is absent.
- Added **Evidence Coverage** over canonical family reasoning with explicit `observed`, `not_observed`, `not_collected`, and `unknown` states.
- Added the **Evidence Completion Planner** to identify hypothesis-local passive gaps, behavioral or controlled validation needs, contradictions, independent-source requirements, analyst-review needs, and safe stop states.
- Added the **Validation Eligibility Gate**, reusing canonical scope, authorization, required-context, and budget policy. `eligible` only means eligible for runner consideration; it is not permission to execute.
- Added **Validation Runner Dry-Run** contracts with fresh eligibility rechecks and zero network execution.
- Added a bounded **Passive-Live Validation Executor** for explicitly approved `passive_live` contracts only.

## Passive-live safety boundary

Passive-live execution is deliberately constrained:

- GET / HEAD / OPTIONS only
- at most two requests per execution
- no request body
- no query-string replay or URL fragment replay
- no cookies, credentials, or session reuse
- no identity switching
- no target mutation
- no redirect following
- no retries
- current scope, authorization, context, budget, canonical family validation level, Gate decision, and dry-run contract are all rechecked before transport
- observations are stored as redacted metadata only

The executor still emits **no typed evidence**, does not set `admitted`, and cannot directly promote a Potential Finding. Canonical Evidence Admission remains the only decision authority.

## Live Recon and Analysis progress

Added live progress and health visibility to both primary workspaces so long operations can be inspected while they run.

The Dashboard now shows, where available:

- estimated work-completion percentage
- current Recon stage or Analysis phase
- real `current / total` counters when a denominator exists
- elapsed time
- heartbeat age
- age of the last measurable progress change
- latest error information
- explicit health states: `progressing`, `waiting`, `stalled`, `failed`, `completed`

Recon reuses the existing nine-stage execution pipeline and its real counters/heartbeats. Analysis adds an independent heartbeat plus phase instrumentation around the existing Analysis Engine pipeline.

The percentage represents **estimated work completion, not estimated time remaining**. A heavyweight Analysis phase can keep the same percentage while a fresh heartbeat proves the process is still alive.

## Existing long-running Analysis jobs

An Analysis process started before 8.7.0 cannot gain the new in-process heartbeat retroactively. It is displayed conservatively as a `legacy` run. Recent persisted Analysis database activity may be used only as a best-effort liveness hint, and the Dashboard will not invent a precise late-stage percentage. New or restarted Analysis runs receive full phase and heartbeat visibility.

## Preserved trust boundaries

This release does not change the meaning of Alerts, Potential Findings, or Admission:

- Collection completeness informs uncertainty; it does not satisfy Admission.
- `not_collected` and `unknown` are not negative target evidence.
- Planner, Eligibility, Dry-Run, Executor observations, and Progress Tracking cannot confirm a vulnerability.
- Passive-live observations still require a future family-specific Typed Evidence Adapter before they can become canonical typed evidence.
- Admission remains the only authority that decides whether evidence is sufficient for a Potential Finding.

## Compatibility and testing

- Application version advances to **8.7.0**.
- Database schema remains **18**; no destructive migration is required.
- Progress state is stored atomically under `state/progress/` and requires no database schema migration.
- Final CI covers source hygiene, strict manifest validation, version consistency, the complete unit suite, and integration tests on Python 3.11 and Python 3.13.
