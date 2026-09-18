# Explicit Policy-change Proposal Workflow

P12 turns a selected P11 human-review packet into a **versioned, audited, non-executable policy proposal**.

The purpose is to make a possible production policy change concrete enough for review without creating any path that automatically changes production behavior.

## Source gate

A proposal can be drafted only from a P11 packet whose state is:

`ready_for_manual_review`

Packets in `collect_more_data` cannot create a P12 proposal.

## Supported policy surfaces

P12 intentionally limits proposals to a small whitelist whose current state can be snapshotted deterministically:

- `meta_ranker.derived_change_weight`
- `change_guidance.calibration_sample_gate`
- `change_guidance.drift_window_and_sample_gate`

Candidate after-state JSON is validated per surface and bounded to the expected fields/ranges.

## Proposal record

Every proposal version stores:

- deterministic proposal key and version ID;
- source P11 packet ID and packet snapshot;
- target and signal type;
- policy surface;
- current before snapshot;
- analyst-supplied candidate after state;
- explicit before/after diff;
- rationale;
- rollback plan;
- required tests;
- content hash;
- creator and timestamps;
- review state and decision metadata.

Persistence uses additive table `change_guidance_policy_proposals` with independent compatibility metadata:

`change_guidance_policy_proposal_schema_version=1`

The core SQLite `SCHEMA_VERSION` remains unchanged.

## Versioning

The first draft is version 1. Re-drafting the same packet + policy surface with identical content is idempotent.

A materially changed draft creates the next version and marks the previous non-accepted version `superseded`. An already accepted proposal cannot be amended in place.

## Review state machine

The only states are:

- `draft`
- `under_review`
- `accepted_for_separate_implementation`
- `rejected`
- `superseded`

The supported transition is:

`draft → under_review → accepted_for_separate_implementation | rejected`

There is deliberately **no `applied` state** and no apply function/endpoint.

## Meaning of acceptance

`accepted_for_separate_implementation` means only that a reviewer accepts the proposal as input to a future, separate code/config change.

It does not:

- edit Meta Ranker weights;
- edit calibration or drift thresholds;
- change Queue score;
- change Investigation Workflow ordering;
- satisfy Evidence Gap requirements;
- change Admission or target-evidence confidence;
- change Safe Validation eligibility or approvals;
- execute network requests;
- create or merge an implementation PR.

A real production change must be implemented separately, with its own code/config diff, tests, review, and normal merge controls.

## Auditability

Creation, submission, and review decision are written to the existing audit log. Proposal versions are preserved rather than overwritten. Before/after state, rollback plan, test requirements, source packet, and reviewer decision remain queryable from the ledger.

Dashboard actions use the existing authenticated, same-origin and CSRF-protected Investigation POST path. API and CLI expose the ledger read-only with explicit safety metadata.
