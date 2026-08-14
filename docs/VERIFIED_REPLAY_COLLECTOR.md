# Verified Replay Collector

## Purpose

`app/verified_replay_collector.py` turns existing human Investigation decisions into offline replay drafts for later calibration review.

It does **not** contact targets, create vulnerability evidence, confirm findings, or activate calibration.

## Source of labels

The collector reads the existing `investigation_cluster_decision` audit trail produced by the Investigation workflow.

Only the latest decisive human review for a case is considered:

- `confirmed_by_analyst` -> positive label
- `rejected` -> negative label

`needs_more_evidence`, `duplicate`, `out_of_scope`, unreviewed states, and known non-human actors are not collected as calibration labels.

A positive label can exist only for an already-promoted Potential Finding because the Investigation workflow itself refuses to confirm a proximity-only cluster.

## Evidence snapshot

For each reviewed Potential Finding the collector hashes the stored evidence state:

- candidate fingerprint
- analysis/run identity
- canonical family
- variant and endpoint
- likelihood/evidence coverage metadata
- supporting evidence
- contradicting evidence
- missing evidence
- rule IDs

The analyst decision and analyst note are deliberately **excluded** from the evidence snapshot hash. A verdict change therefore cannot manufacture a distinct evidence sample from identical evidence.

## Reconstructed decision scores

The collector replays the stored supporting/contradicting evidence through the existing offline Knowledge + Meta Ranker path and captures:

- `decision_readiness_score`
- `bug_proximity_score`
- `target_evidence_confidence`

This replay is offline and non-evidentiary.

## Draft vs contract-ready record

Collection produces a **review draft**, not an activation-ready calibration record.

The label, reviewer, timestamp, case origin and immutable evidence snapshot are populated from the existing review trail. The seven Evidence Quality dimensions remain intentionally empty:

- reliability
- specificity
- directness
- freshness
- independence
- reproducibility
- uncertainty

A reviewer must explicitly fill those dimensions. `finalize_verified_replay_draft()` then runs the canonical `verified_replay_contract` validator.

Until that explicit quality review succeeds, the draft must not enter trusted calibration support.

## Provenance

Collected drafts use:

`human_verified_replay`

with:

`label_source = investigation_cluster_decision`

## Current repository status

The repository contains no committed real target database or human-reviewed replay corpus. Therefore the trusted corpus count remains zero in source control.

The collector is infrastructure for harvesting real reviewed decisions from an operator's local Recon Monitor database. Real records should remain redacted/minimal and should not include credentials, secrets, full private response bodies, or unrelated user data.

## Safety

- offline database reads only
- no target requests
- no payload generation or execution
- no active validation
- no admission or confirmation changes
- no production threshold activation
- no automatic Evidence Quality assignment
- non-human decision actors are excluded
- evidence snapshot hash excludes the analyst verdict
