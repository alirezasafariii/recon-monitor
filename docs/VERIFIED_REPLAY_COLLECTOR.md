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

For each reviewed Potential Finding the collector hashes the logical stored evidence state:

- stable candidate fingerprint
- canonical family
- variant and endpoint
- supporting evidence
- contradicting evidence
- missing evidence
- rule IDs

The analyst decision and analyst note are deliberately **excluded** from the evidence snapshot hash.

Run-local identity (`analysis_id`, `source_run_id`) and derived ranking/coverage scores are also excluded. This makes the evidence snapshot stable across scans when the underlying logical evidence has not changed.

A verdict change, a new run ID, or a recalculated score therefore cannot manufacture a distinct evidence sample from identical evidence.

`case_origin_id` is based on the stable candidate fingerprint instead of a run-local candidate/case identifier. Together with the snapshot hash, this prevents repeated reviews of the same unchanged logical finding from inflating corpus support across runs.

## Reconstructed decision scores

The collector replays the stored supporting/contradicting evidence through the existing offline Knowledge + Meta Ranker path and captures:

- `decision_readiness_score`
- `bug_proximity_score`
- `target_evidence_confidence`

This replay is offline and non-evidentiary.

## Operator CLI

The existing Recon Monitor CLI exposes the collector under the Analysis command family:

```bash
./recon-monitor.sh analysis verified-replay-drafts --limit 100
```

The command prints a JSON review payload to stdout. If an operator wants a persistent review artifact, shell redirection can be used explicitly:

```bash
./recon-monitor.sh analysis verified-replay-drafts --limit 100 > verified-replay-drafts.json
```

The CLI does not create or modify a trusted corpus file itself. It only reads the local Recon Monitor database and serializes review drafts. This keeps collection separate from reviewer approval and prevents accidental activation by a command invocation.

The collection limit is bounded to 1..5000 records inside the compatibility CLI.

## Draft vs contract-ready record

Collection produces a **review draft**, not an activation-ready calibration record.

The label, reviewer, timestamp, stable case origin and immutable evidence snapshot are populated from the existing review trail. The seven Evidence Quality dimensions remain intentionally empty:

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
- no automatic trusted-corpus write
- non-human decision actors are excluded
- evidence snapshot hash excludes the analyst verdict
- evidence snapshot hash excludes run-local identity and derived scores
- stable candidate origin prevents unchanged cross-run duplicates from inflating support
