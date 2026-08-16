# Verified Real-World Replay Collection Contract

## Purpose

This contract defines how independently reviewed real-world replay metadata should be collected before it is considered for Analysis calibration. It is intentionally offline and metadata-only.

It does not contact targets, generate payloads, create vulnerability evidence, alter admission/confirmation, or activate a production threshold.

## Canonical family rule

Every record must use a family from the canonical `family_reasoning.FAMILY_ORDER` catalog. The contract reads that source directly; no second hand-maintained family list is introduced.

Current catalog size: 74 families.

Unknown or misspelled families are rejected by the contract validator.

## Required review binding

Every proposed replay label must include:

- `family`
- `label`
- `decision_readiness_score` (or `score`)
- `provenance`
- `human_verified=true`
- `label_source`
- `reviewer_id`
- `reviewed_at`
- `case_origin_id`
- `evidence_snapshot_id`
- `evidence_quality`

The evidence snapshot identifier binds the human verdict to the exact evidence state that was reviewed. The collection fingerprint uses family, case origin, evidence snapshot and provenance so duplicate copies of the same reviewed snapshot are not counted twice.

## Evidence quality dimensions

`evidence_quality` must contain all seven dimensions, each expressed in the range 0..1 or 0..100:

- reliability
- specificity
- directness
- freshness
- independence
- reproducibility
- uncertainty

These dimensions are collection metadata. The contract does not change Analysis scoring or confirmation.

## Trusted provenance

The validator accepts the same trusted real-world provenance classes used by the calibration policy:

- `human_verified_replay`
- `curated_real_world_replay`
- `confirmed_target_history`

Generated golden/challenge data is not a substitute for independently reviewed real-world replay.

## Recommended corpus composition

The collection should deliberately include both positive and negative outcomes:

- independently confirmed findings
- verified negatives
- false-positive investigations
- contradiction/control-enforced cases
- near misses
- noisy observations
- ambiguous cross-surface cases

The objective is not to maximize case count. It is to create auditable evidence for measuring precision, recall, false-positive rate, false negatives, calibration error and family-specific behavior.

## Privacy and safety

Raw request bodies, credentials, exploit payloads and unrelated target data are not required by this contract. Use stable case/snapshot identifiers and the minimum metadata necessary for reproducible review.

## Implementation

- Validator: `app/verified_replay_contract.py`
- Regression: `tests/test_verified_replay_contract_v941.py`

This layer is deliberately separate from the production Analysis decision path. A later change may wire validated records into calibration only after sufficient independently reviewed corpus coverage exists.
