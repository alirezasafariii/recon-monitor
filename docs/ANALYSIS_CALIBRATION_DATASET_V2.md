# Analysis Calibration Dataset V2

## Purpose

The first calibration benchmark proved that deterministic replay can reveal real ranking defects, including signal-vocabulary drift between dedicated analyzers and older global profiles. It also demonstrated why a small golden set must not be mistaken for production accuracy.

Dataset V2 separates three different jobs:

1. **Golden regression** — deterministic positive/surface-only contracts.
2. **Synthetic challenge diagnostics** — hard negatives and noisy/contradictory replay used to expose ranking weaknesses.
3. **Human-verified real-world replay** — the only data class allowed to contribute to production activation readiness.

## Provenance policy

`app/calibration_dataset.py` assigns explicit provenance and activation eligibility to each labeled row.

Production-eligible provenance is restricted to:

- `human_verified_replay`
- `curated_real_world_replay`
- `confirmed_target_history`

Eligibility additionally requires `human_verified=true` and a non-empty `label_source`.

The following classes are permanently activation-ineligible:

- `golden_seed`
- `synthetic_challenge`
- `generated_hard_negative`
- `generated_partial_evidence`

This means increasing the number of generated cases can improve regression pressure but can never make a threshold production-ready by itself.

## Activation readiness defaults

Default production-readiness minimums are deliberately conservative:

- 400 eligible human-verified records globally
- at least 40 represented families
- 20 verified records for a family-specific threshold
- at least 5 positive and 5 negative verified records per family

These are activation gates, not claims that the resulting model is statistically sufficient for every deployment. They can be raised as the real replay corpus grows.

A production activation request that does not satisfy readiness is automatically reduced to `shadow_only`.

## Challenge replay

`app/analysis_benchmark_v2.py` generates three deterministic diagnostic cases for each of the 74 canonical families:

### Partial evidence

The direct/decisive portion of the positive contract is removed. This checks whether structural context alone is being over-scored.

### Cross-family noise

A surface-only case is mixed with a decisive-looking signal from a different family. This checks whether ranking confuses unrelated vulnerability mechanisms.

### Contradiction-heavy

The positive contract is replayed together with a family-specific observed security control/contradiction. This measures whether contradiction handling meaningfully reduces ranking priority.

There are currently:

- 148 golden records
- 222 synthetic challenge records
- 370 total diagnostic records before any external verified corpus is loaded

Challenge cases are diagnostic-only and never feed production activation readiness.

## Trusted replay corpus format

`load_verified_replay_jsonl()` accepts minimal JSONL records containing only ranking/evidence metadata, for example:

```json
{"id":"case-001","family":"broken_object_authorization","label":true,"score":78,"target_evidence_confidence":65,"signals":["object_identifier","authorization_response_differential"],"contradictions":[],"provenance":"human_verified_replay","human_verified":true,"label_source":"analyst_case_review"}
```

Raw request bodies, exploit payloads, credentials and unrelated target data are not required by this replay format.

## Safety boundary

Calibration remains separate from vulnerability evidence:

- generated challenges create no target evidence
- calibration cannot satisfy admission
- calibration cannot satisfy confirmation
- Knowledge and LLM context remain non-evidentiary
- no network request is made by the benchmark
- no payload is generated or executed

The next quality milestone is to populate the trusted replay corpus with independently reviewed real findings, hard false positives, contradiction-heavy cases, noisy recon observations and cross-surface ambiguity cases before considering any production threshold activation.
