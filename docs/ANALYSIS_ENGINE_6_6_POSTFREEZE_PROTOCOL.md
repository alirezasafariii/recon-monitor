# Analysis Engine 6.6 — Fresh Post-Freeze Blind Holdout

Analysis 6.6 is an evaluation phase, not a model-tuning phase.

The purpose is to measure how the frozen Analysis 6.5 admission/ranking semantics generalize to vulnerability source roots that were not present in, derived from, or inspected through the Golden v3 corpus.

## Frozen baseline

The frozen baseline is commit:

`de3d6f210a52c409a60f9ffb861bc283790ea8fe`

Frozen versions:

- Analysis Engine: `6.5.0`
- Ranking Engine: `1.0.0`
- Ranking Rule: `2026.08.10.6.5`
- Benchmark Engine used as the underlying scorer: `3.1.0`

The following files are protected by their Git blob identities in `benchmarks/golden/splits/v4.json`:

- `app/analysis_engine.py`
- `app/bug_candidates.py`
- `app/security_reasoning.py`
- `app/hypothesis_admission.py`
- `app/analysis_standards.py`
- `app/analysis_ranking.py`

`app/analysis_postfreeze.py` recomputes each Git blob identity from repository bytes. Any difference fails with `POST-FREEZE MODEL MUTATION DETECTED`.

Evaluator, corpus, tests, reports, and protocol metadata may evolve during collection. The protected 6.5 reasoning/admission/ranking files may not.

## Why Golden v3 is not the blind estimate

Golden v3 remains a valuable regression corpus, but its held-out cases were inspected during Analysis 6.5 diagnosis. It is therefore explicitly marked:

`consumed_diagnostic`

Post-6.5 scores on v3 must not be described as fresh blind or unbiased production accuracy.

## Pre-registered acceptance gates

These gates were frozen before the new evaluation corpus was scored:

| Metric | Gate |
|---|---:|
| Precision | >= 0.93 |
| Recall | >= 0.85 |
| Top-1 accuracy | >= 0.90 |
| Top-3 accuracy | >= 0.95 |
| Abstention accuracy | >= 0.90 |
| False-promotion rate | <= 0.05 |
| Brier score | <= 0.15 |
| ECE | <= 0.15 |
| Standards coverage | >= 1.00 |
| Source-root leakage | 0.00 |

The gates are duplicated as immutable constants in the post-freeze evaluator and must exactly equal the manifest. A later corpus result may not lower these gates.

## Corpus construction

Golden v4 contains:

- 50 new independent vulnerability source roots;
- 50 distinct source projects;
- 4 variants per root;
- 200 cases total;
- one split only: `postfreeze_holdout`.

Required variants for every source root:

1. `positive` — sufficient target evidence; expected admission is true.
2. `near_miss` — surface/context evidence without the decisive vulnerability condition; expected admission is false.
3. `secure_negative` — relevant surface plus a directly observed control/contradiction; expected admission is false.
4. `sparse_noisy` — incomplete recon-style evidence that must remain an abstaining hypothesis; it is not forced into the Top-1 family gate.

The same independent source root, project, advisory reference, and primary-source URL are used across all four variants. Positive, near-miss, and secure-negative variants are rank-required; sparse/noisy variants evaluate abstention under insufficient evidence.

## Source policy

Only primary technical sources may introduce a root:

- GitHub Security Lab advisory;
- vendor security advisory;
- project-maintainer security advisory.

Each root must be absent from Golden v3 by all practical identities:

- `source_root`;
- advisory/reference identity;
- primary-source URL.

All provenance URLs must use HTTPS.

OWASP, WSTG, CWE, CAPEC, advisories, and write-ups are context/provenance only. They may never appear in target `support` or `contradict` evidence and may not satisfy evidence groups, source-count rules, contradiction overrides, or candidate admission.

Source adjudication is also bound to the frozen 6.5 policy: each positive root must cover all frozen required evidence groups, decisive evidence must intersect the family condition group, and the secure-negative control must be an actual frozen blocking contradiction for that family.

## Collection versus evaluation

Collection and scoring are deliberately separated.

Before materialization the manifest contained:

```json
"evaluation_status": "collection_open",
"sealed": false
```

After deterministic materialization it became `corpus_materialized` while remaining unsealed and unscored. The evaluator refused `--evaluate` throughout collection.

After all 50 roots / 200 cases were complete:

1. root/url/reference non-overlap with v3 was validated;
2. the exact four-variant invariant was validated for every root;
3. all 50 source-root IDs were recorded in the manifest;
4. the materialized corpus was byte-compared with a deterministic rebuild from the verified registry;
5. SHA256 was calculated and written to the manifest;
6. the manifest was set to `sealed: true` and `evaluation_status: sealed_postfreeze`;
7. the sealed corpus and manifest were committed;
8. one fresh evaluation was run without changing any protected 6.5 file.

Sealed corpus SHA256:

`90aa5e60ee2d7ba9d686d831ad0aa88e6aee28fb4c2f09b87bc02ad3f64290ab`

If the corpus bytes change after sealing, evaluation refuses because its SHA256 no longer matches the manifest.

## Fresh post-freeze result

The first and only fresh evaluation was GitHub Actions run `31356112851`. The immutable result is stored in:

`benchmarks/golden/reports/analysis_v4_postfreeze_report.json`

| Metric | Fresh v4 result | Gate | Result |
|---|---:|---:|---|
| Precision | 1.000000 | >= 0.93 | PASS |
| Recall | 1.000000 | >= 0.85 | PASS |
| Top-1 accuracy | 1.000000 | >= 0.90 | PASS |
| Top-3 accuracy | 1.000000 | >= 0.95 | PASS |
| Abstention accuracy | 1.000000 | >= 0.90 | PASS |
| False-promotion rate | 0.000000 | <= 0.05 | PASS |
| Brier score | 0.015173 | <= 0.15 | PASS |
| ECE | 0.094933 | <= 0.15 | PASS |
| Standards coverage | 1.000000 | >= 1.00 | PASS |
| Source-root leakage | 0.000000 | = 0.00 | PASS |

Additional diagnostics:

- cases: 200;
- source roots: 50;
- source projects: 50;
- rank-required cases: 150;
- ranking errors: 0;
- low-margin correct cases (`Top1 - Top2 < 0.08`): 0;
- wrong-Top1-but-correct-Top3 cases: 0;
- source-root leakage count: 0;
- source-URL leakage count: 0;
- source-reference leakage count: 0;
- quality-gate failures: 0.

Every represented family had Top-1 accuracy 1.0 and positive recall 1.0 in this structured holdout.

## Interpretation boundary

This is a **fresh post-freeze structured evidence benchmark**, not a claim of 100% production-world vulnerability detection accuracy.

The vulnerability source roots and projects were independent from Golden v3 and were not used to tune the frozen 6.5 ranking/admission logic. However, each advisory was adjudicated into the engine's frozen evidence taxonomy before the four benchmark variants were generated. The result therefore demonstrates strong generalization under the engine's evidence contract and strong resistance to near-miss/control contradictions; it does not yet measure the entire upstream problem of extracting correct evidence from arbitrary noisy raw recon traffic.

A stronger future evaluation should keep the 6.6 corpus consumed and introduce another independent set whose inputs are raw or minimally normalized recon artifacts rather than policy-shaped evidence objects.

## Evaluation report

The fresh report includes:

- Precision / Recall;
- Top-1 / Top-3 accuracy;
- Abstention accuracy;
- False-promotion rate;
- Brier score / ECE;
- standards coverage;
- source-root leakage;
- complete confusion matrix;
- per-family rank accuracy and positive recall;
- ranking error rows;
- low-margin correct rate (`Top1 - Top2 < 0.08`);
- wrong-Top1-but-correct-Top3 rate;
- frozen engine identity;
- sealed corpus SHA256.

## Failure discipline

A failed fresh holdout would have remained a failed fresh holdout. No gate was lowered and no 6.5 admission/ranking rule was changed after seeing v4 results.

The v4 set is now consumed as a completed fresh evaluation and must not be used to tune a future engine and then be re-described as blind. A future tuned engine requires a future independent post-freeze holdout.

This preserves the central evidence contract:

`surface clue -> grounded hypothesis -> target evidence -> contradiction check -> family admission -> precise taxonomy when justified`
