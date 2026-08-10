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

These gates are frozen before the new evaluation corpus is scored:

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

## Corpus target

Golden v4 target:

- 50 new independent vulnerability source roots;
- 4 variants per root;
- 200 cases total;
- one split only: `postfreeze_holdout`.

Required variants for every source root:

1. `positive` — sufficient target evidence; expected admission is true.
2. `near_miss` — surface/context evidence without the decisive vulnerability condition; expected admission is false.
3. `secure_negative` — relevant surface plus a directly observed control/contradiction; expected admission is false.
4. `sparse_noisy` — incomplete recon-style evidence sufficient for family hypothesis/ranking but not for finding admission; expected admission is false.

The same independent source root, project, advisory reference, and primary-source URL must be used across all four variants.

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

## Collection versus evaluation

Collection and scoring are deliberately separated.

While the manifest contains:

```json
"evaluation_status": "collection_open",
"sealed": false
```

`analysis_postfreeze.py --evaluate` refuses to score the corpus.

This prevents repeated benchmark peeking while examples are still being collected or normalized.

When all 50 roots / 200 cases are complete:

1. validate root/url/reference non-overlap with v3;
2. validate the exact four-variant invariant for every root;
3. record all source-root IDs in the manifest;
4. calculate SHA256 of `analysis_golden_v4.jsonl`;
5. write that hash into the manifest;
6. set `sealed: true` and `evaluation_status: fresh_postfreeze`;
7. commit the sealed corpus and manifest;
8. run the evaluation once without changing any protected 6.5 file.

If the corpus bytes change after sealing, evaluation refuses because its SHA256 no longer matches the manifest.

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

A failed fresh holdout remains a failed fresh holdout.

If Analysis 6.6 identifies a ranking/admission weakness, the result is recorded unchanged. The failing roots can later become development knowledge for Analysis 6.7, but the same v4 corpus must not be retuned against and then re-described as blind.

A future tuned engine requires a future independent post-freeze holdout.

This preserves the central evidence contract:

`surface clue -> grounded hypothesis -> target evidence -> contradiction check -> family admission -> precise taxonomy when justified`
