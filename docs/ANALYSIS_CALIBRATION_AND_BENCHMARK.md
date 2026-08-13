# Analysis Calibration and Replay Benchmark

## Purpose

Recon Monitor now separates three different questions:

1. **Did the target produce family-specific evidence?** — `target_evidence_confidence`
2. **How useful is this family to investigate?** — `bug_proximity_score`
3. **How well do ranking scores correspond to labeled outcomes over time?** — Calibration / benchmark metrics

Calibration is deliberately advisory. It cannot create target evidence, satisfy hypothesis admission, or confirm a vulnerability.

## Offline replay benchmark

`app/analysis_benchmark.py` replays the existing evidence-only golden fixtures through the production Knowledge + Meta Ranker path.

Current seed benchmark:

- 74 canonical families
- one positive evidence case per family
- one surface-only / negative case per family
- 148 labeled ranking records total
- no network requests
- no exploit payload generation
- no target mutation

The seed corpus is a regression/calibration starting point, not a claim of real-world statistical representativeness. Real analyst-confirmed outcomes should be added as a separate labeled corpus before family-specific thresholds are activated.

## Metrics

`app/calibration_engine.py` provides:

- TP / FP / TN / FN
- precision
- recall
- specificity
- false-positive rate
- F1
- accuracy
- score Brier diagnostic
- expected calibration error (ECE)
- empirical score buckets
- deterministic candidate-threshold selection

`bug_proximity_score` remains a ranking score, not a vulnerability probability. Brier/ECE are therefore diagnostics for score calibration, not proof that the score is probabilistic.

## Family calibration policy

Global calibration can be learned after a minimum labeled support threshold is met.

Family-specific threshold learning fails closed unless the family has enough:

- total labeled cases
- positive cases
- negative cases

The initial defaults require 12 labeled cases per family, including at least 3 positive and 3 negative cases. Until then the family inherits the global advisory threshold.

## Shadow mode

Calibration starts in `shadow_only` mode.

In shadow mode it may:

- compute quality metrics
- propose a threshold
- expose empirical outcome rates
- annotate a ranking for analyst review

It may not:

- change `target_evidence_confidence`
- satisfy admission
- satisfy confirmation
- turn Knowledge, correlation, history, or LLM advice into evidence
- silently alter the production vulnerability decision

This allows threshold quality to be measured before any production decision policy is changed.

## Next dataset stage

The next benchmark stage should add analyst-labeled replay cases from confirmed findings and confirmed false positives. Each record should preserve:

- family
- target evidence types
- independent source groups
- contradictions
- endpoint/auth/object context
- raw proximity score
- target evidence confidence
- analyst outcome
- validation class
- source/write-up reference where appropriate

Only after sufficient representative support exists should family-specific calibration move from shadow mode to an explicit active policy.
