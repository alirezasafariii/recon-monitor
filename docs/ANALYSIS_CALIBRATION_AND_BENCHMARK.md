# Analysis Calibration and Replay Benchmark

## Purpose

Recon Monitor separates four different questions:

1. **Did the target produce family-specific evidence?** — `target_evidence_confidence`
2. **How useful is this family to investigate?** — `bug_proximity_score`
3. **How close is the stored evidence to the canonical confirmation contract?** — `decision_readiness_score`
4. **How well does decision readiness correspond to labeled outcomes over time?** — Calibration / benchmark metrics

These values deliberately do not collapse into one "vulnerability confidence" number.

Calibration and Decision Readiness are advisory. Neither can create target evidence, satisfy hypothesis admission, or confirm a vulnerability.

## Decision Readiness

`app/decision_readiness.py` derives an advisory score from the current `FAMILY_REASONING` confirmation contract.

The score considers:

- target-evidence confidence
- which canonical confirmation groups are satisfied
- which decisive evidence types are present
- blocking security-control contradictions

Fail-closed rules keep structural-only evidence below normal decision thresholds, cap partial confirmation coverage, and sharply reduce readiness when an observed security control contradicts the vulnerable condition.

Importantly, `bug_proximity_score` remains permissive and investigation-oriented. A file-upload surface, privileged function, object reference, or parser sink may remain high-priority to hunt even when Decision Readiness is low.

Meta Ranker continues to sort the investigation queue by proximity/evidence, not by Decision Readiness.

## Offline replay benchmark

`app/analysis_benchmark.py` replays evidence-only golden fixtures through the production Knowledge + Meta Ranker path.

Calibration now uses **Decision Readiness** as the labeled score. Raw Bug Proximity is preserved separately for hunting diagnostics and is not treated as a confirmation probability.

Golden seed coverage:

- 74 canonical families
- one positive evidence case per family
- one surface-only / negative case per family
- 148 labeled records total
- no network requests
- no exploit payload generation
- no target mutation

The seed corpus is a regression/calibration starting point, not a claim of real-world statistical representativeness.

## Challenge Replay V2

`app/analysis_benchmark_v2.py` adds three deterministic hard-negative diagnostics for every family:

- partial evidence
- cross-family noise
- contradiction-heavy evidence

This creates 222 challenge rows, for 370 diagnostic rows including the 148 golden records.

Challenge classification also uses Decision Readiness. Raw Proximity remains visible so tests can prove that a surface can stay hunt-worthy while still being decision-incomplete.

The current regression requires:

- zero challenge false positives at the advisory seed threshold
- zero challenge/positive ordering inversions
- synthetic challenge rows to remain production-activation-ineligible

These are deterministic regression properties, not a production-accuracy claim.

## Dataset provenance and activation

`app/calibration_dataset.py` separates diagnostic data from activation-eligible real-world labels.

Golden and synthetic records can never unlock a production threshold regardless of volume.

Production activation requires trusted provenance plus human verification and a non-empty label source. Default readiness minimums are deliberately conservative:

- at least 400 eligible human-verified records globally
- at least 40 represented families
- at least 20 verified records for a family-specific threshold
- at least 5 positive and 5 negative verified records per family

A production activation request that does not satisfy readiness is automatically reduced to `shadow_only`.

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

Decision Readiness is still an engineered advisory score, not a calibrated probability. Brier/ECE remain diagnostics rather than proof of probabilistic interpretation.

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

## Real-world dataset stage

The next calibration milestone is an independently reviewed replay corpus containing confirmed findings, confirmed false positives, noisy observations, contradiction-heavy cases, and ambiguous cross-surface cases.

Each minimal record should preserve:

- family
- target evidence types
- contradictions
- raw Bug Proximity
- Target Evidence Confidence
- Decision Readiness
- analyst outcome
- human-verification provenance
- label source

Raw request bodies, credentials, exploit payloads, and unrelated private target data are not required for calibration replay.

Only after sufficient representative human-verified support exists should any family-specific calibration move from shadow mode to an explicit active policy.
