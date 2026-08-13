# Analysis Engine 6.29 — Fresh Blind v5 + Multi-Family Hard Cases

Analysis 6.29 is a new pre-scored evaluation phase built from the sealed Analysis 6.28 engine.

## Non-negotiable blind boundary

Before the first v5 score is produced:
- detector, ranking, admission, reasoning, candidate, and orchestration production logic remain byte-identical to the sealed 6.28 base;
- source selection may use only external taxonomy/provenance semantics and the existing pre-score source-family text audit;
- no v4 score, v4 failure, detector score, admission result, or ranking result is used to choose a v5 source;
- all prior Golden/raw v1-v4 roots, projects, provenance URLs, v4 discovery exposures, and detector-grounding write-up URLs are excluded;
- the v5 corpus, shortlist, expected labels, and pre-registered gates are frozen before first scoring.

## Corpus shape

The preparation target is 216 cases:
- 144 single-family cases = 36 families × positive / near-miss / secure-negative / sparse-noisy;
- 72 multi-family interference cases = 18 disjoint family pairs × dual-positive / A-only / B-only / dual-secure.

Every current family appears exactly once in the dual-positive multi-family pairing. The pairing is deterministic from the sealed registry and is fixed before scoring.

Single-family source provenance requires exactly 36 fresh roots and 36 fresh projects with zero overlap against the complete prior exposure index.

## Why multi-family cases exist

The earlier holdouts largely tested one intended family at a time. Real stored target artifacts can carry evidence relevant to multiple families simultaneously. v5 therefore measures whether the engine can:
- admit both intended families when two independent conditions coexist;
- keep only one family when the second condition is secured;
- reject both when both conditions are secured;
- avoid unrelated promotions caused by shared keywords or context;
- preserve useful routing under competing evidence.

## Pre-registered v5 multi-family gates

Frozen before scoring:
- exact admission-set accuracy >= 0.90;
- expected condition recall >= 0.85;
- unexpected promotion rate <= 0.05;
- dual-positive both-admitted rate >= 0.80;
- dual-secure rejection >= 0.95;
- expected-family Top-3 coverage >= 0.90.

The existing raw single-family gates remain unchanged.

## Consumption rule

The first v5 evaluation may run once. Regardless of pass or fail, its report is immutable and v5 becomes consumed. Any later remediation must not modify v5. Calibration, if needed, must use a different source set and later validation must use another fresh holdout.

No first-scan/second-scan alert behavior is changed by Analysis 6.29.
