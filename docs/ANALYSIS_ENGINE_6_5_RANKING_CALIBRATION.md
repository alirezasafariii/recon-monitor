# Analysis Engine 6.5 — Family-Fit / Condition-Confidence Separation

Analysis 6.5 fixes a ranking semantics bug discovered during 6.4 held-out diagnostics.

## Core rule

A contradiction can mean two very different things:

- **Condition evidence:** the target appears to enforce the expected security control, so the vulnerability condition is not established.
- **Family evidence:** the observation is still clearly about that vulnerability family.

Earlier ranking code subtracted blocking contradictions from family compatibility. This could make a secure negative for a precise family rank below a generic neighboring family. For example, a privileged state-changing function with an observed lower-privilege denial is still most naturally a function-authorization observation even though it should abstain from a BFLA finding.

6.5 therefore separates:

- `family_fit_score`: how well the evidence belongs to a vulnerability family;
- `condition_confidence`: how strongly the target evidence establishes the vulnerability condition.

Blocking controls affect `condition_confidence` and admission state, but not `family_fit_score`.

## Production alignment

`security_reasoning._family_score()` now follows the same epistemic rule. Matched family-specific controls remain visible in the ranking reason but are not subtracted from family fit. Exploitability, calibrated likelihood, falsification, and contradiction handling remain separate and continue to reduce vulnerability confidence where appropriate.

## Confusion observability

Benchmark Engine 3.1 adds a complete confusion matrix over all rank-required cases, plus per-case:

- target rank;
- Top-1/Top-2 scores;
- Top-1 margin;
- closest incorrect family;
- ranking error rows.

The held-out confusion matrix now uses this complete matrix instead of incorrectly reusing the hard-case-only matrix.

## Tuning discipline

The 6.5 rule was selected using the **development partition only**. Development baseline had one Top-1 confusion; the frozen rule removed it without changing admission semantics.

The existing 6.4 held-out partition was inspected during diagnosis and is therefore considered a **consumed diagnostic holdout** for future scientific claims. Its post-6.5 result remains useful as a regression audit, but it must not be presented as a new unbiased production-accuracy estimate. A future corpus revision should introduce fresh post-freeze source roots for an unbiased holdout estimate.
