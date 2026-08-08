# Recon Monitor 8.4.4

Schema remains **18**. This release is a compatibility and evaluation-consistency hotfix for the recall-preserving admission model introduced in 8.4.3.

## Changes

- Treats zero admitted candidates as an abstention state instead of forcing average evidence coverage to `0`.
- Adds replay recall protection: previously surfaced unconfirmed families must remain either admitted candidates or retained hidden hypotheses when replaying the same source run.
- Separates current-analysis target-learning counts from historical target-learning context.
- Uses successful target state from globally `partial` runs for Recon coverage.
- Restricts workspace case autopilot sync to cases from each target's latest analysis instead of replaying up to 500 stale historical cases.
- Keeps all historical cases and evidence intact; no destructive migration is performed.

## Safety

No new live validation behavior is added. Hidden hypotheses remain unverified and external knowledge remains detection guidance only.
