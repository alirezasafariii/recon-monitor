# Change-guidance Feedback Calibration

P9 turns explicit P8 task usefulness feedback into a **shadow-only** per-signal calibration report.

The report answers a narrow operational question: which Derived Change Advisory signal types are repeatedly rated useful, neutral, or noisy by analysts? It does not answer whether a vulnerability exists and it does not learn production weights.

## Inputs

Only persisted change-guided tasks are considered:

- deterministic `task-change-*` task identity;
- `source=derived_change_advisory`;
- `advisory_only=true`;
- latest explicit analyst usefulness rating: `useful`, `neutral`, or `noisy`;
- explicit task terminal state where available.

The report can be filtered by target and is bounded to 5,000 task records per evaluation.

## Per-signal report

For each `signal_type`, the report includes:

- task count and terminal rate;
- feedback count and feedback coverage;
- useful / neutral / noisy counts and rates;
- 95% Wilson intervals for useful and noisy rates;
- family coverage;
- a shadow review status.

A signal remains `insufficient_feedback` until at least five explicit ratings exist.

After that gate, the report may show one of these **review prompts**:

- `utility_watch`: explicit useful feedback is consistently strong with low observed noise;
- `noise_watch`: explicit noisy feedback is materially high;
- `mixed`: feedback does not support either watch condition.

These statuses are not production configuration.

## Safety boundary

The report is always `activation=shadow_only`.

It cannot:

- change Meta Ranker weights;
- change Queue score;
- change Derived Change Advisory thresholds;
- change Investigation Workflow task ordering;
- mark Evidence Gap requirements present;
- change Admission or target-evidence confidence;
- change Safe Validation eligibility or approval;
- trigger network requests;
- auto-tune rules, weights, thresholds, or policy.

Analyst usefulness feedback is subjective workflow telemetry, not a vulnerability label. Cohorts are not randomized, feedback can be missing non-randomly, and the latest rating per task is the calibration sample; rating-edit history remains audit evidence rather than multiple independent samples.

The dashboard, API, and CLI expose the report with these constraints.
