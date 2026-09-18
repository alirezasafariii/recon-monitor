# Change-guidance Evaluation

Change-guidance Evaluation measures whether P6 review-only task ordering is associated with useful analyst workflow outcomes. The evaluator is local, read-only, observational, and non-causal.

## Metrics

For each Investigation Queue case, the evaluator derives:

- Evidence Gap coverage at the first persisted snapshot.
- Latest persisted Evidence Gap coverage.
- Coverage delta.
- Time from investigation start to the first persisted coverage increase.
- Time from investigation start to the first analyst decision.
- Analyst decision outcome mix.
- Whether the case had persisted `task-change-*` / Derived Change Advisory workflow guidance.

The cohort report compares change-guided and non-guided cases using descriptive metrics such as evidence-gain rate, median coverage delta, time to first evidence gain, decision rate, time to decision, and rejected/duplicate rate.

## Comparison gate

Directional cohort deltas are shown only after both cohorts have at least five cases. Before that threshold, per-cohort descriptive metrics are available but the comparative delta section is suppressed.

The threshold is a presentation safety gate, not a claim of statistical significance.

## Interpretation boundary

This evaluator does **not**:

- randomize or assign cases to cohorts;
- infer task completion from task disappearance;
- establish causal impact;
- select a winning workflow;
- auto-tune Meta Ranker, Investigation Queue, Evidence Gap, Admission, or validation;
- create target evidence;
- change analyst decisions;
- perform network requests.

Change-guided cases are selected by available change provenance, so cohort composition can differ materially. Time metrics are emitted only when the corresponding persisted event or Evidence Gap snapshot exists.

The dashboard, API, and CLI expose these limitations alongside the metrics.
