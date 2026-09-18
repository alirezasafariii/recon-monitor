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
- Explicit change-task terminal outcome (`completed` or `skipped`).
- Explicit analyst usefulness feedback (`useful`, `neutral`, or `noisy`).
- Time from investigation start to an explicit terminal change-task update.

The cohort report compares change-guided and non-guided cases using descriptive metrics such as evidence-gain rate, median coverage delta, time to first evidence gain, decision rate, time to decision, and rejected/duplicate rate. For the change-guided cohort it also reports explicit task terminal rate, feedback coverage, useful/neutral/noisy rates, and median time to task outcome.

## Comparison gate

Directional cohort deltas are shown only after both cohorts have at least five cases. Before that threshold, per-cohort descriptive metrics are available but the comparative delta section is suppressed.

The threshold is a presentation safety gate, not a claim of statistical significance.

## Interpretation boundary

This evaluator does **not**:

- randomize or assign cases to cohorts;
- infer task completion from task disappearance or task regeneration;
- establish causal impact;
- select a winning workflow;
- auto-tune Meta Ranker, Investigation Queue, Evidence Gap, Admission, or validation;
- create target evidence;
- change analyst decisions;
- perform network requests.

Change-guided cases are selected by available change provenance, so cohort composition can differ materially. Task lifecycle metrics count only explicit analyst-recorded terminal states and usefulness ratings; missing ratings remain unknown. Time metrics are emitted only when the corresponding persisted event, Evidence Gap snapshot, or terminal task update exists.

The dashboard, API, and CLI expose these limitations alongside the metrics.
