# Change-guidance Drift Monitoring

P10 adds longitudinal monitoring for the explicit analyst feedback collected by P8 and summarized by the P9 shadow calibration report.

The monitor compares each Derived Change Advisory `signal_type` across two adjacent, equal-duration UTC windows. By default each window is 30 days. The windows are anchored to the **latest explicit analyst feedback timestamp present in the data**, not to the machine clock, so historical replay remains deterministic.

## Inputs

Only persisted change-guided tasks with all of the following are considered:

- deterministic `task-change-*` identity;
- `source=derived_change_advisory`;
- `advisory_only=true`;
- explicit usefulness feedback: `useful`, `neutral`, or `noisy`;
- valid `analyst_feedback.recorded_at` timestamp.

The latest persisted rating per task is the longitudinal sample.

## Windows and sample gate

For an anchor timestamp `T` and a window size `W`:

- recent window: `[T-W, T]`
- previous window: `[T-2W, T-W)`

A signal remains `insufficient_history` until **both** windows contain at least five explicit ratings.

Recent target and family slices are also included for cohort-composition review. These slices are descriptive only; a slice is marked sample-sufficient after three recent ratings.

## Monitoring statuses

When both windows satisfy the sample gate, the monitor can emit these review-only statuses:

- `noise_increase_watch`: recent noisy rate increased materially;
- `utility_decline_watch`: recent useful rate declined materially;
- `utility_improvement_watch`: recent useful rate increased materially while observed noise remains low;
- `stable`: useful/noisy rates remained within conservative drift bands;
- `mixed_shift`: rates moved, but no conservative watch condition was met.

These are monitoring prompts, not statistical significance tests and not production configuration.

## Safety boundary

The drift report is always `activation=monitoring_only`.

It cannot:

- change Meta Ranker weights;
- change calibration thresholds;
- change Queue score;
- change Investigation Workflow task ordering;
- mark Evidence Gap requirements present;
- change Admission or target-evidence confidence;
- change Safe Validation eligibility or approval;
- trigger network requests;
- auto-tune any production rule, threshold, score, or policy.

Feedback is subjective and non-randomized. Target mix, bug-family mix, deployment mix, and analyst behavior can differ between windows, so drift must be interpreted as an operational review signal rather than a causal conclusion.
