# Change-guided Task Lifecycle

P8 adds explicit analyst lifecycle feedback for review-only tasks created from Derived Change Advisory context.

## Supported lifecycle

Only tasks with deterministic `task-change-*` IDs and `source=derived_change_advisory` participate.

A task begins as `open` and may transition to exactly one terminal outcome:

- `completed`
- `skipped`

Once terminal, the task cannot switch to the other terminal state. The analyst may update the usefulness rating or note while preserving the terminal outcome.

## Usefulness feedback

Analysts may record one of:

- `useful`
- `neutral`
- `noisy`

The feedback is persisted inside the task's `details_json.analyst_feedback` object and an `investigation_change_task_feedback` Security Case event is appended for auditability.

Refresh preserves terminal change-task outcomes and feedback. Only open change-guided tasks are regenerated.

## Safety boundary

Task outcome and usefulness are workflow telemetry only. They:

- do not become target evidence;
- do not mark Evidence Gap requirements as present;
- do not change Admission;
- do not change target-evidence confidence;
- do not change Safe Validation eligibility or approvals;
- do not trigger network requests;
- do not auto-tune ranking, task ordering, rules, thresholds, or workflow policy.

P7 evaluation may summarize this explicit lifecycle telemetry, but remains observational and non-causal.
