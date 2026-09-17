# Evidence Gap and Case Autopilot

Evidence Gap answers three questions for every case: what evidence is already present, what is missing, and what is the safest next analyst action. Case Autopilot converts these gaps into investigation tasks.

Sensitive authorization families stay manual-only/controlled. Autopilot never performs cross-user enumeration, credential replay, exploit payload execution, destructive operations or automatic confirmation. Analyst decisions remain authoritative and auditable.

## Change-aware investigation prioritization

Investigation Queue cases may carry successful-run source-map or JavaScript chunk change provenance from the Derived Change Advisory pipeline. This context may reorder analyst review tasks and highlight which **already-missing** Evidence Gap requirements deserve attention first.

The boundary is strict:

- derived change context does not mark an Evidence Gap requirement as present;
- Evidence Gap coverage is calculated exactly as before from target evidence;
- Autopilot readiness is calculated exactly as before;
- validation eligibility and approval gates are unchanged;
- change-guided tasks are review-only and cannot execute validation;
- no network request is made by change-aware prioritization;
- the context cannot satisfy Admission or confirm a vulnerability.

When persisted for an Investigation Queue case, change-guided tasks are stored separately with `advisory_only=true`, `counts_as_evidence=false`, and `can_execute_validation=false`. Existing evidence-collection tasks remain intact and are shifted below the change-review task rather than replaced.
