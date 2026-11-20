# Final review: persistent Hunt Agent

The review reproduced and corrected two orchestration defects:

| Trigger | Before | After |
| --- | --- | --- |
| Approved live plan returns stopped_for_safety | Step/mission could report completed | Engine status is retained; step partial and mission completed_with_gaps |
| Existing approved live plan before offline validation | Live priority ran first; later offline work overwrote the case state | Live is offered only after completed offline validation |
| Offline validation fails | Live plan could still be offered | Live is withheld and missing/failed work remains visible |

Four regressions in tests/test_hunt_agent_review.py failed before the correction
and passed afterward. They use actual offline/case/report engines and synthetic
live results; no external target request is made. Existing active/family/approval
checks remain owned by Safe Validation. No execution quota was added.

Local suite results are recorded in the PR description. Native runner and
production-target acceptance are separate; this review does not assert that
unobserved platform/provider checks passed.
