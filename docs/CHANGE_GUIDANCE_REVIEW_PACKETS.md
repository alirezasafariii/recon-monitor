# Change-guidance Human Review Packets

P11 joins P9 shadow calibration and P10 longitudinal drift into deterministic, non-executable review packets for human policy review.

The purpose is to make a possible policy discussion auditable without creating an automatic path from analyst feedback to production behavior.

## Readiness gate

A signal can reach `ready_for_manual_review` only when:

- P9 calibration has at least the minimum explicit feedback required for the signal;
- the calibration status is no longer `insufficient_feedback`;
- P10 drift has sufficient history in both adjacent windows;
- the combined calibration/drift state maps to a conservative human-review direction.

Otherwise the packet remains `collect_more_data`.

## Review directions

Packets may contain these non-executable directions:

- `consider_manual_promotion_review`: usefulness is strong and longitudinal behavior is stable or improving;
- `consider_manual_noise_mitigation_review`: explicit noise is elevated and increasing;
- `consider_manual_regression_review`: longitudinal usefulness declined materially;
- `retain_shadow_monitoring`: evidence is not sufficient for a conservative policy-review direction.

These values are review labels, not configuration.

## Packet contents

Each packet includes:

- deterministic proposal ID;
- signal type;
- P9 calibration status, sample counts, useful/noisy rates and Wilson intervals;
- P10 drift status, previous/recent windows and useful/noisy deltas;
- recent target and family slices for cohort-composition review;
- review rationale;
- a human review checklist;
- prohibited automatic actions.

The packet intentionally contains no proposed numeric weight, threshold, executable patch, or activation command.

## Safety boundary

The report is always `activation=human_review_only`.

A packet cannot:

- edit Meta Ranker weights;
- edit calibration or ranking thresholds;
- change Queue score;
- change Investigation Workflow task ordering;
- satisfy an Evidence Gap;
- change Admission or target-evidence confidence;
- change Safe Validation eligibility or approval;
- execute network requests;
- activate production behavior.

Even `ready_for_manual_review` means only that an analyst has enough descriptive evidence to consider a separate policy proposal.

Any production change must be implemented separately through an explicit code/config change with independent tests, review, and normal merge controls. The P11 packet itself never applies that change.
