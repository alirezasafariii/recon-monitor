# Analysis Engine 6.13 — Fresh Raw Holdout v2

## Goal

Analysis 6.13 evaluates the frozen Analysis 6.12 raw-artifact pipeline on a second independent holdout. The purpose is to test whether the 6.12 reconstruction and routing improvements generalize to unseen source roots without reusing the consumed raw v1 corpus as fresh evidence.

## Frozen production boundary

The production detector/reasoning path is frozen at Analysis 6.12 clean head:

`2c3dcd78774b484a812ce60571dca0d6eecbd4ae`

The benchmark branch may add corpus/validation/evaluation tooling, but it must not change the frozen detector, reconstruction, admission, ranking, standards, or security-reasoning logic before the first v2 evaluation.

## Core execution contract

stored raw/minimally-normalized target artifact → Analysis 6.12 execution/reconstruction → physical family detector → evidence firewall → hidden hypothesis/admission → family reasoner/ranking → finding or abstention

No live requests, exploit payloads, brute force, identifier guessing, secret validation, redirect following, or application-state mutation are part of this benchmark.

## Why v2 is different from raw v1

Raw v1 exposed an important fixture-design problem: 15 of 24 source roots had a positive variant that was raw-identical to at least one negative/control variant. Those roots could not be separated by any deterministic detector using only permitted raw input.

Raw v2 makes observability a pre-seal corpus requirement. For every source root:

- the positive raw artifact must differ from both the near-miss and secure-negative artifacts;
- `raw.details` for the positive must contain a distinct target-observable delta relative to both controls;
- a label, CWE, advisory prose, or expected family is never copied into raw detector input;
- engine-native evidence signal keys remain forbidden inside raw input.

If these conditions are not met, the source root is rejected before corpus sealing.

## Independence policy

A v2 source root and canonical advisory URL must be absent from:

- Golden v3;
- Golden v4;
- raw v1.

The source root is the split unit. All four variants for a root stay together. Duplicate projects should be avoided when an unused project is available, but root and URL independence are the hard requirements.

## Required variants

Each selected source root must produce exactly four variants:

1. `positive` — raw target evidence contains a materially observable condition;
2. `near_miss` — same family surface without the vulnerability condition;
3. `secure_negative` — an explicit blocking/control result where available;
4. `sparse_noisy` — insufficient raw evidence that should remain a hidden hypothesis or abstention.

## Collection floors

Pre-registered minimums:

- 24 source roots;
- 20 source projects;
- 18 positive families;
- 96 total cases;
- exactly four variants per source root.

Primary sources are required. GitHub reviewed security advisories are preferred; project/vendor advisories are acceptable when they are the primary publication.

## Acceptance gates

The scoring gates are intentionally kept identical to raw v1 so the second holdout is directly comparable rather than tuned after seeing v1 outcomes:

- condition extraction precision ≥ 0.90;
- condition extraction recall ≥ 0.75;
- routing Top-1 ≥ 0.80;
- routing Top-3 ≥ 0.95;
- admission precision ≥ 0.93;
- admission recall ≥ 0.75;
- abstention accuracy ≥ 0.90;
- false-promotion rate ≤ 0.07;
- wrong-family-promotion rate ≤ 0.05;
- end-to-end accuracy ≥ 0.80;
- prior source-root overlap rate = 0;
- raw-label leakage rate = 0.

Additional v2 hard corpus gates:

- positive/control exact raw collisions = 0;
- positive target-observable delta rate = 1.0.

## Scientific sequencing

The required sequence is:

1. create the 6.13 benchmark tooling;
2. pre-register gates, collection floors, source buckets, and the frozen Analysis 6.12 boundary;
3. seal the protocol and record exact protected file/tree hashes;
4. only then begin source discovery and fixture materialization;
5. validate corpus structure, provenance independence, raw-label leakage, and observability without detector scoring;
6. seal the completed corpus with a SHA-256 digest;
7. run exactly one first fresh evaluation;
8. immediately mark v2 `evaluated_once_consumed` and record the run, head SHA, report, and metrics;
9. every later run is regression-only and must never be described as fresh or blind.

## Retuning rule

No detector, reconstruction, admission, ranking, standards, or family-reasoning changes are allowed between protocol freeze and the first fresh v2 evaluation. If the first evaluation fails, v2 becomes consumed diagnostic evidence. Any subsequent production improvements must be made on a new branch and evaluated later on a new independent corpus.
