# Analysis Engine 6.15 — Fresh Raw Holdout v3

Analysis 6.15 performs one new blind raw-artifact evaluation of the frozen Analysis 6.14 engine. The benchmark protocol, quality gates, production code hashes, collision rules, and corpus validator are sealed before any new v3 source discovery.

## Scientific contract

- Raw v1 and raw v2 are consumed diagnostics and are never treated as fresh again.
- Source roots and canonical advisory URLs must be absent from Golden v3, Golden v4, raw v1, and raw v2.
- Every root has four variants: positive, near_miss, secure_negative, sparse_noisy.
- A positive raw artifact must differ from near_miss and secure_negative and contain a target-observable delta.
- No engine-native signal names, typed evidence arrays, CWE labels, WSTG labels, or advisory conclusions may be copied into raw detector input.
- No production tuning is permitted after the first v3 score while still calling v3 fresh/blind.
- The first score consumes v3 permanently, regardless of PASS or FAIL.

## Pre-registered quality gates

The same raw gates used by Analysis 6.13 are retained for direct comparability: extraction P/R, routing Top-1/Top-3, admission P/R, abstention, FPR, wrong-family promotion, end-to-end accuracy, source overlap, and label leakage. Positive/control raw collision must be zero and positive observable-delta rate must be 1.0.

A fresh PASS demonstrates generalization only within this curated raw-artifact benchmark boundary; it is not a claim of universal real-world vulnerability-detection accuracy.
