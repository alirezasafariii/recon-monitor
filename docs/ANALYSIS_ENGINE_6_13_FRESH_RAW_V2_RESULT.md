# Analysis Engine 6.13 — Fresh Raw Holdout v2 Result

## Status

Analysis 6.13 completed exactly one first fresh evaluation of the sealed raw v2 holdout.

- Fresh evaluation run: `31471744115`
- Evaluation head: `f60469a6d69dfe26a174a77c808f9556813cc4ae`
- Corpus: `benchmarks/raw/analysis_raw_v2.jsonl`
- Corpus SHA-256: `1ad289915f89bf281fd6a80e0b8d55ebb045ecd8f9658b1ae9d88f07afddb1f3`
- Cases: 96
- Source roots: 24
- Source projects: 24
- Positive families: 20
- Positive/control exact raw collisions: 0
- Positive observable-delta rate: 1.0
- Prior source-root overlap: 0
- Prior URL overlap: 0

The corpus was marked `evaluated_once_consumed` in the same one-shot workflow immediately after scoring. It must never be described or rerun as fresh/blind again.

## Pre-registered quality result

The overall quality gate **did not pass**.

| Metric | Result | Gate | Status |
|---|---:|---:|---|
| Condition extraction precision | 0.840000 | >= 0.90 | FAIL |
| Condition extraction recall | 0.875000 | >= 0.75 | PASS |
| Routing Top-1 | 0.930556 | >= 0.80 | PASS |
| Routing Top-3 | 0.986111 | >= 0.95 | PASS |
| Admission precision | 0.913043 | >= 0.93 | FAIL |
| Admission recall | 0.875000 | >= 0.75 | PASS |
| Abstention accuracy | 0.972222 | >= 0.90 | PASS |
| False-promotion rate | 0.027778 | <= 0.07 | PASS |
| Wrong-family promotion rate | 0.000000 | <= 0.05 | PASS |
| End-to-end accuracy | 0.947917 | >= 0.80 | PASS |
| Prior source-root overlap rate | 0.000000 | 0 | PASS |
| Raw-label leakage rate | 0.000000 | 0 | PASS |

The failure is narrow and useful: recall, routing, abstention, end-to-end behavior, and provenance safety are all above their pre-registered gates; two precision gates remain below threshold.

## Condition false positives

The saved first-evaluation report contains four condition false positives.

### 1. Account Enumeration — timing differential too sensitive

`GHSA-43mm-m3h2-3prc-near_miss`

The near-miss stored contexts differed only slightly (`51 ms` vs `52 ms`). Analysis 6.12 treats any observable tuple difference as sufficient for `response_difference`. This is too permissive for timing evidence: normal jitter can satisfy the condition.

Required next boundary: timing-based enumeration evidence needs a materiality threshold or repeated-sample/statistical separation rather than simple tuple inequality.

### 2–3. CORS — authenticated context is being counted as condition evidence

`GHSA-7p93-6934-f4q7-near_miss`

`GHSA-7p93-6934-f4q7-secure_negative`

Both controls emitted `authenticated_context` despite not establishing an unsafe cross-origin policy. Admission did not promote them, but the raw benchmark correctly counted them as condition predictions because `authenticated_context` is currently in the family's condition allowlist.

Required next boundary: authenticated/sensitive context is contextual evidence, not by itself a vulnerability condition. Unsafe origin policy and cross-origin exposure semantics must remain decisive.

### 4. NoSQL Injection — error signature is too broad

`GHSA-47r2-v3x6-wff9-near_miss`

The ordinary text `document query returned zero results` matched the generic `document query` NoSQL error pattern and emitted `nosql_error_observed`, causing both a condition false positive and an admission false positive.

Required next boundary: remove generic document-query wording from error signatures and require actual engine/operator/parser error structure or another direct query-influence observation.

## Admission false positives

There were exactly two:

1. Account Enumeration near-miss above.
2. NoSQL Injection near-miss above.

Both are condition-extraction specificity bugs, not admission-threshold failures. The correct fix is to improve evidence semantics rather than raise or lower global admission thresholds.

## Condition/admission false negatives

There were exactly three positive misses:

### Command Injection

`GHSA-g6g7-pvmx-m74p-positive`

Routing identified the family correctly, but the engine stopped at process-execution surface evidence and did not reconstruct `process_execution_reached` from stored raw execution behavior.

### Race Condition

`GHSA-h54m-c522-h6qr-positive`

Routing identified race-condition semantics, but no conservative raw reconstruction exists for `duplicate_effect_observed` / atomicity failure from paired concurrent results.

### Unrestricted Resource Consumption

`GHSA-qw5r-ppcg-f8rj-positive`

Routing identified the resource-consumption surface, but stored size/duration/output amplification is not yet translated into `resource_exhaustion_differential` or a related decisive condition.

These misses were expected from the pre-evaluation 6.12 capability audit and were intentionally not hidden with engine-native flags in the raw corpus.

## Routing residuals

- Top-1 errors: 5
- Top-3 errors: 1

The dominant Top-1 confusion is Authentication Session vs Account Enumeration on login-shaped surfaces without decisive condition evidence. The lone Top-3 miss is a secure-negative Secret Exposure case with no remaining family identity evidence, where generic fallback families outrank the expected diagnostic family.

## Scientific conclusion

Raw v2 successfully corrected the central design defect of raw v1: every positive now has a distinct target-observable raw delta, with zero positive/control raw collisions and zero prior-corpus overlap.

The first fresh result shows that frozen Analysis 6.12 generalizes substantially better than raw v1 on recall and routing, but it does **not** yet meet the pre-registered precision bar. The next production phase should therefore target evidence specificity and missing family-specific raw condition reconstruction—not lower benchmark gates or relax admission policy.

## Recommended next production phase

**Analysis 6.14 — Raw Evidence Specificity & Missing Condition Reconstruction**

Priority order:

1. Account-enumeration timing materiality / repeated-sample differential.
2. NoSQL error-signature precision.
3. CORS contextual-vs-condition signal separation.
4. Command-injection stored process-effect reconstruction.
5. Race-condition paired/concurrent-effect reconstruction.
6. Resource-consumption size/time/cost differential reconstruction.
7. Authentication-vs-enumeration family-fit confusion cleanup.

Raw v2 is consumed diagnostic evidence for that work. Any later claim of fresh generalization must use a new independently sealed corpus.
