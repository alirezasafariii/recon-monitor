# Analysis Engine 6.27 Seal

Analysis Engine 6.27 seals the blind-failure calibration derived from the immutable Analysis 6.26 Fresh Raw Holdout v4 first-blind result.

## Seal target

Formal cutover commit:

`a3f39f62a92f62a439d71496ba1bb3cdd8c13e3c`

The seal preserves the exact Analysis 6.27 layer versions:
- analysis engine: `6.27.0` / `2026.08.13.6.27`
- candidate engine: `6.27.0` / `2026.08.13.6.27`
- security reasoning: `6.27.0` / `2026.08.13.6.27`
- detector execution: `1.3.0` / `2026.08.13.6.27`
- raw condition reconstruction: `1.2.0` / `2026.08.13.6.27`
- hypothesis admission: `2.5.0` / `2026.08.13.6.27`
- physical detector engine: `1.2.0` / `2026.08.13.6.27`
- standards engine: `1.4.0`
- family reasoners: `1.2.0` / `2026.08.13.6.27`
- family evidence extractors: `1.1.0` / `2026.08.13.6.27`

## Grounding invariant

All 36 vulnerability families retain mandatory WSTG, OWASP, CWE, and related real-world write-up grounding. External standards and write-ups remain detector-design knowledge only and never count as target evidence. Promotion continues to require stored target observations/artifacts satisfying each family's evidence and admission contract.

## Immutable v4 boundary

The consumed v4 holdout remains byte-identical to the first-blind inputs:
- 144 cases = 36 families × 4 variants
- corpus SHA256: `fe6936881b7fe0e8c71c9bc76a0f87d02446a3d703ec1dddf84e0b6caa7fb9b6`
- shortlist SHA256: `d329752e8b6045b433e3d490c0ff438f067577840fb5429a80721a0f79a34f85`
- immutable first-blind report SHA256: `5c9d241b9da38fb374caa1851b8474aab2580dbafd1dbf25b6e68db267097960`
- first-blind status: `first_blind_consumed`

The original first-blind failure is preserved permanently. No benchmark source, fixture, expected label, source audit, or first-blind result was modified during calibration. Every 6.27 v4 execution is explicitly a post-first-blind regression.

## Sealed post-blind regression

The same immutable 144-case corpus after production-side calibration reports:
- condition extraction precision: `1.000000`
- condition extraction recall: `1.000000`
- routing Top-1: `0.861111`
- routing Top-3: `0.962963`
- admission precision: `1.000000`
- admission recall: `1.000000`
- abstention accuracy: `1.000000`
- near-miss abstention: `1.000000`
- secure-negative rejection: `1.000000`
- sparse/noisy abstention: `1.000000`
- false-promotion rate: `0.000000`
- wrong-family promotion rate: `0.000000`
- positive end-to-end accuracy: `1.000000`
- overall end-to-end accuracy: `1.000000`
- prior-source-root overlap rate: `0.000000`
- raw-label-leakage rate: `0.000000`

All pre-registered v4 quality gates pass. The remaining routing ambiguity is confined to non-promoted control cases and remains above the pre-registered Top-1 and Top-3 gates; the seal does not overfit those controls by changing benchmark inputs or introducing case-specific scoring.

## Validation required by the seal

The final seal re-validates:
1. exact Analysis 6.27 version and ownership contract;
2. all 36 family WSTG/OWASP/CWE/write-up grounding;
3. immutable consumed-v4 hashes and first-blind receipt;
4. post-first-blind v4 quality-gate pass;
5. no condition false positives and no wrong-family promotions in the stored 6.27 diagnostic;
6. full unit suite on Python 3.11 and Python 3.13;
7. strict Golden benchmark on Python 3.11 and Python 3.13;
8. integration suite on Python 3.11 and Python 3.13;
9. manifest integrity.

No alert lifecycle behavior is changed by this seal.
