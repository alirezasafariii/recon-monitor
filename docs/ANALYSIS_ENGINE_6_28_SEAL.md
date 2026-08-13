# Analysis Engine 6.28 Seal

Analysis Engine 6.28 seals the final candidate-orchestration cleanup on top of the calibrated and sealed Analysis 6.27 detector stack.

## Seal target

Formal 6.28 cutover commit:

`0558bcb20df1262504001d2f81fc8df5d1e51aab`

Top-level release identity:
- analysis engine: `6.28.0` / `2026.08.13.6.28`
- candidate engine: `6.28.0` / `2026.08.13.6.28`
- security reasoning: `6.28.0` / `2026.08.13.6.28`
- family orchestration: `1.0.0` / `2026.08.13.6.28`

Detector/admission semantics remain the sealed 6.27 semantics:
- detector execution: `1.3.0` / `2026.08.13.6.27`
- raw condition reconstruction: `1.2.0` / `2026.08.13.6.27`
- hypothesis admission: `2.5.0` / `2026.08.13.6.27`
- physical detector engine: `1.2.0` / `2026.08.13.6.27`
- standards engine: `1.4.0`
- family reasoners: `1.2.0` / `2026.08.13.6.27`
- family evidence extractors: `1.1.0` / `2026.08.13.6.27`

## Final primary ownership partition

The 36 vulnerability families now have an exact, disjoint, machine-verifiable primary ownership partition:
- 30 raw physical families through the central raw collector binding registry;
- 1 dedicated BOLA family (`broken_object_authorization`);
- 5 specialized static families (`source_map_exposure`, `secret_exposure`, `graphql_authorization`, `graphql_data_exposure`, `websocket_authorization`).

DOM XSS, postMessage trust, and open redirect may receive persisted JavaScript static supplemental observations, but their primary ownership remains raw. Supplements are explicitly not primary owners.

## Orchestrator invariant

`bug_candidates.py` no longer directly orchestrates individual raw collectors and no longer contains the JavaScript DOM/postMessage/open-redirect family branches. It consumes:
1. one generic raw-owned observation stream;
2. the dedicated BOLA analyzer;
3. one generic static candidate observation stream.

The old execution-family fallback is removed. A missing or overlapping primary owner is registry drift and fails validation instead of being silently emitted through a fallback.

Raw collector observations remain metadata-only. Target evidence continues to come from stored target artifacts, detector execution/reconstruction, BOLA target observations, or persisted static intelligence. OWASP WSTG, OWASP Top 10/API Security, MITRE CWE, and real-world write-ups remain detector-design knowledge only and never count as target evidence.

## Preserved calibrated behavior

The immutable consumed v4 holdout remains 144 cases = 36 families × 4 variants, and the post-first-blind regression remains:
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

Immutable first-blind boundaries remain byte-identical:
- corpus SHA256: `fe6936881b7fe0e8c71c9bc76a0f87d02446a3d703ec1dddf84e0b6caa7fb9b6`
- shortlist SHA256: `d329752e8b6045b433e3d490c0ff438f067577840fb5429a80721a0f79a34f85`
- first-blind report SHA256: `5c9d241b9da38fb374caa1851b8474aab2580dbafd1dbf25b6e68db267097960`
- receipt status: `first_blind_consumed`

## Seal validation

The final 6.28 seal must independently verify:
1. exact 6.28 top-level versions and orchestration version;
2. exact 30 + 1 + 5 ownership and no overlap across all 36 families;
3. all 36 family WSTG/OWASP/CWE/write-up grounding and the external-knowledge/non-target-evidence invariant;
4. the immutable v4 hashes and consumed first-blind receipt;
5. the post-first-blind v4 quality-gate pass with zero false or wrong-family promotions;
6. full unit suite on Python 3.11 and Python 3.13;
7. strict Golden benchmark on Python 3.11 and Python 3.13;
8. integration suite on Python 3.11 and Python 3.13;
9. manifest integrity.

No first-scan/second-scan alert lifecycle behavior is changed by Analysis 6.28.
