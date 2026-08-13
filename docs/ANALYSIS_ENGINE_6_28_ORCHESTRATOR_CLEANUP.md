# Analysis Engine 6.28 — Final Orchestrator Cleanup

Analysis 6.28 removes family-specific orchestration from `bug_candidates.py` while preserving all detector, admission, standards, and evidence semantics sealed in 6.27.

## Primary ownership partition

The primary family ownership registry is now machine-verifiable:
- 30 raw physical families through nine metadata-only raw collector bindings;
- 1 dedicated BOLA family through `bola_intelligence.py`;
- 5 specialized static families through `static_family_collectors.py`.

The three JavaScript families DOM XSS, postMessage trust, and open redirect may receive persisted static supplemental observations, but their primary ownership remains raw. Supplemental adapters never alter the 30 + 1 + 5 partition.

## Orchestrator shape

`bug_candidates._alert_candidates()` now follows one generic path:
1. execute passive detector intelligence;
2. collect raw-owned metadata through the central registry;
3. run the dedicated BOLA analyzer;
4. apply generic detector extraction, hypothesis admission, quality guard, and candidate insertion.

There is no execution-family fallback and no per-family raw collector loop in the orchestrator. All 36 primary owners are explicit, so an unowned execution family is treated as registry drift instead of being silently emitted.

`bug_candidates._static_candidates()` now consumes one static adapter stream. DOM/postMessage/open-redirect branching lives in a static supplemental adapter; specialized static family ownership remains unchanged.

## Security invariant

WSTG, OWASP, CWE, and related write-ups remain detector-design knowledge only. They never count as target evidence. Promotion continues to require stored target evidence satisfying the existing family detector and admission contracts.

## Validation

The 6.28 cutover must preserve the immutable 6.26 v4 corpus and the sealed 6.27 regression metrics, then pass the full unit, strict Golden, and integration suites on Python 3.11 and Python 3.13.

No first-scan/second-scan alert lifecycle behavior is changed in 6.28.
