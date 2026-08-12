# Analysis Engine 6.19 — Seal

Analysis 6.19 is sealed after the client-side collector cutover and the four-layer security-knowledge grounding upgrade.

## Sealed version lineage

- Analysis engine: `6.19.0`
- Candidate engine: `6.19.0`
- Security reasoning engine: `6.19.0`
- Analysis rule lineage: `2026.08.12.6.19`
- Client-side collector rule lineage: `2026.08.12.6.19`
- Standards engine: `1.3.0`
- Physical detector engine: `1.1.0`
- OWASP taxonomy reference: `Top10:2025+API-Security:2023`

## Mandatory detector knowledge contract

Every one of the 31 vulnerability families is required to carry four independent knowledge layers:

1. OWASP WSTG testing guidance.
2. OWASP Top 10:2025 and/or OWASP API Security Top 10:2023 taxonomy.
3. MITRE CWE weakness mapping.
4. At least one relevant real-world security write-up with an explicit detector lesson.

The physical detector registry fails closed if WSTG, OWASP, CWE, or write-up grounding is absent. Detector rule lineage exposes `wstg:*`, `owasp:*`, `cwe:*`, and `writeup:*` identifiers.

## Evidence boundary

Standards and write-ups define the detector criteria, family identity, confounders, and required vulnerability condition. They never count as target evidence, never satisfy independent-source requirements, and never override target-side contradictions. Promotion still requires stored target evidence from passive execution/reconstruction and family-specific admission.

## Client-side family boundary

- DOM XSS: WSTG-CLNT-01 + OWASP A05:2025 + CWE-79 + relevant DOM-XSS write-up evidence model.
- postMessage trust: WSTG-CLNT-11 + OWASP A07:2025 + CWE-940/CWE-346 + postMessage/external-message write-ups.
- Open Redirect: WSTG-CLNT-04 + OWASP A01:2025 + CWE-601 + real Open Redirect write-up.

Hidden near-miss hypotheses may coexist with promoted hypotheses in the same family. This is intentional: incomplete client-side surfaces are retained for correlation while only observations carrying decisive family-condition evidence can promote.

## Validation boundary

The seal requires four-layer standards validation, client-side collector regression, the full unit suite, strict Golden benchmark, and integration runner. It is an architecture/regression claim, not a universal real-world accuracy claim.
