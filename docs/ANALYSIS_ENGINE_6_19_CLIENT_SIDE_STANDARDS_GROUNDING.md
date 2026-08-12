# Analysis Engine 6.19 — Client-side collectors + four-layer standards grounding

Analysis 6.19 introduces a physical client-side raw collector for DOM XSS, postMessage trust, and Open Redirect, and upgrades the detector knowledge contract for all 31 vulnerability families.

## Mandatory four-layer grounding

Every physical family detector must now have all four layers:

1. **OWASP WSTG** — testing method and condition model.
2. **OWASP Top 10:2025 and/or OWASP API Security Top 10:2023** — risk taxonomy and family context.
3. **MITRE CWE 4.20** — weakness taxonomy and root-cause mapping.
4. **Real security write-up(s)** — concrete primary cases used to sharpen the family pattern, confounders, and decisive evidence boundary.

The detector registry refuses incomplete grounding. Detector rule lineage now carries `wstg:*`, `owasp:*`, `cwe:*`, and `writeup:*` metadata.

## Evidence firewall

External knowledge is never target evidence. OWASP, WSTG, CWE, write-up, advisory, or knowledge-source material cannot satisfy an admission group, cannot count as an independent target source, and cannot override a target contradiction. Only stored target artifacts produced by passive execution/reconstruction may do that.

## Client-side batch

- `dom_xss`: WSTG-CLNT-01 + OWASP A05:2025 + CWE-79 + GHSL-2023-205 go2rtc DOM XSS.
- `postmessage_trust`: WSTG-CLNT-11 + OWASP A07:2025 + CWE-940/CWE-346 + GCHQ Stroom postMessage origin-validation case and GHSL-2024-027/028 external-message case.
- `open_redirect`: WSTG-CLNT-04 + OWASP A01:2025 + CWE-601 + GHSL-2020-085 Sourcegraph Open Redirect.

The collector owns emission metadata only. `family_detectors.execution`, reconstruction, the physical detector, family evidence scoping, hidden-hypothesis ledger, admission, independent-source guard, and candidate insertion retain their existing responsibilities.

## Scientific boundary

This phase is an architecture and regression claim. It does not claim universal vulnerability detection accuracy and does not consume a new fresh holdout. Existing Golden/raw corpora remain regression assets only.
