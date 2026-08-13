# Analysis Engine 6.27 — Blind Failure Calibration

Analysis 6.27 repairs production detector/reconstruction/admission precision after the immutable Analysis 6.26 raw-v4 first-blind holdout exposed real gaps.

## Immutable evaluation boundary

The v4 corpus was frozen before first scoring and remains unchanged:
- 144 cases: 36 families × positive / near-miss / secure-negative / sparse-noisy
- corpus SHA256: `fe6936881b7fe0e8c71c9bc76a0f87d02446a3d703ec1dddf84e0b6caa7fb9b6`
- shortlist SHA256: `d329752e8b6045b433e3d490c0ff438f067577840fb5429a80721a0f79a34f85`
- immutable first-blind report SHA256: `5c9d241b9da38fb374caa1851b8474aab2580dbafd1dbf25b6e68db267097960`

The first blind is permanently consumed. Analysis 6.27 never edits the v4 corpus, shortlist, source audit, expected labels, or first-blind result. Every later v4 execution is explicitly a post-first-blind regression.

## First-blind result that triggered calibration

The immutable first blind failed its pre-registered gates: condition precision 0.452830, condition recall 0.666667, Top-1 routing 0.629630, Top-3 routing 0.824074, admission precision 0.469388, admission recall 0.638889, false-promotion rate 0.129630, wrong-family promotion rate 0.145833, and end-to-end accuracy 0.777778.

The stored-result diagnostic identified condition-reconstruction gaps across the newly completed families and a major cross-family precision leak from sensitive caching. It also exposed narrower ownership confusions involving GraphQL versus generic BOLA/authentication, login versus function authorization, business path names versus API inventory, generic exception text versus security misconfiguration, and third-party TLS certificate validation.

## Production repairs

Analysis 6.27 changes production logic rather than benchmark inputs:
- sensitive caching now needs observed cacheability/shared-cache behavior and real stored authentication/sensitive-response context;
- DOM and postMessage use stored browser/message behavior and retain safe-path blockers;
- GraphQL resolver authorization and GraphQL sensitive-data expansion own their stored response conditions instead of leaking into generic BOLA/authentication;
- WebSocket unauthorized subscription requires stored unauthorized subscription/message behavior;
- business-logic and sensitive-business-flow conditions are reconstructed from explicit workflow/automation observations;
- OWASP Top 10:2025 completion families reconstruct concrete stored component, TLS, update-integrity, logging, and exceptional-condition outcomes;
- source-map promotion requires meaningful embedded/internal source material plus public reachability;
- unsafe API consumption includes certificate-hostname validation failure, grounded in CWE-295, without turning the consumed holdout advisory into detector grounding;
- API inventory and generic authorization heuristics use narrower ownership boundaries;
- CORS is modeled as explicit CORS surface → unsafe origin policy → credential/sensitive exposure;
- handled exceptions and safe DOM/CORS paths remain useful routing identity while blocking promotion.

All existing WSTG, OWASP, CWE, and write-up grounding remains detector criteria only. External standards/write-ups never count as target evidence.

## Post-first-blind regression

After calibration, the same immutable 144-case corpus reports:
- condition precision: 1.000000
- condition recall: 1.000000
- Top-1 routing: 0.861111
- Top-3 routing: 0.962963
- admission precision: 1.000000
- admission recall: 1.000000
- near-miss abstention: 1.000000
- secure-negative rejection: 1.000000
- sparse/noisy abstention: 1.000000
- false-promotion rate: 0.000000
- wrong-family promotion rate: 0.000000
- positive end-to-end accuracy: 1.000000
- overall end-to-end accuracy: 1.000000

Every pre-registered v4 quality gate passes. Remaining routing ambiguity is limited to non-promoted control cases and remains above the pre-registered Top-1/Top-3 gates; it is not overfit away by changing benchmark labels or adding case-specific scoring.
