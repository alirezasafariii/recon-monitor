# Analysis Engine 6.30 — Open Redirect Precision Calibration

Analysis 6.30 is a post-First-Blind calibration phase triggered by the consumed Analysis 6.29 Fresh Blind v5 result.

## Why this phase exists

Fresh Blind v5 passed every single-family gate. The multi-family gate failed only because one of eighteen dual-secure pairs was promoted as `open_redirect`. The stored v5 diagnostic showed both unexpected promotions belonged to `open_redirect`; no other family produced an unexpected promotion.

The failure mechanism was general rather than case-specific: detector execution treated any external `Location` header on a redirect-shaped endpoint as `external_destination`, even when the HTTP response was not itself a redirect. In the failed dual-secure v5 case, the response carrying `Location` had status 400.

## Immutable v5 boundary

Analysis 6.30 does not modify the v5 corpus, shortlist, evaluator, freeze manifest, first-blind report, or first-blind receipt. v5 is permanently consumed. Any execution of v5 after this point is explicitly a post-first-blind regression.

Frozen corpus SHA256 remains:

`0ca89aab4d2fcb00459b6c6d1328b0c9aa4ebb859835a98d66c7afe76e07ba50`

Frozen evaluator SHA256 remains:

`273df1c35f1795a8d45bf339e73bf4773448d134c676c3074b8b85fc86a97e22`

Consumed first-blind report SHA256 remains:

`1ee299ab86e0301babd31fa0729f93cc127810881f74481d899b85db31a2e9ce`

## Separate calibration set

Before the production fix is applied, Analysis 6.30 pre-registers a separate eight-case calibration set under `benchmarks/calibration/analysis_630_open_redirect.json`.

Positive source roots are independent from v5:
- CVE-2024-53995 / SickChill — user-controlled `next_` redirected to arbitrary destinations;
- CVE-2025-4143 / Cloudflare workers OAuth provider — missing `redirect_uri` allow-list validation;
- CVE-2025-62595 / Koa — protocol-relative `//host` redirect bypass.

Controls cover:
- an external `Location` on an HTTP 400 response;
- an explicit destination allow-list;
- same-origin navigation;
- relative-only navigation;
- a NoSQL-shaped confounder carrying unrelated redirect-shaped noise.

External advisories define calibration semantics only. They are not target evidence.

## Production rule change

The HTTP-header open-redirect condition becomes:

1. a redirect/navigation input surface exists;
2. the stored response is an actual HTTP redirect (`300 <= status < 400`);
3. its `Location` resolves to a different host, including protocol-relative `//host` destinations;
4. no stored allow-list, same-origin-only, or relative-only control is present.

An external `Location` on a non-3xx response is not a vulnerability condition. An explicitly allow-listed redirect remains a redirect surface but is blocked from admission.

No request is sent and no redirect is followed. The rule remains passive/offline.

## Validation plan

The one-shot 6.30 cutover must:
1. prove the pre-registered calibration set fails in the expected places before the patch;
2. apply the general production fix;
3. pass all eight independent calibration cases;
4. run consumed v5 strictly as post-first-blind regression and preserve all frozen hashes;
5. preserve 6.28 ownership and WSTG/OWASP/CWE/write-up grounding contracts;
6. pass full unit, strict Golden, and integration suites on Python 3.11 and 3.13;
7. update the release/manifest only after all gates pass.
