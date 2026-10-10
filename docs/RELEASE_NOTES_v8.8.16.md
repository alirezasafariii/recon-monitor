# Recon Monitor 8.8.16 — Optional Katana Per-Origin Completion

Application version: **8.8.16**. Database schema: **18**, unchanged.

Compatible standard-engine Katana producers can emit explicit v1 completion events. Recon removes independently completed origins from the crawl backlog while retaining failed or missing siblings; resume retries unfinished origins only. Fresh bounded artifacts, strict origin/counter validation, and process timeout, nonzero-exit and operator-stop overrides reject unreliable evidence. Partial URL output remains available. Existing request budgets, rate, concurrency and timeout limits are unchanged.

The official Katana 1.8.0 binary does not emit this experimental contract. It retains the existing conservative completion behavior. This release does not bundle or install a patched crawler, and updating Recon alone does not fix the stock crawler queue lifecycle. The separately reviewed prototype is tracked in PR #160. Queue exhaustion describes bounded standard-engine work, not exhaustive website coverage; browser modes and the separate transport timeout behavior are not certified.

Validation: 43 focused regressions and the full 1733-test suite passed. All seven PR #161 exact-head CI jobs passed. Operator-reported macOS Intel component acceptance with an isolated patched producer passed healthy, mixed-error and pending-only resume scenarios. Discovery/database were stubbed and requests were loopback-only; this was not a full production target run. Publication remains gated on successful exact-main CI, archive/manifest checks, updater installation tests and downloaded asset verification.

No historical crawl status, backlog or DNS state is rewritten. See docs/KATANA_COMPLETION_CONTRACT.md.
