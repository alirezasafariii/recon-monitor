# Recon Monitor 8.8.14 — Katana Completion Integrity

Application version: **8.8.14**. Database schema: **18**, unchanged.

A bounded Katana process can return zero after its internal crawl deadline.
Zero exits lasting at least one input's crawl duration are conservatively
recorded as `completion_unverified`, stop reason `crawl_completion_unverified`.
The URL stage remains partial, discovered URLs are retained and uncertain
origins remain pending. This is an uncertainty guard, not proof of timeout;
a healthy long batch can also be marked unverified. Fast successful batches
and uncapped mode retain their existing behavior. Full HTTP response coverage
and request errors require separate evidence.

Doctor warns about Katana 1.6.1's queue cancellation defect despite valid flags.
Upgrade the external binary separately; Recon does not replace it. Operator
macOS tests of Katana 1.8.0 returned zero in 2.15 seconds for one local input
and 50.15 seconds for five delayed local inputs. Full target acceptance is
not established by these tests.

No increase to timeout, rate, request reservation, scope or budget; no schema
migration or automatic rewrite of historical results. Publication requires
green exact-main CI, archive/manifest, fixture integration, actual updater
installation and downloaded release verification.
