# Recon Monitor 8.8.9 — Migration

Application version: **8.8.9**. Database schema: **18**, unchanged.

Wildcard candidates now require three random in-scope sibling controls and repeated A/AAAA/CNAME observations. Stable matching CNAME or complete stable address profiles establish a candidate; explicit negative controls can clear a previous flag. Missing rows, failures, rotating address-only responses and conflicting profiles remain unknown and preserve previous flags.

A wildcard candidate shares an observed DNS response. It does not prove that a host is nonexistent. All resolved hosts remain available to URL probing and port input. Controls never become assets or persisted target DNS records.

Queries obey scope, shared budgets, parent/host caps and runtime limits. Per-host normalized evidence is saved in dns-wildcard-evidence.jsonl. Coverage limits or ambiguity report incomplete classification. Existing DNS preservation fixes remain in place. There is no timeout increase, schema migration or automatic historical repair.

Offline validation covers stable positives/negatives, partial observations, scope and budgets, rotating CDN responses, conflicting CNAME/IPv6 profiles and the 100-host warning-only failure. Live behavior on the user's Mac remains a separate controlled acceptance test.

The verified publisher requires all seven CI jobs for the exact main push commit, including macOS unit/integration/cleanup and Safari. It also verifies archive bytes, manifest, integration, actual legacy/current updater installs and downloaded release assets before publishing Latest.

Use the standard updater with a verified checksum and backup. Historical wildcard flags are preserved when new evidence is unknown; they are not automatically repaired.
