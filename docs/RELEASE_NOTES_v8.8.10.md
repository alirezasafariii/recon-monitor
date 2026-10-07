# Recon Monitor 8.8.10 — DNS Baseline Independence

Application version: **8.8.10**. Database schema: **18**, unchanged.

A healthy target with 129 siblings or more than 16 immediate parents could remain permanently baseline-ineligible because bounded wildcard enrichment marked the whole DNS stage partial. Primary DNS collection now determines collection_status independently. dns_collection_complete reports its health; wildcard_classification_complete, wildcard_unknown_hosts, wildcard_coverage_reasons and per-query outcomes expose enrichment gaps.

Unknown wildcard flags remain unchanged and resolved hosts remain available downstream. Probe caps, scope restrictions, insufficient control budget and ambiguous or failed control responses do not block a healthy DNS baseline. Missing, failed or malformed primary DNS observations still produce partial collection and prevent baseline replacement. Global runtime and operator interruption rules remain in force.

The probe caps (128 hosts, 16 parents), scope policy, query budget and production timeouts are unchanged. This release does not add automatic repair of historical data or claim that unprobed hosts were classified.

Offline validation includes 129 siblings, 17 parent groups, budget/scope restrictions, control warnings/timeouts, and full run lifecycle/report/snapshot persistence. Primary zero-observation and timeout regressions still reject baselines. No live target scan was performed.

Publication uses the verified exact-main CI gate and validates archive source bytes, manifest, integration, actual legacy/current updater installs and downloaded assets before publishing Latest.
