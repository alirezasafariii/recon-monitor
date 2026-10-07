# Recon Monitor 8.8.8 — DNS Downstream Coverage

Application version: **8.8.8**. Database schema: **18**, unchanged.

This release completes the DNS observation integrity fix from 8.8.7. The downstream resolved-host list now uses current A/AAAA/CNAME records after pair-scoped finalization, including preserved records for temporarily unobserved hosts. It is restricted to the current discovered in-scope input, so unrelated historical hosts cannot expand the run scope. Explicit negative observations remove hosts only when no current resolution records remain.

For hosts with resolution observations, assets.resolved is recomputed from the surviving DNS state. Collector failures leave unobserved asset flags unchanged; NS-only answers do not mark an asset resolved. Metrics expose fresh_resolved_hosts, preserved_resolved_hosts and effective_resolved_hosts separately. Preserved observations are historical coverage, not newly verified DNS answers; the DNS stage remains partial when coverage is incomplete.

Wildcard limitation: the plain dnsx filtering output does not explicitly identify newly classified wildcard hosts. No new wildcard-positive classification is inferred from omitted lines. Ambiguous filtering preserves previous flags and reports classification incomplete. An explicit classification mechanism remains future work; this release does not claim to restore it.

Install through the normal updater with backup and checksum verification. There is no schema migration, timeout change or target scan required. Historical false DNS removals and incorrect wildcard flags are not automatically repaired and require separately reviewed recovery from raw artifacts or backups.

Validation includes 24 offline DNS regressions, the 100-host warning-only scenario feeding every preserved host to URL probing and port input, 99/100 coverage, explicit negative state reset, partial negative retention, scope limits and NS-only behavior. The full suite has 1672 tests (one skipped).
