# Analysis Engine 6.16 — Physical Raw Collector Decomposition

Analysis 6.16 begins the physical removal of duplicate raw-family collection logic from `bug_candidates._alert_candidates()` after Analysis 6.15 demonstrated that the Analysis 6.14 execution/reconstruction stack generalized on a new blind raw holdout.

## Injection batch

The first migration batch owns five server-side injection families:

- SQL Injection
- NoSQL Injection
- OS Command Injection
- Server-Side Template Injection
- LDAP Injection

`app/raw_family_collectors/injection.py` now owns only family emission metadata: variant, base score, missing-evidence prompts, rule identifiers, and summary. It does **not** create target evidence. Target evidence remains produced by `execute_detector_intelligence()` and the Analysis 6.14 reconstruction layer, then passes through the existing physical detector firewall, hidden-hypothesis ledger, admission gate, independent-source guard, and candidate insertion path.

The physically duplicated Analysis 6.1 SQL/NoSQL/Command/SSTI/LDAP block is removed from `_alert_candidates()`. The generic execution fallback no longer handles these families because the dedicated injection collector explicitly emits them first.

## Non-goals

- No admission threshold changes.
- No ranking changes.
- No detector condition changes.
- No reconstruction changes.
- No active requests or payload execution.
- No claim that all remaining legacy raw collectors have been decomposed yet.

Authorization, file handling, client-side, API-resilience/configuration, and business-flow collector batches remain for later phases.

## Validation contract

The migration must retain:

- exact five-family physical collector coverage;
- positive admission for family-specific stored conditions;
- abstention on near misses;
- SQL/NoSQL condition separation;
- hypothesis routing through the dedicated collector rule lineage;
- all existing unit, Golden, and integration regressions.

Raw v1/v2/v3 remain consumed diagnostics. Analysis 6.16 does not create a new fresh accuracy claim.
