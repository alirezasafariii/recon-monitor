# Analysis Engine 6.21 — Business Logic / Race Condition raw collectors

Analysis 6.21 physically decomposes `business_logic` and `race_condition` from the alert-orchestrator monolith.

Both families remain grounded in the mandatory four-layer detector contract: OWASP WSTG, OWASP Top 10 taxonomy, MITRE CWE, and a real primary security write-up. The Branch Deploy Action GHSL-2025-038 advisory is used as the primary control-flow/TOCTOU case and its exact advisory URL is pinned in both physical detector specs.

The collector contributes emission metadata only. It does not manufacture workflow violations, duplicate effects, atomicity failures, or any other target evidence. Those signals remain owned by stored passive execution/reconstruction artifacts and are filtered through family-scoped evidence extraction and admission.

A workflow name, checkout route, transfer route, or single-use semantic is therefore only a hypothesis surface. Business Logic promotion requires an observed invariant violation. Race Condition promotion requires an observed duplicate/atomicity/concurrency effect that sequential behavior should not permit.

This phase is an architecture/regression claim and consumes no new fresh holdout.
