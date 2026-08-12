# Analysis Engine 6.17 — Authorization Raw Collector Decomposition

Analysis 6.17 begins the next physical raw-collector migration after the five injection families moved out of `bug_candidates._alert_candidates()` in Analysis 6.16.

## Scope of the authorization batch

This batch owns the two authorization/property families whose raw alert collection logic still lives directly in the legacy candidate orchestrator:

- Broken Function Level Authorization
- Mass Assignment / Broken Object Property Level Authorization

The new `app/raw_family_collectors/authorization.py` registry owns emission metadata only: family, variant, base score, missing-evidence prompts, rule lineage, and summary. It does **not** manufacture target evidence.

Target evidence remains owned by `execute_detector_intelligence()` and raw-condition reconstruction. Admission still requires the decisive family-specific condition:

- function authorization: a lower-privilege or unauthorized context actually succeeds at the protected function;
- mass assignment: a privilege-sensitive property is actually accepted/applied outside the caller's property policy.

A privileged-looking route or writable `role` field remains a hypothesis surface and cannot promote by itself.

## Deliberate exclusions

- BOLA / IDOR is not migrated by this registry because its specialized target reasoning is already physically owned by `bola_intelligence.py`.
- GraphQL authorization remains in the static GraphQL intelligence path and is not part of the raw-alert collector cutover.
- WebSocket authorization remains in static/client intelligence.
- Authentication/session and account-enumeration are a later identity-lifecycle batch rather than function/property authorization.

## Cutover contract

The 6.17 cutover now routes both legacy raw authorization families through `collect_authorization_observations(execution_map)` and the existing `emit()` firewall. The old Function/Role Authorization and Mass Assignment collection blocks are physically removed from `_alert_candidates()`.

The cutover preserves:

1. admission thresholds and family-specific decisive-condition requirements;
2. detector execution and raw-condition reconstruction ownership of target evidence;
3. independent-source guards and hidden-hypothesis behavior;
4. BOLA, GraphQL and static authorization behavior;
5. the existing ranking and impact model.

Surface-only privileged routes and writable privileged fields still remain hidden hypotheses until stored target evidence satisfies the corresponding authorization/property condition.

## Non-goals

- No active requests or payload execution.
- No ranking changes.
- No admission-threshold changes.
- No detector-condition changes.
- No benchmark retuning.
- No fresh accuracy claim until the full collector decomposition is complete and evaluated on a new source-isolated raw holdout.
