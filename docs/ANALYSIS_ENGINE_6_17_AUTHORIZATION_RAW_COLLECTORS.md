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

## Stage-one contract

The first 6.17 commit establishes and tests the physical authorization collector registry without changing production candidate routing. This gives the cutover a regression-safe equivalence point.

The subsequent cutover must:

1. call `collect_authorization_observations(execution_map)` from `_alert_candidates()`;
2. route both families through the existing `emit()` firewall;
3. remove the legacy Function/Role Authorization and Mass Assignment collector blocks;
4. preserve admission thresholds, ranking, detector conditions, reconstruction, and independent-source guards;
5. prove that near misses remain hidden hypotheses and positive stored-condition fixtures still promote;
6. keep BOLA, GraphQL and static authorization behavior unchanged.

## Non-goals

- No active requests or payload execution.
- No ranking changes.
- No admission-threshold changes.
- No detector-condition changes.
- No benchmark retuning.
- No fresh accuracy claim until the full collector decomposition is complete and evaluated on a new source-isolated raw holdout.
