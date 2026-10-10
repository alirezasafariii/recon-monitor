# Recon Monitor 8.8.18 — Durable Katana Frontier Continuation

Application version: **8.8.18**. Database schema: **18**, unchanged.

Bounded resumes can restore unfinished anonymous GET work instead of starting every origin from its seed. This requires the experimental producer built from the pinned upstream source patch in `docs/prototypes/katana-v1.8.0-frontier.patch`; no binary is bundled. Stock Katana and older completion-only producers retain their existing behavior.

Work is durably admitted before dispatch and acknowledged after parsing and child admission. URL depth and source provenance survive continuation. Per-origin invocation scopes are stable, and existing request/rate/runtime ceilings and fresh completion checks remain enforced.

Linux and operator-provided macOS acceptance passed: direct pending work decreased 10 to 4 to 0; real-stage pending work decreased 23 to 0 on the next bounded attempt, without repeating the root. Producer race tests repeated 20 times passed. All eight checks on PR #166's exact head passed before merge.

Existing counts cannot reconstruct an old frontier. The first checkpoint-capable invocation creates it. Failed requests remain partial; this does not repair the remote careers HTTP connection reset or guarantee live-target completion. Unsupported authenticated/form/stateful-filter modes and corrupt or incompatible checkpoints fail closed. After a hard kill, verify the producer is stopped before recovering its exclusive lock.

Same-Run continuation stores private checkpoint files under `current/katana-frontier/`. See `docs/prototypes/KATANA_FRONTIER_CHECKPOINT.md`. Publication remains gated on exact-main CI, manifest/archive verification and actual legacy updater installs.
