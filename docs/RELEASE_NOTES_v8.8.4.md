# Recon Monitor 8.8.4 — Minimal Dashboard & Complete Search

Application version: **8.8.4**. Core database schema: **18**, unchanged.

- Minimal Command Center preserves complete inventory counts, collection warnings, attention links and specialist controls.
- Complete searchable records, stable pagination, combined filters, full provenance and labeled narrow tables remain available.
- Run review distinguishes timeout/partial collection and retains Katana and JavaScript chain diagnostics.
- Analysis and Quality respect the selected Target. Missing analyst feedback is shown as insufficient feedback; measured zero stays zero. Quality reads do not append snapshots.
- Potential Findings places search below the heading and the ranked candidate inventory before the separate correlation queue. Queue scores are not comparable to candidate Investigation values.
- Full investigation details, native disclosures, themes, density, focus, scroll and polling behavior are retained.
- The isolated real-data review helper verifies copied records/artifacts without modifying the source installation or running collectors.

## Validation and upgrade

The dashboard code passed 1,656 unit tests (one platform skip), seven CI jobs including Linux and macOS Intel/Apple Silicon, and 21 HTTP/native Safari acceptance tests. The user verified the final ordering against their Mac snapshot; all table counts, 1,383 copied files, seven references and all 12 HTTP checks passed.

Use the normal update check/install path after finishing active Runs and stopping the dashboard/API/workers. Existing configuration, policies, artifacts and database records are preserved. No manual schema migration or new target scan is required. ZIP and SHA-256 assets are verified before publication. See MIGRATION-v8.8.4.md for commands.
