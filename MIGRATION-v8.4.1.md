# Migration to Recon Monitor 8.4.1

Recon Monitor 8.4.1 is a focused Dashboard startup hotfix. Database schema remains **17**.

## Fixes

- Background Dashboard readiness no longer calls the diagnostic-heavy `/health` page. It waits for the local TCP listener directly, so large migrated databases cannot cause a false startup timeout.
- The startup window is increased from 8 to 20 seconds for slower machines while still failing fast if the child process exits.
- Workspace diagnostics and the Health page now use the current `SCHEMA_VERSION` instead of the stale hardcoded schema 16 expectation.

No Recon, Analysis, Potential Findings, validation, or authorization behavior changes in this hotfix.
