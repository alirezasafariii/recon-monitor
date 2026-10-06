# Recon Monitor 8.8.5 — Installed Update Validation

Application version: **8.8.5**. Core database schema: **18**, unchanged.

8.8.4 validated in the source tree and extracted ZIP, but installation by the 8.8.3 updater omitted tools. The dashboard review regression then failed to import dashboard_real_data_review and the update rolled back. This release fixes that installed-layout dependency without skipping post-install validation.

- Move the review implementation to app/dashboard_review_support.py, which legacy updaters install. The source-tree tools entry point delegates to it; the helper also runs directly from app.
- Review, dependency-range, isolated-JS and JS-validation tests import installed app modules instead of depending on tools. Their source-tree CLI entry points remain available.
- Track tools in future updater staging, program backup, replacement and rollback. Older updaters can install this release even when tools is absent.
- Add a fresh-interpreter regression against the legacy copied layout with no tools directory and keep copy/rollback tests covering program tools.
- Preserve the full 8.8.4 dashboard, filters, records and collection behavior. No schema migration, collector run, timeout increase or validation bypass is required.

## Upgrade

Retry the normal update from the rolled-back 8.8.3 installation. ZIP and SHA-256 assets are verified before publication. Existing data/configuration and backups remain in place. See MIGRATION-v8.8.5.md.
