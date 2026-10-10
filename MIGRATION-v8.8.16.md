# Migration to Recon Monitor 8.8.16

Application version: **8.8.16**. Database schema: **18**, unchanged.

Use the normal verified-package updater and keep its data/program backups. No manual SQL migration or historical result repair is required. Existing pending origins remain pending.

The completion feature activates only when the selected Katana binary advertises the exact supported v1 standard-engine marker. Official Katana 1.8.0 is not compatible with that contract; its existing behavior is unchanged. This update does not replace Katana. Keep any experimental producer isolated and validate it separately before selecting it for a production run.

With compatible evidence, successful origins are checkpointed independently and resume retries only unfinished siblings. Missing, malformed or contradictory evidence remains incomplete. Process failures and timeouts override emitted completion. See docs/KATANA_COMPLETION_CONTRACT.md for limits.
