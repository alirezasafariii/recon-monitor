# Migration to Recon Monitor 8.8.18

Application version: **8.8.18**. Database schema: **18**, unchanged; no database migration is required.

Back up the installed program and Run evidence before installing the verified package. The release includes Recon support and the experimental producer source patch, not a replacement Katana binary. Select the separately built and tested checkpoint-capable producer to enable durable continuation. Stock Katana remains supported.

Only saved work within the same Run can be restored. Previous completion counts are not checkpoint data. Changing bound parsing/scope/transport options rejects incompatible state; do not edit checkpoint contents to manufacture completion. A hard kill may leave a lock; verify the producer has stopped before recovering that particular lock.

Request, rate and runtime limits remain unchanged. Real target errors and crawl deadlines can still produce partial results. See `docs/prototypes/KATANA_FRONTIER_CHECKPOINT.md` for supported modes, bounds and acceptance evidence.
