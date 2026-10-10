# Migration to Recon Monitor 8.8.17

Application version: **8.8.17**. Database schema: **18**, unchanged.

Use the verified-package updater and retain its data/program backups. No manual SQL migration is required. Existing collected URLs and pending origins are preserved.

Resume now allocates time and admission capacity only to unfinished live origins. It still starts a new crawl session and does not restore Katana's internal frontier. Scope, rate and cumulative request/runtime limits remain active; large or failing origins can remain partial. This update does not replace the installed Katana binary.

After installation, run doctor and the loopback stage acceptance with the already tested isolated producer before resuming the production run. Installed macOS acceptance is pending; do not interpret offline or CI tests as a live-target completion claim.
