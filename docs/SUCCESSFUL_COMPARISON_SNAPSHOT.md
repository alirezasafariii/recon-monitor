# Successful comparison snapshots

Snapshot compatibility schema 3 extends the successful-collection boundary to
every inventory used by Recon's `new` and `changed` decisions:

- assets, DNS records, URLs, and HTTP fingerprints;
- JavaScript files and indicators;
- ports, stored Nuclei findings, and classified endpoints.

Core database schema 18 and the application version remain unchanged. These
tables are mutable working views during collection. A new target run restores
them from the last committed collection. Failed, partial, and interrupted
collection cannot advance that reference. A complete collection may commit even
when Analysis, report generation, or notification delivery fails; the explicit
collection lifecycle is authoritative.

For example, if successful run A sees old JavaScript bytes, failed run B sees new
bytes, and run C sees the same new bytes, C compares against A. Both the raw and
semantic changes, as well as newly observed indicators, remain discoverable.
Failed-only ports and findings are likewise new in the next valid observation.

## Artifact retention and availability

`successful_recon_cas_state` saves the current JavaScript, source-map, and
embedded-source owner bindings for each committed target. Independent
`successful_recon_snapshot` CAS owners pin those digests while a later working
run changes or removes its current owners. Snapshot rows, owner handoff,
reference counts, and baseline promotion share one SQLite transaction and the
CAS retention lock. Backup inventories already include these owner references.
After moving a backup, restored JavaScript paths are derived from the local CAS
metadata instead of old absolute paths.

`successful_recon_js_availability` stores the last committed observation per URL.
It survives runs that do not request that URL and does not depend on aggregate
`run_targets.status='success'`. Failed observations remain in the historical
`js_availability_history` table but cannot become a disappearance/reappearance
reference. Same-run updates are still idempotent.

## Resume and upgrades

Resuming the latest target run keeps its working rows, processed work receipts,
and current artifact owners. It does not restore the previous baseline or
redownload verified completed work. An older run cannot resume after another
run has replaced that target's shared working view; start a fresh scan instead.

Older snapshot schemas stored only four tables. On opening such a database:

1. If the committed collection is still the latest target run and remains
   trustworthy, expand its snapshot from the untouched working inventory and
   pin its artifacts. Availability is recovered only from trusted run history.
2. If a later target run has started, the missing historical JS/port/finding
   versions cannot safely be reconstructed from overwritten mutable rows.
   Invalidate that target's comparison baseline and require one fresh baseline
   scan. Historical run evidence is retained; mutable comparison rows are
   cleared when the fresh run starts. A legacy run that depended on the
   invalidated baseline cannot resume.

The fresh baseline suppresses Recon Change Alerts under the existing baseline
contract. Raw-data Analysis and Potential Finding processing still run. The
upgrade records `recon_snapshot_coverage_migrated` with action `expanded` or
`rebaseline_required` in the audit log. Migration is atomic per target and
reopening an upgraded database does not repeat baseline invalidation.

## Validation

`tests/test_extended_comparison_snapshot.py` exercises real JavaScript stage
processing and the runtime orchestrator, failed/partial/interrupted collection,
same-run resume and restart, inventory rediscovery, CAS garbage collection,
source-map owners, cross-target isolation, backup inclusion and project moves,
availability after report/Analysis failure, rollback injection, and legacy
migration. All fixtures run offline.
