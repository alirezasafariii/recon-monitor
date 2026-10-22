# Migration to Recon Monitor 8.8.19

Application version: **8.8.19**. Core database schema: **18**, unchanged.

Back up the installed program, configuration, database and Run evidence before upgrading. Stop active scans before updating the checkout or running baseline maintenance. Existing `config.env`, target policies and `output/` evidence remain in place; setup does not need to be repeated.

The runtime installs additive baseline-integrity tables, frozen collection-coverage receipts and per-observation JavaScript comparison flags. Their independent metadata key is `recon_baseline_integrity_schema_version`; the core schema stays at 18. No manual SQL conversion is required.

The 8.8.3 updater omits the optional `tools/` directory. Core upgrade validation supports that layout. The full release ZIP contains `tools/`; use the full package layout when you need its pinned Katana installer or developer utilities. Existing source checkouts and newer updater layouts retain their tooling.

## Review historical baselines

The next target run checks its committed comparison baseline before restoring it. You can also review a finished target explicitly, without target requests:

```bash
./recon-monitor.sh platform baseline-repair --target YOUR_TARGET
```

To review the targets from a particular finished Run, use `--run RUN_ID`. The command shares the scan lock and refuses a target that is currently running. Repeating the review is safe.

`baseline_rebuild_required_targets` lists targets that need a new collection-complete reference. Quarantine retains the old snapshot, observations and historical Run outcomes while excluding that snapshot from comparison. It does not manufacture missing collection results. A healthy replacement or verified same-Run recovery can establish the next baseline.

## Resume and diagnostics

Resume a partial Run with its existing ID:

```bash
./recon-monitor.sh run --target YOUR_TARGET --resume RUN_ID
```

Completed work from that Run is retained. Ordinary tool failures allow later collectors to process available inputs, while cumulative budget exhaustion and operator interruption still stop collection. Analysis can succeed on partial evidence; inspect `collection_status`, component reasons and baseline eligibility separately.

To refresh a finished Run's diagnostic projections without collection or Analysis requests:

```bash
./recon-monitor.sh platform finalize --run RUN_ID
./recon-monitor.sh dashboard restart --open
```

Finalization does not promote or repair a comparison baseline. Use `baseline-repair` for the historical review described above. Remote access restrictions and external tool limits may still require further collection before a usable baseline exists. The separately reviewed Analysis issues remain outside this patch release.
