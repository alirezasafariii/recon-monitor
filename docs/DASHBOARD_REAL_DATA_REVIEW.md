# Local dashboard review with real data

Use the feature branch in a separate code checkout. This is an acceptance review
before merging/releasing the dashboard, not an update of the installed program.
Python 3.10+ and the existing authenticated GitHub CLI are sufficient.

```bash
gh repo clone alirezasafariii/recon-monitor "$REVIEW_CODE_DIR" -- --branch feat/dashboard-minimal-preserve-20261004 --single-branch
cd "$REVIEW_CODE_DIR"
python3 tools/dashboard_real_data_review.py --source /Users/alireza/recon-monitor --port 8788 --open
```

Choose a new empty directory for `REVIEW_CODE_DIR` and pin the tested commit before
running the helper. Keep the terminal open. The helper prints a random Viewer
username/password and the snapshot directory. The review uses a separate cookie
name, so login/logout does not replace the installed dashboard's browser session
even when both ports use the same hostname. `Ctrl+C` stops only this foreground
review server. The installed dashboard on port 8787 can remain running. If 8788 is
occupied, select another unused port with `--port`.

## What is copied and verified

- A consistent SQLite snapshot made with `Connection.backup()` from a source
  connection opened using `mode=ro`. The installed database is never opened through
  the application's migration class.
- All database tables and rows, including Run/Analysis/source identifiers, stored
  collection outcomes, tags, baselines and investigation records. Table counts are
  compared before and after preparation. Schema 18, `quick_check` and foreign keys
  must pass. No migration is attempted on an older installed schema.
- The target policy, available `output/` and `reports/` directories, and the
  `state/blobs/` and `state/objects/` stores. Referenced JS/CAS/evidence artifacts
  must exist and match their hashes in the snapshot. Absolute JS, evidence,
  screenshot, diff and Run-directory paths inside these managed trees are rebased
  to the copy. Unreferenced files in these trees are copied too.
- Symlinks and non-regular files are rejected rather than followed. Missing,
  changed or unsafe referenced artifacts stop preparation; no incomplete review
  directory is left behind. Existing/overlapping destinations are never replaced.

SQLite provides the consistent database snapshot. Files are copied separately;
referenced artifact hashes are verified again after copying. This is not a live
mirror, and later changes in the installation will not appear in the review.

The private snapshot directory has mode 0700; its database and copied files have
mode 0600. A new safe configuration is written. Source configuration, secrets,
session files, PID/lock files, workers, LaunchAgents, logs, backups and plugins are
not copied. Original user records remain in the copied database but are disabled;
API tokens are revoked in the copy. One fresh Viewer is added after count parity
is verified. These copy-only credential changes and the Viewer audit record are
outside the parity comparison and do not change the installed credentials.

The review binds to `127.0.0.1`. Only login POSTs are accepted; every operational
POST is blocked independently of role/CSRF. Python remote connections and DNS
lookups are blocked while serving the review. No collector, scan, worker or
notification sender is started. The normal app's CSP remains in force. Every
rendered page labels this as a snapshot; stored Running states describe the
copied instant, not an active process in the review.

## Automatic checks and report

The actual dashboard handlers are exercised over HTTP after Viewer login. Home,
Recon, Runs, Analysis, a combined Query/Target/Run/type search and the latest Run
review (when available) are each requested twice. The selected URL-search count
is checked against an independent SQL count, including literal `%` and `_` in
URLs. An empty URL inventory must produce an empty result rather than a failure.
HTTP statuses, first/repeat response times and checks are saved to
`review-report.json` in the snapshot directory. No threshold declares a page
"fast"; timings are observations for the operator's actual data and machine.

`all_table_counts_preserved` must be true. `http_checks_passed` must be true before
accepting the basic real-data rendering. A failed HTTP check remains in the report
and logs; the server stays available for investigating the failing page.

For preparation and HTTP checks without keeping the browser/server open:

```bash
python3 tools/dashboard_real_data_review.py --source /Users/alireza/recon-monitor --port 8788 --prepare-only
```

## Manual Safari acceptance

1. Compare Home and Recon counts with the installed dashboard using the same
   Target/Analysis. Check All targets and one populated target. The review is a
   snapshot, so compare at the captured time rather than during a new Run.
2. Search a known URL, endpoint, JS indicator or finding. Combine Query, Target,
   record type, full Source run and date filters. Try a second results page and
   stored details; returning must keep every filter.
3. Open a real partial/timeout Run. Verify input/output counts, stop reason,
   durations and IDs against Full metrics. Inspect a zero-JS stage's recorded
   reason. Unavailable historical fields must remain unknown.
4. Test light/dark, normal/compact, browser Back/Forward and a narrower window.
   Submit a filter after scrolling. Read long Run/Analysis IDs and confirm no
   information or controls disappear in the narrow layout.
5. Record slow pages, status failures and visible mismatches. Share the short
   console summary and relevant timings/error IDs; the full real database does
   not need to be uploaded.

The snapshot does not run a live collector. Native live-progress polling,
selection/focus and operational controls are covered by the isolated Safari CI
fixture; this local review measures real-data rendering, search and layout.
Successful synthetic CI alone does not certify this laptop's data or performance.
