# Scan completion and resume

A run can reach every stage and still have partial collection. The stage and
lifecycle status describe coverage, rather than only whether the process ended.
For example, a rejected JavaScript request can leave collection partial while
analysis and report generation succeed. This does not establish a complete
comparison baseline.

Resume the same run to retain verified work:

```bash
./recon-monitor.sh run --target example.com --resume RUN_ID
```

If the original authorized run used active modules, pass `--allow-active` again
to retain the same runtime authorization gate. Target policy and configuration
authorization still apply.

JavaScript and source-map collection retry recognized transport timeouts,
connection failures and HTTP 408/425/500/502/503/504 responses within the target's
configured retry count. Verified files are reused. Cumulative request and byte
budgets remain in force. Operator Next, scope blocks, exhausted budgets and
shared HTTP cooldowns prevent an automatic retry from overriding those limits.

Resumed file batches select the least-attempted pending URLs first, balancing
hosts within each attempt tier. Repeated failures at the start of the sorted
list therefore cannot starve files that have not been attempted. Failed remote
downloads and failed source-map tasks may be claimed for a new local attempt
on explicit `--resume`. Automatic attempts preserve terminal worker decisions,
and active worker leases remain protected. Verified 404/410 receipts keep their
existing absence validation and reuse behavior.

The CLI and report stage metrics include:

- `collection_attempt` and `collection_attempt_limit`: attempts in this stage invocation.
- `retryable_collection_errors`: recognized transient errors still pending.
- `download_http_status_summary`: statuses of failed JavaScript/map requests.
- `completion_blockers`: reasons collection remains partial.
- `completion_next_action`: guidance for the remaining blocker.

Full per-request evidence remains in `current/javascript-errors.jsonl` and
`current/source-map-work.jsonl` under the run directory. Successful recovery
rebuilds these outputs, removing resolved errors while retaining verified
availability and changes from earlier attempts.

HTTP 400/401/403 responses are not automatically retried unchanged. Review the
failed URL and permitted site access, then explicitly resume after correcting
the cause. HTTP 429 requires waiting for the shared host cooldown. A status code
alone does not establish whether a response came from a bot challenge or an
application error.

Updating the code or importing browser JavaScript does not change an old run to
complete. Collection becomes complete only after the relevant work and upstream
inputs are verified. A persistent rejected request remains partial and cannot
replace the last successful baseline.
