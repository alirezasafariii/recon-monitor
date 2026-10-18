# Collector timeout and partial collection

The Subdomains stage records an outcome for each attempted `subfinder` and
`assetfinder` invocation on each authorized root. A timed-out process,
nonzero exit (including exit code 1), or missing output file makes the stage
`partial`. Other sources and roots can continue. Valid in-scope observations
from incomplete output remain in the asset database and downstream input files;
the raw tool output remains available under `current/raw/`.

Subdomains and DNS use the same attempted-tool outcome contract. A completed
invocation has exit code zero, no timeout or operator interruption, and an
existing output file. An empty output file can represent a completed invocation.
Configured process timeouts are preserved; offline regressions use 1800 seconds.

The URL stage applies the same contract to `waybackurls`. A failed archive
invocation makes URL collection partial even when Katana completes. The URL
metrics record `wayback_available`, `wayback_status`, `wayback_tool_outcomes`,
and collector-specific `collection_reasons`; quality diagnostics distinguish
an incomplete archive from an incomplete Katana crawl.

Each Wayback attempt retains its raw output in
`current/wayback-attempt-NNN-urls.txt`. `current/wayback-urls.txt` combines archive
evidence across a partial-stage resume, and outcomes retain input-host count,
exit code, timeout flag, duration, raw line count, stop reason, and output file.
Resume can retry the archive while reusing a completed Katana crawl's evidence.
A never-attempted unavailable Wayback tool remains optional; unavailability
after a known incomplete archive attempt preserves that unresolved gap.

## Continuing bounded collection

DNS's explicit resolver fallback sends at most 128 additional queries per stage
attempt. A verified positive or SOA-backed negative answer is retained as a
completed `dns-explicit-observations` receipt in the existing work queue. Resume
reuses it only for the same run, target, policy and resolver, after checking the
immutable raw artifact's hash and parsing the matching response again. Missing
or changed proof is queried again. A fresh contradictory/unknown dnsx response
is not replaced by a cached negative. NS records are parsed as validated DNS
names, including multiple nameservers. Failed lookups remain unknown.

The cumulative DNS request budget still applies. Reusing a verified fallback
answer does not charge another explicit query; the normal dnsx collection is
still budgeted on each attempt. Exhausted budgets remain partial and require an
explicit policy change or a fresh scan rather than silently resetting usage.

`max_js_files` bounds unfinished JavaScript parents admitted in one attempt.
Verified completed parents remain in the cumulative evidence without occupying
the next attempt's quota. Resume advances through the remaining files, rechecks
completed CAS receipts and retains earlier change/availability artifacts. The
stage remains partial while unselected parents or download errors remain, so
partial batches cannot establish a comparison baseline.

A parent JavaScript 404/410 is conclusive only with a completed transport,
no transport failure or truncation, and an in-scope final URL. Unverified
absence remains retryable and cannot emit a disappearance observation. Its
completed receipt records the URL, final URL, status and policy hash; resume
checks this receipt against same-run availability history. Legacy receipts
without this proof are rechecked. Both JavaScript not-found outputs are rebuilt
from validated receipts plus new observations, even if earlier output files
were deleted. A policy change invalidates absence receipts.

A verified in-scope source-map 404/410 is a completed absence observation tied
to the exact parent bytes, policy and run. It is recorded in source-map work
metrics and is not downloaded again within that context. A fresh run or policy
change checks it again. Safety stops, incomplete responses, 429, 5xx and other
download failures remain retryable partial work. Confirmed absence releases the
working map/source references and permits an observed removal comparison.

For standard Katana without the completion contract, the internal crawl duration
is explicitly disabled with `-ct 0s`. The existing outer batch timeout and shared
rate/request reservation enforce the finite envelope for the entire process.
A natural zero exit inside that envelope can complete a multi-origin batch;
timeout, operator interruption, abnormal exit or a zero exit at/after the outer
deadline remains incomplete. Custom completion/checkpoint producers retain
their per-origin deadline and must provide validated completion events.

## Subprocess input and shutdown

`CommandRunner` starts supervision before feeding stdin and multiplexes bounded,
nonblocking stdin writes with stdout/stderr reads. Large input cannot prevent
Timeout, operator Next, or cancellation, and a tool can emit output before it
consumes all input. Existing encoding, newline conversion, line callbacks, and
EOF behavior are preserved; an early stdin close returns the tool's exit result.

The configured deadline covers open pipes even after the parent process exits.
Shutdown signals the process group, drains output for a bounded interval, then
force-kills remaining group members. An inherited pipe outside the group cannot
extend cleanup indefinitely. Collected output is retained, including an EOF tail
without a newline; a truncated final character during interruption is replaced.
Pipes, output handles, and runner state are cleaned up on startup and callback
failures as well as Timeout/Next. Configured timeout values are unchanged.

## Persisted collector results

The Run report and persisted stage metrics include `collection_status`,
`collection_reasons`, and `subdomain_tool_outcomes`. Each subdomain outcome has:

| Field | Meaning |
| --- | --- |
| `tool`, `root` | Collector and authorized root for that invocation |
| `input_hosts` | One input root for passive subdomain tools; host count for DNS |
| `exit_code`, `timed_out` | Actual process result and timeout flag |
| `duration_seconds` | Process duration |
| `lines` | Raw output line count, including diagnostic or rejected lines |
| `stop_reason` | `completed`, `timeout`, `nonzero_exit`, `output_missing`, or `operator_next` |

Downstream stages can use partial evidence. The stage, target, Run, and target
lifecycle retain the incomplete collection status. Partial collection cannot
create or replace a successful comparison baseline.

On resume, the active lifecycle runner reruns an incomplete collector and every
later stage for that target, so newly collected inputs reach DNS, URLs,
JavaScript, fingerprints, and Analysis. Earlier successful collectors and
successful collectors on other targets retain their resume skip behavior.

The offline regressions guard subprocess launches, DNS resolution, and socket
connections. They cover partial output and scope filtering, other successful
sources, empty output, abnormal exits, Run/report/baseline persistence, resume
dependency refresh, and target isolation:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_subdomain_collection_quality.py' -q
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_collection_resume_repairs.py' -q
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_wayback_collection_quality.py' -q
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_command_runner_stdin.py' -q
```

The Katana frontier workflow builds and exercises the pinned upstream commit
before applying the project's producer patch. Run the same unpatched acceptance
with `python tools/katana_stage_local_acceptance.py --stock-only --binary PATH
--output REPORT.json`. This mode rejects binaries advertising the custom
completion contract and tests ordinary capability detection without a mock.
