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
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_wayback_collection_quality.py' -q
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_command_runner_stdin.py' -q
```
