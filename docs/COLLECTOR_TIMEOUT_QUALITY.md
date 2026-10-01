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
```
