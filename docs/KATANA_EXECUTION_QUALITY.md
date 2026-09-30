# Katana execution and JavaScript input quality

These changes do not increase `timeout_seconds`. Regression scenarios use
1800 seconds and fake tools/transports; they do not scan a target.

## Tool outcomes and Run state

The URL stage preserves output from a timed-out or nonzero-exit Katana batch.
Its `collection_status` is `partial`, and the persisted stage, target lifecycle,
target and Run retain that incomplete outcome. Downstream stages can process
the available evidence. Partial collection cannot establish or refresh a
successful comparison baseline.

Run report stage metrics include:

- `katana_status`, `katana_stop_reason`, `katana_exit_code`, `katana_timed_out`;
- `katana_input_origins`, attempted/completed/pending origin counts;
- `katana_observed` (raw tool output lines, not accepted URLs or HTTP requests);
- `katana_duration_seconds` and `katana_batch_outcomes`.

Each batch outcome contains the exact origin list, start/finish timestamps,
exit code, timeout flag, duration, output line count, stop reason, rate,
per-origin crawl time, process deadline and request reservation. The JSONL
record and completed/pending lists are checkpointed after each finished batch.

Artifacts under a target Run's `current/` directory:

| Artifact | Meaning |
| --- | --- |
| `katana-batches.jsonl` | Per-batch tool evidence, also included in report metrics |
| `katana-batch-NNN-urls.txt` | Raw output of that batch, including partial output |
| `katana-urls.txt` | Combined output from attempted batches |
| `katana-pending-origins.txt` | Unattempted origins and origins in incomplete batches |
| `katana-completed-origins.txt` | Origins whose batch exited normally; no full-site coverage claim |
| `url-collection.json` | Run/target-tagged collector and URL-selection metrics |
| `javascript-selection.jsonl` | Discovered JS candidates, source attribution and selection/drop reason |

`katana_exit_code` is the first nonzero outcome unless a subsequent batch
times out; successful attempted collections record zero. No launched process
means no exit code. Exhaustion of the shared deadline is recorded separately
from a subprocess timeout; it does not invent return code 124.

## Batches and budgets

Invocations are sequential, with at most five exact authorized live origins per
batch. Scope remains restricted by `-cs`; configured credentials are not passed
to Katana. A timed-out batch stays pending while later batches may proceed
within the existing shared deadline and budget. There is no automatic retry.

The collector envelope is bounded by configured rate, timeout, remaining HTTP
budget and URL cap. Each invocation reserves only its own bounded share before
launch, at no more than 120 seconds of its rate allowance. Per-origin `-ct` is
also bounded by the batch's available time. A small run therefore does not
reserve the entire potential 1800-second envelope and unnecessarily starve JS.

`katana_request_accounting=rate_duration_reservation` is explicit: reservations
are conservative rate/time estimates, not measured request counts. Output
lines are never used to refund requests. External-tool rate-limit behavior,
in-flight requests and watchdog termination latency still require controlled
measurement; these offline tests do not prove a hard per-request network cap.

## Diagnosing zero JavaScript output

The pipeline records counts before and after URL selection and `max_js_files`,
download attempts, reused work items, errors, missing files and rejected content
types. `collection_reasons` and `zero_download_reasons` distinguish:

- missing URL input or incomplete upstream collection;
- no JS URLs recognized by the URL-path classifier;
- JS candidates dropped by `max_urls` or `max_js_files`;
- download failures, unexpected content type, or HTTP 404/410;
- already processed work on resume.

The classifier recognizes `.js` and `.mjs` paths, including query strings. It
does not prove that an extensionless URL is not JavaScript. No additional
network probes are introduced to guess MIME types.

Missing/truncated upstream input does not produce empty successful derived JS
snapshots or false removal signals. Unexpected content types leave work items
retryable instead of stuck in `running`. Report quality honors partial tool
outcomes and explicit `no_input`; legacy zero-count records without an input
diagnosis remain `unknown`.

## Offline regression commands

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_katana_*.py' -q
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_javascript*.py' -q
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_collection_quality.py' -q
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_report_failure_lifecycle.py' -q
```

The new execution-quality and lifecycle tests reject subprocess launches, DNS
resolution and socket connections. Timeouts and batch progression are simulated
without waiting. A real-target Run and dashboard/browser validation remain
separate follow-up work.
