# Experimental durable Katana frontier

This proposal extends the pinned standard-engine producer, not the official
ProjectDiscovery binary. Recon Monitor 8.8.18 includes the capability-gated integration.
The producer is a source patch against upstream commit
`35267ac5c8ff1db9694a319d0eb466ed97b0969f` (v1.8.0).

## Concrete behavior

A deadline used to leave only an unfinished origin: the next invocation started
from that origin's seed again. With `-recon-checkpoint-dir`, anonymous standard
GET work is durably registered before dispatch and acknowledged only after its
response is parsed and its children are durably admitted. Restored requests keep
URL, depth and source/tag/attribute provenance. Completed admissions seed URL
uniqueness so previous pages are not crawled again. Failed, cancelled and
unparsed work stays unacknowledged. Completion pending counters include that
persistent work, including requests popped from the queue before cancellation.

Recon uses this mode only after a successful bounded help probe advertises both
completion v1 and the separate durable-frontier marker. It uses one origin per
invocation so the exact-origin scope binding survives changes in the sibling
backlog. The existing shared request reservation, rate, runtime limit and finite
30-second crawl ceiling still apply. The frontier is under the same Run's
`current/katana-frontier/`. Previous URL evidence is preserved. Neither presence
of a file nor a zero exit code certifies completion; the production completion
reader still requires a valid fresh event and successful process lifecycle.

If all requests were acknowledged but completion publication was lost, recovery
rechecks the seed once. It does not report historical state as zero-request
success. Ordinary partial-frontier recovery does not repeat the seed.

## Integrity and bounds

- The contract is `recon.katana.standard.frontier.v1`, bound to the seed and
  parsing, scope and transport options. Invocation duration, rate/concurrency,
  output destinations and lifecycle callbacks are excluded from this binding.
  Every saved request is revalidated against current path/scope and depth.
- GET requests with body, per-request headers/custom fields, credentials,
  automatic forms, known-files crawling, page caps and stateful similarity/query
  filters are unsupported. These fail closed instead of silently dropping work.
- Each origin has at most 50,000 admission records; files are bounded to 64 MiB.
  Required fields, duplicate keys/items, nesting and invalid depths are checked.
- Atomic temporary-file writes, file fsync, rename and directory fsync precede
  admission/acknowledgement. Directories are private, files are mode 0600;
  symlinks and concurrent writers are rejected. Failed writes cannot certify an
  exhausted frontier. Source metadata remains bounded.
- State is trusted local operator data, not a signed remote interchange format.
  Checkpoints retain URLs and source URLs and should be protected like other Run
  evidence. No response bodies, request bodies or credential headers are saved.

A hard process kill may leave an exclusive `.lock` file. Recovery must establish
that the previous producer is stopped before removing that particular stale
lock; automatic PID-based unlocking is intentionally absent. A crash can repeat
unacknowledged work, but acknowledgement ordering prevents losing its children.

## Validation and remaining acceptance

Linux producer race tests repeated 20 times, the existing producer suite, focused
Recon regressions and real loopback stage acceptance have been exercised.
Committed reports describe:

- Direct producer: 2-second attempts decrease persistent pending work 10 → 4 → 0;
  the root is requested once and all 15 leaf pages are fetched.
- Real `stage_urls`/CommandRunner: 78 requests acknowledged on the first bounded
  attempt; 23 requests resumed and completed on the second. All 101 pages are
  represented, root fetched once, and each reservation stays within its envelope.
- Healthy and mixed-error stage scenarios: only the failed page is retried after
  the fixture recovers; a healthy sibling remains completed.

Operator-provided Mac loopback acceptance passed on Go 1.26.5 darwin/amd64
for PR #166 head `5a0109219919f2d06f2836c0b27c148d65bf8cb9`. Producer
race tests repeated 20 times passed; direct pending work decreased 10 → 4 → 0,
and real-stage pending work decreased 23 → 0 with reservations of 90 within
each attempt's envelope of 90. Healthy and mixed-error/resume integration passed.
This Mac evidence comes from the supplied terminal output, not independently
read report files. All eight exact-head CI checks passed before merge.
Live-target frontier acceptance and release publication are separate steps.
The existing batch-27 counts are not a recoverable frontier: the first invocation
of this producer must build its own checkpoint. It cannot reconstruct those
unrecorded 182/113 requests from counts alone.

## Reproduction (loopback only)

Apply `katana-v1.8.0-frontier.patch` to the pinned upstream commit, use Go 1.26.5
with `GOTOOLCHAIN=local`, run producer race tests and build a separate binary.
Run these from this Recon branch, always with stdin detached:

```bash
python3 tools/katana_frontier_local_acceptance.py --binary /path/to/katana-frontier --output /tmp/frontier.json </dev/null
python3 tools/katana_frontier_stage_local_acceptance.py --binary /path/to/katana-frontier --output /tmp/frontier-stage.json </dev/null
python3 tools/katana_stage_local_acceptance.py --binary /path/to/katana-frontier --output /tmp/stage.json </dev/null
```

These tools use disposable state and loopback fixtures. They do not replace the
system binary or modify the production Run. Production installation is a later
step after the recorded acceptance results have been reviewed.
