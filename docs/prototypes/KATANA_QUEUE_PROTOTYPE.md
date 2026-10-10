# Experimental Katana queue lifecycle patch

Status: local prototype only. This is not integrated into Recon Monitor, not
an official ProjectDiscovery release, and must not replace an installed Katana.
The Recon request budget, rate, deadlines and completion guard are unchanged.

## Pinned producer and build

Apply `katana-v1.8.0-tracked-queue.patch` to ProjectDiscovery Katana tag v1.8.0,
commit `35267ac5c8ff1db9694a319d0eb466ed97b0969f` in an isolated checkout.
The comparison used Go 1.26.1 on Linux for BOTH source builds, unchanged go.mod
and go.sum, and `go build -buildvcs=false`. The prototype executable was kept
in /tmp, never installed. No remote target scan was performed.

```bash
git apply --check /path/to/katana-v1.8.0-tracked-queue.patch
git apply /path/to/katana-v1.8.0-tracked-queue.patch
go test -race -count=20 ./pkg/utils/queue
go build -buildvcs=false -o /tmp/katana-queue-prototype ./cmd/katana
```

From the Recon checkout, run the fixed loopback fixtures against each build:

```bash
python3 tools/katana_queue_local_acceptance.py --binary /tmp/katana-queue-prototype --scenario fast
python3 tools/katana_queue_local_acceptance.py --binary /tmp/katana-queue-prototype --scenario slow
python3 tools/katana_queue_local_acceptance.py --binary /tmp/katana-queue-prototype --scenario short-idle
python3 tools/katana_queue_local_acceptance.py --binary /tmp/katana-queue-prototype --scenario deadline
```


## Observed problem and change

The old queue waits for Options.Timeout after the last pop even when all work
is finished. If this idle interval expires while a worker is still reading a
response, the queue can stop before that worker enqueues its child links.

The prototype adds a separate tracked-pop API. Items are counted as active
before delivery. A discarded item releases its reservation; a worker releases
its reservation only after response parsing and child enqueueing. Empty pending
work with active workers waits on a condition variable. Pending=0 and active=0
ends immediately. Context cancellation wakes waiting consumers. The legacy API
remains available; the shared standard crawl loop opts into the tracked API.
No HTTP timeout or crawl-duration setting is reduced or extended.

## Local acceptance

Each fixture binds only 127.0.0.1. The root links to /slow, whose HTML alone
links to /proof; /proof has no children. The slow response delays its headers
by three seconds. The deadline fixture delays by six seconds. Depth=3,
concurrency=1, input parallelism=1, rate=3, retries=0. Each subprocess has an
independent 15-second outer deadline. Output URLs and server-side requested
paths jointly establish whether the delayed link was traversed.

| Build | Delay | -timeout | -ct | Duration | /proof found |
| --- | --- | --- | --- | --- | --- |
| Unpatched source | 0s | 30 | 6s | 6.044s | yes |
| Unpatched source | 3s | 30 | 8s | 8.038s | yes |
| Unpatched source | 3s | 2 | 8s | 4.044s | no |
| Prototype | 3s | 2 | 8s | 3.051s | yes |
| Prototype, deadline | 6s | 30 | 2s | 2.040s | no |

Additional prototype runs with -timeout=30 completed the fast fixture in
0.049s and the delayed fixture in 3.052s, both preserving all three pages.
Both queue strategies, active-parent child preservation, cancellation during
active work, cancellation during blocked delivery and empty queue completion
passed `go test -race -count=20 ./pkg/utils/queue`.

All binaries returned rc=0, INCLUDING the true deadline case. Request error
logs were empty in the original lost-child case. Neither rc=0 nor an empty
error log proves completion. The machine-readable paired results are stored
in `katana-queue-linux-acceptance.json`.

## Important correction and remaining work

The initial assumption that lowering -timeout necessarily cut the HTTP request
was too strong. In the paired source test the worker could finish its delayed
response but its child was lost by premature queue shutdown. Inspection also
shows retryablehttp DefaultOptionsSingle.Timeout (30 seconds) can overwrite
the custom HTTP client timeout in this pinned dependency. This prototype does
not fix or certify that independent HTTP-timeout contract.

This demonstrates queue lifecycle behavior, not production readiness or
exhaustive page coverage. Before any Recon integration, require a versioned,
per-origin completion contract reporting context/deadline termination, request
errors, explicit truncation and quiescent completion; test it against failed
requests, sibling workers, concurrency and skipped/out-of-scope work. The
request-error and deadline cases must remain partial. Missing/malformed
completion evidence must preserve pending state. No duration heuristic should
be relaxed based on this prototype. macOS acceptance and the full upstream
Katana suite remain pending. Headless/hybrid modes are not validated here.

## Experimental completion contract (v1)

The patched standard engine accepts `-recon-completion-log PATH`. Each origin
appends one JSONL event with contract `recon.katana.standard.completion.v1`,
origin, stop_reason, attempted_requests, failed_requests, limited_requests,
pending_items and active_items. Queue exhaustion requires at least one request,
zero failed/limited requests, and zero pending/active work. Reaching a page cap
is conservatively partial, even if no further link was observed. Deadline,
cancellation and request errors cannot certify completion despite rc=0.

`tools/katana_completion_contract.py` is an experimental reader, deliberately
not imported by production stages. It rejects missing, duplicate, unexpected,
malformed, unsupported or inconsistent events and preserves missing siblings
as unknown. An empty error log is never completion evidence. Use
`--completion-contract` with the loopback acceptance script for patched builds.

Linux producer-to-reader acceptance is recorded separately in
`katana-completion-linux-acceptance.json`. Fast and delayed child traversals
reported queue_exhausted; the true deadline reported partial. These establish
bounded standard-engine queue semantics, not exhaustive website coverage.
Request-error and page-limit fixtures also reported partial despite rc=0.
Broader concurrency, upstream suite,
macOS and headless validation remain necessary before production integration.

## Concurrent standard-engine acceptance

`tools/katana_concurrent_local_acceptance.py` starts two independent loopback
origins with concurrency=3, input parallelism=2, rate=3 and a 20-second outer
deadline. The four asserting scenarios are recorded in
`katana-concurrent-linux-acceptance.json`: delayed-parent siblings, one broken
response alongside a healthy origin, explicit out-of-scope links, and duplicate
content across origins. Both healthy queues retain their delayed children; an
origin with a broken response remains partial without contaminating its sibling.
Scope exclusions never reach the local server.

Inspection and the duplicate-content fixture exposed a subtle producer case:
Katana can return an empty navigation response after filtering duplicate content.
The completion producer now reports unknown, rather than a network failure or
queue_exhausted, when such a response cannot be parsed. Errors are counted once
per request even if the response was throttled as well. The consumer remains
fail-closed and unchanged. Duplicate-content results can vary with worker order;
the assertion requires unknown evidence and never assumes which origin wins.

Queue tests additionally exercise 12 concurrent parents and all their children
under both strategies. Artifact tests write 24 different origin events in
parallel and verify complete, non-duplicate JSON records. These tests run with
the race detector for 20 repetitions. The full upstream test command is
`go test -timeout=120s ./...`; browser-dependent skips do not establish headless
or hybrid acceptance. macOS installed-binary acceptance and production
integration are still pending. No Recon stage imports the experimental reader.

```bash
python3 tools/katana_concurrent_local_acceptance.py \
  --binary /tmp/katana-queue-prototype \
  --output /tmp/katana-concurrent-acceptance.json
```


## Origin-scoped exact content deduplication (2026-10-10)

The macOS A/B fixture confirmed that global exact-body dedup could skip relative child links on the second origin. The updated standard engine supplies a fixed-size SHA-256 key containing canonical seed origin and response content to the existing uniqueness filter. HTTP and HTTPS, hosts and nondefault ports are independent; explicit default ports and host case normalize. Same-origin duplicates remain deduplicated. Similarity filtering is unchanged and can still produce unknown. Relative-base differences within one origin and redirected response origins are not certified by this change; the scope follows the crawl seed origin.

The earlier duplicate-content unknown fixture described the previous producer. The current concurrent fixture requires both origins to request /proof and emit queue_exhausted without -duf. Key and same-origin dedup tests pass under race detection for 20 repetitions. Full upstream tests passed with Go 1.26.1 on Linux, as did sibling/error/scope/duplicate loopback scenarios and Recon 8.8.16 healthy/mixed-error/resume component acceptance. Mac acceptance of this updated producer remains pending. Production binaries have not been replaced; this artifact is still experimental.


## Bounded unparsed-response diagnostics

The prototype writes `<completion-log>.diagnostics.jsonl` with contract `recon.katana.standard.diagnostics.v1`, the seed origin, and fixed counters `exact_content_duplicate`, `similarity_filtered`, and `missing_response_reader`. The file contains no response body or request credentials. Concurrent increments are atomic; artifact appends are serialized and synced. Write failures propagate as producer errors. Completion contract v1 fields and conservative unparsed-response semantics remain unchanged: diagnostic counts do not authorize completion.

Operator-provided Mac acceptance for commit b6d174cf477836f4b86ee1df755141b50b91042c passed race tests, six single-origin cases, four concurrent cases (both duplicate-content origins fetched proof), and installed Recon 8.8.16 healthy/mixed-error/resume integration. A real-target resume improved completed origins from 61 to 78 and pending from 27 to 10. Five remaining unknown origins are not certified as fixed. A subsequent helpsurvey default/-duf comparison hit deadlines in both runs and was inconclusive. These observations do not certify this newer diagnostic patch; its Mac acceptance remains pending.

Linux validation for the diagnostic patch: race tests repeated 20 times for queue, completion, origin dedup and diagnostic counters passed; producer build passed; a loopback same-origin duplicate fixture recorded exactly one exact-content duplicate and retained unknown completion. Full clean-upstream patch application checked.



## Parsing-context exact dedup (supersedes origin-only limitation)

Exact-content keys now include the seed origin and response bytes plus the requested document URL, final response URL, request depth and method, response status and response headers. The standard parser uses both document and final-response URLs, so equal bytes alone do not certify equal relative-link destinations. Identical complete contexts remain deduplicated; distinct contexts are parsed independently. This conservative key may accept more responses, including when headers vary. Existing depth, rate, page and runtime bounds still apply; optional similarity filtering is unchanged. Contract v1 and unknown semantics are unchanged.

The operator's Mac diagnostic at commit 5b3201d305e48a1be5d056b9ee86b0483ef2a878 observed helpsurvey unknown with 12 attempts, zero failures, empty frontier, and seven exact_content_duplicate skips. This identifies the current-run skip reason, not the safety of skipping those responses. The newer context patch still requires Mac acceptance.

Linux validation: 20 repeated race tests for parsing-context discrimination, response metadata, queue, completion and diagnostics passed. A real loopback fixture with identical /a/ and /b/ bodies fetched both /a/proof and /b/proof, completed with five attempts and zero unparsed counters. Real Recon 8.8.16 stage integration passed healthy, mixed-error and pending-only resume scenarios. Clean pinned-upstream patch application and producer build passed. Run tools/katana_relative_base_local_acceptance.py --binary PATH to reproduce the relative-base fixture.

