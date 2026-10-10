# Experimental Katana standard-engine producer

This isolated patch targets Katana v1.8.0 commit
`35267ac5c8ff1db9694a319d0eb466ed97b0969f`. It is not an official
ProjectDiscovery release or a distributed system binary. Recon 8.8.16 can
optionally consume its completion contract; stock Katana retains conservative
completion handling. Existing scope, rate, depth, page and runtime limits apply.

## Queue lifecycle and completion

Tracked pops reserve active work before delivery. Workers release reservations
after parsing and child enqueueing. Empty pending work waits while workers are
active, and a quiescent queue closes immediately. Cancellation wakes consumers.
The legacy queue API remains available.

`-recon-completion-log PATH` writes one standard-engine event per seed origin:
contract `recon.katana.standard.completion.v1`, origin, stop_reason,
attempted_requests, failed_requests, limited_requests, pending_items, active_items.
Completion requires attempts > 0, no failed/limited requests, no active/pending
work, no context termination and no unparsed responses. Deadline, request errors,
page limits and missing/unparsed evidence remain partial. rc=0 and an empty error
log never prove completion. Artifact write failures propagate as producer errors.

Completion certifies bounded queue exhaustion, not exhaustive website coverage.
Headless/hybrid modes and the pinned retryablehttp transport timeout behavior are
not certified. Resume creates a new crawl session, not a saved internal frontier.

## Parsing-context exact deduplication

Global exact-body dedup dropped children on a second identical origin. Origin-only
dedup fixed that fixture but still discarded equal bodies at distinct relative
bases inside an origin. The current fixed-size key includes seed origin, body,
requested document URL, final response URL, request depth/method, status and
response headers. The parser uses both document and final-response URLs.
Identical full contexts remain deduplicated; different contexts are parsed.
This conservative key can increase work, including when headers vary. Scope and
collection bounds remain enforced. Optional similarity filtering is unchanged.

## Bounded diagnostics

`PATH.diagnostics.jsonl` contains contract
`recon.katana.standard.diagnostics.v1`, seed origin and fixed counters:
`exact_content_duplicate`, `similarity_filtered`, `missing_response_reader`.
Counters are atomic; artifact appends are serialized and synced. No response body
or credential is included. Diagnostics do not change completion contract v1 or
authorize an unknown response as complete.

## Reproduce in an isolated upstream checkout

```bash
git apply --check /path/to/katana-v1.8.0-tracked-queue.patch
git apply /path/to/katana-v1.8.0-tracked-queue.patch
GOTOOLCHAIN=local go test -race -count=20 \
  ./pkg/engine/standard ./pkg/engine/common ./pkg/utils/queue \
  -run 'Test(ParsingContent|OriginContent|Tracked|ReconCompletion|ReconDiagnostics)'
GOTOOLCHAIN=local go build -buildvcs=false -o /tmp/katana-prototype ./cmd/katana
```

Manual acceptance tools use subprocess.DEVNULL: Katana consumes stdin as seeds
even when -u/-list is supplied, so inheriting bash heredoc input is unsafe.
Standalone shell invocations should use `</dev/null`. The relative-base fixture
reads JSONL row by row, prints raw artifacts and requires exactly one seed event.

```bash
python3 tools/katana_relative_base_local_acceptance.py --binary /tmp/katana-prototype
python3 tools/katana_concurrent_local_acceptance.py \
  --binary /tmp/katana-prototype --output /tmp/concurrent-report.json
python3 tools/katana_stage_local_acceptance.py \
  --binary /tmp/katana-prototype --output /tmp/stage-report.json
```

The standalone experimental reader lives in tools/katana_completion_contract.py;
production uses app/katana_completion.py. Older report artifacts describe producer
versions at their capture time, rather than current producer acceptance.

## Validation and operator acceptance

Linux Go 1.26.1: build, clean pinned-upstream patch application, full upstream
`go test -timeout=120s ./...`, and 20 repeated focused race tests passed.
Browser-dependent skips do not establish browser-engine acceptance. The current
relative-base fixture fetched /a/proof and /b/proof from identical parent bodies,
with five attempts, no unparsed counters and queue_exhausted. Recon 8.8.16
healthy/mixed-error/pending-only resume integration passed.

Operator-provided Mac evidence is recorded in katana-context-macos-acceptance.json.
Producer source patch commit 8e730f1f023f780f1b50970da4f359e36d920843 and stdin-safe
harness commit cd3dcd0b19f1b07c4066902a5316c675851bc2c0 passed Mac race, relative-base
fixture and installed Recon 8.8.16 stage integration. These Mac runs were reported
by the operator, not independently run on the operator's computer.

Latest real-target resume completed 85/88 origins, with no unknown or unparsed
counters in that attempt. Careers request failure and community/giftcards
deadlines remain partial. JavaScript errors remain a separate collection issue.
No exhaustive coverage, release or installed-system-binary claim is made.
