# Optional Katana per-origin completion contract

Recon probes installed Katana's local help with a five-second deadline. Only a
successful help result advertising `-recon-completion-log` and the exact v1
standard-engine marker enables the contract. Stock Katana keeps its existing
conservative duration guard; Recon does not install or replace a crawler.

Each invocation uses a freshly emptied, distinct completion artifact. The v1
reader accepts bounded JSONL with exact fields, canonical expected origins,
nonnegative integer counters and consistent queue-exhaustion claims. Missing,
malformed, duplicate, unexpected, oversized or unsupported records fail closed.
A nonzero exit, outer timeout or operator stop overrides every completion event.

For a supported producer, only an explicit queue_exhausted event with attempted
requests, no errors/limits, and zero pending/active items completes that origin.
Such evidence replaces the duration heuristic. A completed sibling leaves the
backlog even when another origin fails or omits its event. Partial URL evidence
is retained. Resume invokes only unfinished origins. Per-origin outcomes and the
artifact name are recorded in katana-batches.jsonl.

The scope, rate, workers, request reservations, internal crawl durations, outer
timeouts and global deadline are unchanged. This contract establishes bounded
standard-engine queue exhaustion, not exhaustive website coverage. Headless and
hybrid crawlers are not enabled by this integration.

## Producer acceptance

The separate experimental upstream patch is tracked in PR #160, commit
06d0cd48a7460b75734500b35fbfab32bc5fc2f2, based on Katana v1.8.0 commit
35267ac5c8ff1db9694a319d0eb466ed97b0969f. It is not part of stock Katana 1.8.0.

Operator-provided terminal output on 2026-10-10 confirms acceptance on macOS
Intel with Go 1.26.5. Race tests passed for 20 repetitions. Six single-origin
fixtures yielded the expected outcomes: fast/slow/short-idle queue exhaustion,
and partial deadline/request-error/page-limit. Four concurrent fixtures passed
with concurrency=3, parallelism=2 and rate=3: healthy siblings, isolated request
failure, excluded path, and duplicate-content unknown. This supplements Linux
acceptance; it does not certify unrelated transport-timeout or browser behavior.

## Recon integration regressions

Offline tests exercise explicit completion despite long duration, unchanged
stock behavior, mixed and missing sibling events, stale and malformed artifacts,
process timeout/failure, operator stop, capability discovery, and partial resume.
No regression test contacts a remote target.

## Manual stage-to-producer acceptance

Run tools/katana_stage_local_acceptance.py with --binary pointing to the isolated
patched Katana and --output pointing to a disposable report. It uses the actual
stage_urls, capability probe and CommandRunner with two loopback servers. The
origin discovery input and database are stubbed; production state is never
opened. Assertions cover healthy completion, a mixed failed/successful batch,
and resume of only the failed origin. This is component integration acceptance,
not a full recon run or remote-target assessment.
