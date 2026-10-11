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
  Every saved request is revalidated against scope and depth at load. The bound
  path filter is applied again by the worker; filtered pending admissions are
  acknowledged without HTTP, and filtered acknowledged history is retained.
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

## Filtered-admission recovery fix

A community origin checkpoint could contain default-filtered image/font URLs
that Enqueue had durably admitted before Do applied its path filter. Reloading
that history with ValidatePath rejected the entire checkpoint, including already
acknowledged records. Restore now retains those in-scope, valid-depth records
and Do applies the unchanged bound path policy before any HTTP request. Scope,
depth, metadata, binding, integrity and locking checks remain enforced.

The new regression covers both pending and acknowledged filtered admissions;
an unfinished allowed page remains resumable and the seed is not repeated.
Race tests repeated 20 times passed. The loopback CLI acceptance tool
`tools/katana_filtered_frontier_local_acceptance.py` checks fresh completion
and that neither PNG nor WOFF2 is fetched during resume. Mac acceptance of
this updated producer patch remains pending. Existing checkpoints need no edits.


## Discovery provenance

When a completion-log path is configured, parser discoveries with raw reference
metadata are appended to `<completion-log>.provenance.jsonl`. Records contain
`raw_reference`, `source`, resolved `url`, `tag`, `attribute`, and `depth` under
contract `recon.katana.discovery.provenance.v1`. Recording precedes scope and
uniqueness filtering, so an external reference can be inspected without fetching
it. This is discovery evidence, never completion or HTTP success evidence.
Headers and response bodies are excluded. Records larger than 16 KiB and data
beyond 8 MiB per log are omitted; the log is not a complete crawl inventory.
References restored from older checkpoints may lack raw metadata. Historical
plain-text URL files cannot recover the original reference retroactively.

`tools/katana_provenance_local_acceptance.py` tests relative, root-relative, and
external scheme-relative script references on loopback. Updated macOS acceptance
is pending; the installed filtered-checkpoint binary is unchanged.


## Event metadata extraction

The regex JavaScript parser now masks literal values of object properties named
`event` before endpoint extraction. The observed GTM snippet uses
`event: 'gtm.js'` as metadata, while `j.src` specifies the external script URL.
Quoted property names and comments between tokens are supported. Real relative
references in `src`, `fetch`, or other URL fields remain candidates, including
the same filename elsewhere in the same script. CSS keeps the original extractor.
This is a narrow lexical correction, not evaluation of arbitrary JavaScript;
dynamic concatenation and other metadata fields remain heuristic candidates.

The loopback acceptance fixture serves GTM metadata under `/metadata/` and a
real relative reference under `/real/`. It must fetch only the valid script and
retain the external GTM discovery without making an external request. The event metadata fix passed macOS acceptance.


## Executable inline script isolation

On supported structured-parser platforms (macOS and non-386 Linux), the HTML
body regex no longer scans executable inline script text. Dedicated script regex
parsers still scan that text; a bounded AST pass additionally recovers literal
DOM `.src` and `.href` assignments, including dotted filenames and relative
folders that look like domains. The AST pass is limited to 512 KiB per script.
HTML attributes and non-executable JSON script blocks retain body extraction.
Standalone JavaScript responses and CSS retain their existing body behavior.
Windows and 386 retain the legacy path because their build excludes jsluice.

This prevents the New Relic `agent:"js-agent.newrelic.com/nr-spa-1208.min.js"`
configuration from becoming a local `/Edge/` path through the HTML body regex.
It does not infer aliases, evaluate `"https://"+t.agent`, or manufacture an
external URL. Candidates found only by the broad HTML regex inside executable
script text can disappear; literal DOM assignments and existing dedicated
script-regex candidates remain. Existing saved artifacts are not rewritten.

Linux parser/utils race tests (20 repetitions), New Relic loopback crawl,
GTM event acceptance, provenance, filtered checkpoint recovery and stage resume
passed. macOS acceptance and installed-binary comparison for the isolation change passed. See issue #171.


## Browserify-shaped resolved dependencies

For JavaScript up to 2 MiB on structured-parser platforms, an AST pass masks
literal `require` arguments and dependency-map keys only when the corresponding
numeric module exists in the same object table. Entries must have the standard
`[function(require,...), dependencyMap]` shape. Unknown targets, arbitrary require
calls, shadowed/replaced require bindings, duplicate keys and malformed
syntax are preserved rather than assumed internal. Source offsets are unchanged.
Actual src/fetch references elsewhere to the same path are preserved. The mask
is applied to dedicated script regex extraction and standalone JS body scraping;
CSS and legacy Windows/386 paths are unchanged. This is not evaluation of bundle
bootstrap code, and nonstandard bundlers or require aliases are unsupported.
The AST bound is explicit: larger files keep legacy extraction.

The observed signup bundle maps `./address-suggestions.js` to internal module 1.
This proves that occurrence is a bundle dependency, not a standalone-file URL;
it does not explain every HTTP 400 or establish the origin of es.array.at.
Linux parser/utils and producer race regressions (20 repetitions), bundle
loopback crawl, script isolation, GTM, provenance, filtered frontier and stage
resume passed. The first Tree-sitter implementation passed macOS loopback tests
but FAILED on the SHA-verified, 227673-byte saved signup bundle: parsing stopped
at byte 161325 with no_stacks_alive, and increasing GLR retention did not help.
The revised pass uses Goja's parser pinned at 913bd86fb70c, with source-map
loading disabled. It does not execute JavaScript or load external files. Inherited
require calls inside nested closures are handled; any nested require shadow,
reassignment, eval, or with conservatively preserves the module.
The exact uploaded saved bundle (SHA256
4250d60f5761e6397b677844fda9028f708b0ed17066a1930c9698b50d6e0c80)
now returns source_masked=true and empty targeted after_body/after_script arrays
on Linux. A loopback crawl serving that exact bundle also completes without
requesting address-suggestions.js or core-js/modules paths. Other legacy regex
candidates remain; this is not a claim that every JavaScript error is fixed.
New nested-closure and shadowing regressions pass. The operator validated this revision on macOS and installed the matching binary.
`tools/katana_bundle_saved_probe.go` reads a SHA-verified local bundle without
network requests or database mutations and reports targeted before/after candidates.

### HTML document base resolution

Relative HTML references now resolve against the first base element with an href,
resolved against the final response URL. Missing, malformed, or non-HTTP(S) bases
fall back to the response URL. Header references and base elements themselves
retain response URL resolution; provenance keeps the original source and raw reference.
Existing crawl scope checks still decide whether an external resolved URL may be requested.

Linux validation: race tests repeated 20 times, existing parser tests, pinned patch
apply check, and loopback HTML base plus distinct-page-relative-base acceptance passed.
The /Edge/ fixture with base href / requests /main.js and /polyfills.js, never
/Edge/main.js or /Edge/polyfills.js. macOS validation remains pending for this change.
This does not resolve remote 429 responses or retroactively change stored run artifacts.

### JavaScript regex literal isolation

Bounded Goja AST analysis replaces regex literals with numeric placeholders before
URL heuristics and bundle analysis. Byte offsets and line breaks remain intact,
string paths remain intact, and parsing does not execute code or load source maps.
Malformed and over-2-MiB scripts retain the existing fallback. Windows/386 retain
the existing legacy behavior. Linux race tests repeated 20 times for utilities
and parser, plus local regex literal crawl acceptance passed. macOS and the real
account-analytics saved bundle remain to be validated. Existing checkpoints are unchanged.


### Redirect scope enforcement

The standard crawl HTTP client now validates each redirect destination against
the session crawl scope and path policy before making the next request. Blocked
redirects return the original HTTP response without requesting the destination.
In-scope redirects continue to work. Discovery of an external URL in output is
not evidence that it was requested. This change does not rewrite checkpoints or
mark network failures complete. Existing checkpoints keep their semantic binding.

A two-server loopback acceptance fixture asserts zero requests to the external
server, successful in-scope redirection, and durable frontier exhaustion.
