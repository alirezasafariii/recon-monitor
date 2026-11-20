# Browser XSS evidence worker

The `xss-browser` command executes an explicit, target-bound plan in an isolated
Chromium context, then sends its evidence through the existing XSS analyzers and
hypothesis/candidate workflow. Analyst decisions remain unreviewed. The optional
Agent integration runs a frozen plan after Analysis, before investigating cases.
There is no autonomous discovery or submission of browser tests.

## Install and prepare

```bash
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
./recon-monitor.sh xss-browser --help
```

Use `--chromium /path/to/chromium` for an existing Chromium executable, or
`--headed` to see the browser. Playwright is optional and is imported only when
executing browser work. Browser tests skip when it or Chromium is unavailable.
Use a compatible Playwright-installed browser for reproducible results; this
change was accepted with the system Chromium executable on Linux.

The exact configured target must have installation authorization, active modules
enabled and target `active.confirmation` equal to
`I_AM_AUTHORIZED_FOR_ACTIVE_TESTING`. Execution additionally requires
`--allow-active`. These are the same target active gates used by existing tools.
This explicit browser command is a separate execution path; the existing
manual-only Safe Validation contracts are not downgraded.

Prepare a plan based on `examples/xss-browser-plan.json`, replacing target, URLs
and input names with actual scoped application endpoints. Bind it to an existing
Analysis ID for that target:

```bash
# Inert marker collection only; still runs the application's own JavaScript.
./recon-monitor.sh xss-browser --plan my-plan.json --analysis AN-ID --allow-active

# Also attempt callback-only JavaScript execution probes.
./recon-monitor.sh xss-browser --plan my-plan.json --analysis AN-ID \
  --allow-active --verify-execution
```

Only one browser capture runs per configured target at a time.

Results are in `output/xss-browser/XSS-ID/report.json` with file mode 0600 and
capture-directory mode 0700. The command prints that path and exits 0 for a
completed bounded test, 2 for incomplete coverage. `not_demonstrated` is not a
claim that the target is safe. Startup/transport failures retain an incomplete
report. Ctrl-C and Agent stop are cooperative between browser operations and
requests; an in-flight operation can take up to the bounded browser timeout.

## Plan and probe contract

`version` is 1, `target` is an exact policy name, and `tests` is a nonempty list
of unique IDs. There are no execution quotas on test count, workflow steps,
requests, total runtime or response bytes. Legacy `max_requests` and
`max_seconds` plan fields are accepted but ignored. The browser worker does not
apply collector request/download quotas. Manual stop and scope/authorization
checks remain active. The JSON configuration file retains its 1 MiB parser limit;
this does not limit collected responses. Individual connection timeouts (8 s)
and browser-operation timeouts (10 s) detect stalls without limiting total runtime.

Each test may specify ordered `encodings` chains. By default the worker tries
identity, URL, double URL, HTML entities, double entities, Base64, JSON, JS Unicode
and a composed HTML/Base64/URL profile. The same chain is recorded for inert and
execution attempts. These are supported transformations, not claims of exhaustive
encoding coverage. See the matrix for examples.

Each test names `family` (`reflected_xss`, `stored_xss`, `dom_xss`), `url`, and
`input` with `kind` (`query`, `hash`, `form`) and `name`. Query injection replaces
only the named parameter. Hash injection replaces the fragment. Form injection
uses the explicit workflow below. Plan steps do not accept arbitrary JavaScript.

With `--verify-execution`, the worker tries the named callback-only probes
listed in [the coverage matrix](XSS_COVERAGE.md), stopping at the first observed
execution. Restrict a test with, for example, `"probes": ["html", "attribute"]`.
No probe performs credential collection or external callback requests. A unique
per-test marker must reach the worker binding in the target origin. Marker
presence in HTML or a sink event alone never counts as execution.

Browser-only input kinds include `local_storage`, `session_storage`, `window_name`
and `post_message`; they require `dom_xss`. Storage/window values are seeded
before application scripts with a removable CDP init script. They are isolated
to this test context. Their attacker-controllability is not assumed: observations
retain a missing source-control prerequisite and do not emit direct vulnerability
condition evidence. Use disposable keys rather than authentication keys.
`post_message` sends from a sandboxed opaque-origin iframe, not from the receiver
itself. `name: "$"` sends a scalar, otherwise `name` is the object property.

DOM hooks cover the HTML APIs in the matrix, Shadow DOM, srcdoc and event/URL
attribute assignment. Native calls and exceptions are preserved. `eval` and
`Function` are not wrapped. For browser-only sources, a real execution callback
can establish an unattributed execution condition without naming a sink;
`exact_sink_attribution` remains false. Query-only execution is not relabeled
DOM XSS without a corresponding runtime flow. Sandboxed opaque-origin execution
is not counted as execution in the target origin.

`settle_ms` sets an explicit post-workflow observation wait (default 350 ms,
nonnegative with no quota ceiling). Use `wait_for` workflow steps for application
readiness and increase `settle_ms` for delayed rendering. This is an observation
window, not a mission timeout; no finite test proves absence of all later behavior.

## Stored XSS and form flows

Stored tests require `--allow-write`. Explicit steps support `goto`, `fill`,
`click`, `wait_for`; locators use Playwright selectors. `{probe}` expands to the
current inert/execution probe, `{marker}` to its identifier. Use a disposable
controlled record and explicit cleanup steps, for example:

```json
{
  "id": "test-note",
  "family": "stored_xss",
  "url": "https://example.com/test-note/edit",
  "input": {"kind": "form", "name": "text"},
  "probes": ["html"],
  "steps": [
    {"action": "fill", "selector": "textarea[name=text]", "value": "{probe}"},
    {"action": "click", "selector": "button[type=submit]"},
    {"action": "goto", "url": "https://example.com/test-note/view"}
  ],
  "cleanup": [
    {"action": "goto", "url": "https://example.com/test-note/edit"},
    {"action": "fill", "selector": "textarea[name=text]", "value": ""},
    {"action": "click", "selector": "button[type=submit]"}
  ]
}
```

Optional `read_session` supplies a separate read URL, storage-state file and
readiness steps. It is restricted to the same authorized origin and read-only
HTTP operations. It cannot fill the probe into the reader again; cleanup uses
the original writer context. HTML or JSON/fetch responses can provide read evidence
when actual execution is established in that reader. See XSS_COVERAGE.md.

The worker requires a separate observed POST/PUT/PATCH carrying the marker and a marker-free read whose response
contains the marker. Execution must be observed on the final read page; execution
on an immediate write response does not establish stored execution. The worker
never infers persistence from a single echo. Cleanup is attempted in `finally`;
cleanup failure or revoked scope can prevent cleanup and is
recorded explicitly. Missing cleanup is recorded as `not_requested`. Existing
content is not automatically restored; configure appropriate cleanup for your
controlled record. POST form submission remains supported. Explicit `request` steps also support
POST/PUT/PATCH/DELETE JSON workflows with `--allow-write`; non-POST methods must
match the exact method/URL declared in the reviewed plan. Request bodies are not
exported. DELETE is supported for explicit cleanup, not persistence proof. Non-GET 307/308 redirects are stopped rather than replaying writes.

## Authenticated pages

Use a dedicated test session. Playwright's `storage_state` is loaded into the
fresh context; cookies follow normal browser domain/path rules. Create it with:

```bash
umask 077
python -m playwright codegen --save-storage=session.json https://example.com/login
# Log in, then close the codegen browser.
./recon-monitor.sh xss-browser --plan my-plan.json --analysis AN-ID \
  --allow-active --verify-execution --storage-state session.json
```

Keep session files and plans containing login values outside version control.
Each completed test also gets an immutable capture JSON artifact used by hypothesis provenance.
Reports omit request headers, cookies, storage values, response bodies, marker
values and query/fragment values. They include response hashes, status codes,
request IDs, capture IDs, phase names, sink names, browser version and hook hash.
URLs retain their path, which may itself identify a controlled record. Screenshots
and full traces are deliberately not collected because they can contain secrets.
The worker starts its own context; it does not attach to personal browser tabs/CDP.

## Scope and transport

Navigation and writes remain limited to the test's exact scheme/host/port and
current target policy. Optional `resource_origins` permits read-only assets/APIs
from explicitly listed origins already inside that target policy. It cannot grant
new scope, authorize cross-origin navigation/writes or enable WebSockets.
Requests use fresh public-address resolution, reject mixed/private DNS answers,
and connect through the existing pinned HTTP(S) transport, preserving Host/TLS
SNI. HTTP requests are fulfilled into Chromium; proxies, redirects to unapproved
origins, service workers, WebSockets and unapproved write methods are blocked.
Same-origin GET/303 main-frame navigation redirects use an inert intermediate
document and are followed explicitly through the pinned broker. Redirects are
checked at every hop; cycles are stopped without a hop quota. Fetch/XHR and
subframe redirects require an explicit workflow and are reported incomplete
instead of permitting native follow-up requests outside the broker. Captured
responses retain their original HTTP status.

Applications requiring unapproved origins, WebSockets, unsupported content codings,
browser client certificates or unsupported streaming semantics may therefore
produce incomplete results. This is not a general browser sandbox against a
hostile browser exploit; keep Chromium current. Response 401/403/429/5xx on the
main document, blocked resources, and per-operation timeouts remain visible
as incomplete coverage. CSP is preserved; its mere presence is not proof that
execution was blocked. The execution callback is the decisive observation.

## Agent integration

```bash
./recon-monitor.sh agent run --target example.com --run RUN-ID --planner rules \
  --browser-plan my-plan.json --allow-browser-active --verify-browser-execution
# Add --allow-browser-write for forms, --browser-storage-state for a test session,
# and --browser-chromium for a system executable if needed.
```

The plan path and canonical content hash are persisted; credentials are not
copied into mission state. Changing the plan requires a new mission. Browser
results are promoted through the existing candidate workflow, then the Agent's
Investigation Queue can create cases, perform offline validation and draft
reports. Interrupted browser work is marked uncertain and is never replayed
automatically. Incomplete browser results produce `completed_with_gaps`.

## Verification

```bash
python -m unittest discover -s tests -p 'test_xss_browser.py' -v
python -m unittest discover -s tests -p 'test_xss_browser_coverage.py' -v
python -m unittest discover -s tests -p 'test_xss_browser_multistage.py' -v
python -m unittest discover -s tests -p 'test_hunt_browser_integration.py' -v
```

The acceptance tests use a loopback-only HTTP fixture and real Chromium. Only
fixture tests replace public DNS resolution with a pinned loopback address; the
production CLI provides no private-network bypass.

HTTP response codings are decoded before browser fulfillment, with wire and
decoded hashes retained. Text evidence follows BOM, HTTP charset and early HTML
charset declarations. Invalid/unsupported content codings produce incomplete
captures. See PR_203_FINAL_REVIEW.md for the reproduced cases and CI status limits.
