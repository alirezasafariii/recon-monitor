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

# Also attempt bounded callback-only JavaScript execution probes.
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

`version` is 1, `target` is an exact policy name, `tests` contains 1–30 unique IDs.
`max_requests` is 1–1000 (default 100) across the complete plan; `max_seconds` is
1–900 (default 120). Policy limits may reduce these budgets. Responses are
limited to 1 MiB each and 16 MiB total or the tighter target download limit.

Each test names `family` (`reflected_xss`, `stored_xss`, `dom_xss`), `url`, and
`input` with `kind` (`query`, `hash`, `form`) and `name`. Query injection replaces
only the named parameter. Hash injection replaces the fragment. Form injection
uses the explicit workflow below. Plan steps do not accept arbitrary JavaScript.

With `--verify-execution`, the worker tries a finite set of callback-only HTML,
attribute, single-quoted JS string, double-quoted JS string and JS expression
probes, stopping at first observed execution. Restrict a test with, for example,
`"probes": ["html", "attribute"]`. No payload performs credential collection or
external callback requests. A unique per-test marker must reach the worker's
browser binding from the current final document. Marker presence in HTML or a
sink event alone never counts as execution.

DOM hooks record `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`
and `document.writeln` before page scripts run. They do not replace `eval` or
`Function`, whose wrapping changes JavaScript scope/semantics. Execution without
a recorded DOM sink is still reported but may require manual attribution before
candidate promotion. These finite probes do not cover every JavaScript grammar,
framework, browser, mutation-XSS or sanitizer bypass. Hooks can affect timing.

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

The worker requires a separate observed POST and marker-free read whose response
contains the marker. Execution must be observed on the final read page; execution
on an immediate write response does not establish stored execution. The worker
never infers persistence from a single echo. Cleanup is attempted in `finally`;
cleanup failure, revoked scope or exhausted budget can prevent cleanup and is
recorded explicitly. Missing cleanup is recorded as `not_requested`. Existing
content is not automatically restored; configure appropriate cleanup for your
controlled record. POST is the supported write method; PUT/PATCH/DELETE are not
sent. Non-GET 307/308 redirects are stopped rather than replaying writes.

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

Each test is limited to its exact scheme/host/port and target policy scope.
Requests use fresh public-address resolution, reject mixed/private DNS answers,
and connect through the existing pinned HTTP(S) transport, preserving Host/TLS
SNI. HTTP requests are fulfilled into Chromium; proxies, redirects to other
origins, service workers, WebSockets and unapproved write methods are blocked.
Same-origin GET/303 navigation redirects are followed explicitly when fulfilled
Chromium responses expose a redirect document. Budgets cover each redirect hop.

Applications requiring cross-origin APIs/CDNs, WebSockets, non-UTF-8 response
semantics, browser client certificates or streamed/large resources may therefore
produce incomplete results. This is not a general browser sandbox against a
hostile browser exploit; keep Chromium current. Response 401/403/429/5xx on the
main document, blocked resources, timeouts and byte/request limits remain visible
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
python -m unittest discover -s tests -p 'test_hunt_browser_integration.py' -v
```

The acceptance tests use a loopback-only HTTP fixture and real Chromium. Only
fixture tests replace public DNS resolution with a pinned loopback address; the
production CLI provides no private-network bypass.
