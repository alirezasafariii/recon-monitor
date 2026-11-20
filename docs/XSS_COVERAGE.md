# Browser XSS coverage 1.3

This matrix names supported paths and their real-Chromium acceptance controls.
It is a testable coverage contract, not an assertion of exhaustive XSS detection.
No request, byte, test-count or mission-time quota is added.

| Path | Mechanism | Acceptance control |
| --- | --- | --- |
| Encoded input | identity, URL, double URL, HTML entities, double entities, Base64, JSON, JS Unicode and composed chains | decoding to text-only sinks stays negative |
| Real renderer fixtures | React 18.3.1 and Vue 3.5.13 unsafe HTML versus escaped rendering | real libraries, not simulated framework names |
| Sanitize/decode chain | DOMPurify 3.3.0 followed by unsafe decoding/reinsertion | DOMPurify-only safe rendering remains negative |
| Parse/serialize cycles | multiple template parsing/text extraction stages | final text-only rendering |
| Stored reader context | separate read-only session and HTML or JSON response evidence | writer-only execution does not establish reader execution; reader writes blocked |
| Reflected HTML | callback-only image event | encoded text |
| Quoted/unquoted attribute | explicit HTML/attribute probes | quoted encoded attribute |
| textarea/title/comment/style | context-closing probes | encoded context delimiters |
| JavaScript single/double strings | callback after string boundary | encoded output / text-only use |
| JavaScript template | interpolation probe | escaped interpolation |
| Script raw-text boundary | script-closing probe | CSP / encoded output |
| SVG rendering | callback-only load event | encoded markup |
| javascript URL | named URL probe plus explicit reviewed click | URL placed in a fixed safe path |
| DOM HTML APIs | native setter/method instrumentation | text-only rendering |
| Range fragment / DOMParser | observe marker at fragment/HTML parse input | text-only rendering; parsing alone never confirms |
| Shadow DOM | ShadowRoot innerHTML / guarded setHTMLUnsafe hook | textContent |
| iframe srcdoc | setter and attribute hooks plus origin-bound callback | opaque sandbox execution rejected |
| Event attributes | setAttribute event-handler observation plus execution | ordinary text attribute / textContent |
| eval / Function / string timer | real callback without replacing these APIs | text-only use; exact sink remains unattributed |
| localStorage / sessionStorage | seed a reviewed key before page scripts | textContent; source controllability remains a prerequisite |
| window.name | seed before page scripts | textContent; realistic navigation/source control remains a prerequisite |
| postMessage | separate opaque-origin sender, scalar or keyed object | receiver origin check / textContent |
| CSP / Trusted Types | record actual violation metadata without policy bodies | blocked assignments versus permissive default policy; policy presence alone is not safety |
| Delayed render | explicit readiness step and settle_ms | actual callback required |
| Stored form | marker-bearing POST, separate read, cleanup | marker-free read / separate request requirement |
| Stored JSON API | explicit POST/PUT/PATCH request, separate read; DELETE cleanup | write method/URL must be declared and scoped |
| Fetch/XHR redirect | native URL/responseURL and redirected metadata; HTML/JSON rendering | escaped rendering; CORS enforced by Chromium |
| Redirected same-origin iframe | frame-bound callback and response; nested frames and relative resources | encoded rendering; opaque sandbox execution rejected |
| Redirect sessions | Set-Cookie on each hop; credential-aware cycle detection | secrets excluded from captures; reader remains read-only |
| Every network hop | CDP request-stage interception and pinned transport; local rejecting proxy fallback | private DNS, scope changes, write replay, disabled interception and manual stop |
| Authorized resource origin | explicit resource_origins, same target policy, reads only | unlisted or out-of-scope origin blocked |

Hooks record innerHTML, outerHTML, insertAdjacentHTML, document.write/writeln,
Range.createContextualFragment, HTML DOMParser.parseFromString, ShadowRoot.innerHTML,
iframe.srcdoc, setAttribute, and setHTMLUnsafe when the browser exposes it.
Browser-version-specific APIs such as setHTMLUnsafe are observed only when
present; their mere availability is not acceptance of every semantic variant.

## Browser-only input example

```json
{
  "id": "message-rendering",
  "family": "dom_xss",
  "url": "https://example.com/messages",
  "input": {"kind": "post_message", "name": "html"},
  "probes": ["html", "svg"],
  "settle_ms": 1000
}
```

A storage source uses `local_storage` or `session_storage` and a disposable key
in `name`; window-name uses `window_name`. Execution from these operator-seeded
values is recorded, while missing real-world attacker source control remains
explicit. It is not promoted as a direct XSS condition solely because a tester
can edit browser state.

## Explicit JSON Stored example

```json
{
  "id": "controlled-note",
  "family": "stored_xss",
  "url": "https://example.com/test-note/edit",
  "input": {"kind": "form", "name": "text"},
  "probes": ["html"],
  "steps": [
    {"action": "request", "method": "PUT", "url": "https://example.com/api/test-note", "json": {"text": "{probe}"}},
    {"action": "goto", "url": "https://example.com/test-note/view"}
  ],
  "cleanup": [
    {"action": "request", "method": "DELETE", "url": "https://example.com/api/test-note", "json": {}}
  ]
}
```

This requires `--allow-write` in addition to active gates. Use a disposable
controlled record. A request without the marker is not accepted as its write
provenance. API-specific CSRF and application readiness still need appropriate
reviewed form/session steps; arbitrary JavaScript is not accepted in a plan.

## Limits that remain explicit

Finite probes do not establish the absence of all XSS. Browser-specific parsing,
all mutation/namespace-XSS variants, every sanitizer bypass or framework gadget,
all possible encoded grammars, every storage provenance chain, popup workflows,
WebSockets and exploitability across all CSP/Trusted Types configurations are
not exhaustively covered. setTimeout/function execution is reported without
pretending to know the exact sink if no hook observed it. Styling or parsing a
marker is not execution. Operator-seeded sources retain their prerequisites.

Named source/context/sink pairs are exercised against both executable and secure
controls in tests/test_xss_browser_coverage.py. Native macOS/browser-matrix and
production-application acceptance remain separate from Linux Chromium fixtures.

## Encoding chains and multi-stage Stored reads

The default encoding profiles are the nine named chains in
`xss_browser_encodings.DEFAULT_ENCODINGS`. A plan can explicitly select ordered
chains with `"encodings": [[], ["url", "url"], ["html_entities", "base64", "url"]]`.
Each transformation is applied in order before the normal URL/form/JSON transport
encoding. No encoding-depth or execution quota is imposed. An encoded reflection
alone does not establish XSS: encoded or JSON response evidence requires a bound
real browser callback before direct condition evidence is accepted.

A Stored test can declare an isolated reader:

```json
"read_session": {
  "url": "https://example.com/test-note/view",
  "storage_state": "reader-session.json",
  "steps": [{"action": "wait_for", "selector": "#note-loaded"}]
}
```

Use the normal `--storage-state writer-session.json` for writing. Omitting reader
storage state creates an anonymous reader. The reader cannot issue state-changing
HTTP requests, even when the writer has `--allow-write`; reader steps cannot inject
the marker again. Cleanup runs in the writer context. Execution and response
records are matched to the actual reader page, so execution at the write page is
insufficient. HTML and JSON/fetch read responses can establish persistence when
the same controlled value is really rendered/executed by the reader. Session-state
and input fingerprints are recorded without exporting cookies or payloads. Two
contexts are not automatically proof of two different users; account ownership and
impact remain analyst-reviewed prerequisites.

Framework and sanitizer fixtures are vendored under tests/fixtures/xss_browser_vendor
with licenses, npm tarball integrity and selected-file SHA-256 provenance. They
exercise application rendering mistakes and unsafe processing order. These tests
do not claim a vulnerability in the pinned libraries, nor coverage of every version.

## Native redirect transport

Coverage 1.3 uses Chromium's Fetch protocol request stage for every native
redirect follow-up, including fetch/XHR and iframe requests. It preserves native
URL/base-URL, fragment inheritance, response.redirected/responseURL, cookies and
CORS behavior. Same-origin nested frame callbacks are matched to their own frame
responses; a marker in another frame cannot supply that response evidence.
Opaque sandbox frames cannot establish target execution or target sink events.

Every hop is checked against current scope, public DNS, pinned transport and its
writer/reader role. Non-GET 307/308 and non-POST/non-GET 301/302 redirects are
rejected rather than automatically replaying writes. POST 301/302 and non-HEAD
303 can transition to GET under native browser semantics. No redirect-hop quota
is added; Chromium's own redirect policies still apply. Repeated URL/method and
credential-state fingerprints detect cycles without rejecting a cookie-setting
redirect merely for visiting the same URL again.

Cross-process iframe targets are paused until interception is installed. A
local proxy rejects any request which escapes interception, including IP-literal
requests; page network failures remain incomplete. Browser-internal background
services are also blocked and do not establish application evidence. Popups and
worker-target workflows remain explicitly unsupported. Service workers and
WebSockets remain blocked. Multipart requests whose exact body is unavailable
are rejected rather than reconstructed from incomplete protocol data.

The redirect controls are in tests/test_xss_browser_redirects.py. They include
positive/encoded-safe fetch, JSON, XHR and nested-frame pairs, DOM execution in a
redirected frame, final-base relative assets, session cookies, native CORS,
read-only readers, scope/private DNS, cycles, manual stop, write replay rejection
and a deliberately disabled interceptor behind the rejecting proxy.
