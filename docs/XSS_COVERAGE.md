# Browser XSS coverage 1.1

This matrix names supported paths and their real-Chromium acceptance controls.
It is a testable coverage contract, not an assertion of exhaustive XSS detection.
No request, byte, test-count or mission-time quota is added.

| Path | Mechanism | Acceptance control |
| --- | --- | --- |
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
mutation-XSS, complete sanitizer-bypass coverage, every framework gadget,
all encoded/nested grammars, every storage provenance chain, popup workflows,
WebSockets and exploitability across all CSP/Trusted Types configurations are
not exhaustively covered. setTimeout/function execution is reported without
pretending to know the exact sink if no hook observed it. Styling or parsing a
marker is not execution. Operator-seeded sources retain their prerequisites.

Named source/context/sink pairs are exercised against both executable and secure
controls in tests/test_xss_browser_coverage.py. Native macOS/browser-matrix and
production-application acceptance remain separate from Linux Chromium fixtures.
