# Stability and Operator UX — v7

- Structured Error IDs persist safe diagnostics with recursive secret redaction.
- Dashboard POST failures distinguish origin and CSRF failures.
- Safari loopback compatibility accepts literal `Origin: null` only for `Sec-Fetch-Site: same-origin`, exact loopback Host/listener port, loopback client/server and non-proxy-trusted deployments.
- Browser disconnects (`BrokenPipeError`, reset/aborted connections) do not emit misleading server tracebacks during response writes.
- Startup performs a local-only operator self-check.
- `/diagnostics` shows database/schema/files/run state/browser support and recent Error IDs.
- Safe repair defaults to preview and only targets stale execution state and expired session files.
