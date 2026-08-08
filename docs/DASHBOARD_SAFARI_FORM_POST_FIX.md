# Safari Local Form POST Compatibility

Recon Monitor 6.0.4 fixes Safe Validation plan creation when Safari omits the `Origin` and `Referer` headers for a local form POST and sends `Sec-Fetch-Site: same-site`.

The compatibility path is intentionally narrow. It is enabled only when the actual dashboard listener and the connecting client are both loopback addresses. A valid session and per-session CSRF token remain mandatory. Requests marked `cross-site`, remote callers, remote binds, malformed explicit origins, different ports and stale CSRF tokens remain rejected.

The dashboard log now records sanitized Origin diagnostics (`Origin`, `Host`, `Sec-Fetch-Site`, Referer origin, client endpoint and server endpoint) without recording cookies, passwords, authorization values or CSRF tokens.
