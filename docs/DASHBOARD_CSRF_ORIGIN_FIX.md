# Dashboard Origin and CSRF validation

Recon Monitor 6.0.1 keeps same-origin and CSRF protections enabled while fixing local-address compatibility.

## Server-rendered CSRF

Every authenticated `POST` form receives a hidden CSRF field before the HTML response is sent. JavaScript injection remains only as a fallback for dynamically created forms. This prevents a form from being submitted before JavaScript has attached the token.

## Loopback equivalence

These names are treated as the same local machine when the scheme and port match:

- `localhost`
- `127.0.0.0/8` loopback addresses
- `::1`

For example, an Origin of `http://localhost:8787` is accepted when the Host is `127.0.0.1:8787`. A different port or scheme is rejected.

## Still rejected

- External origins
- `Origin: null`
- Malformed Origin headers
- Cross-origin posts without explicit allowlisting
- Missing, stale, or incorrect CSRF tokens
- Untrusted forwarded headers

## Reverse proxy

`DASHBOARD_TRUST_PROXY_HEADERS` is disabled by default. When explicitly enabled, the first `X-Forwarded-Host` and `X-Forwarded-Proto` values are used. `DASHBOARD_ALLOWED_ORIGINS` accepts a comma-separated list of exact origins and never supports wildcards.
