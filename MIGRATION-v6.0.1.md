# Migration to Recon Monitor 6.0.1

## Purpose

This maintenance release fixes `Origin or CSRF validation failed` errors when using Safe Validation from a local dashboard session.

## What changed

- CSRF fields are rendered directly into POST forms by the server.
- `localhost`, `127.0.0.1`, and `::1` are accepted as equivalent local loopback names only on the same scheme and port.
- External origins, null origins, different ports, and invalid CSRF tokens remain blocked.
- Error pages now distinguish an Origin mismatch from an expired or missing CSRF token.

## Schema

Schema remains **15**. No data migration is performed.

## Optional reverse proxy configuration

Local installations need no configuration change. Reverse-proxy deployments may explicitly set:

```env
DASHBOARD_TRUST_PROXY_HEADERS="yes"
DASHBOARD_ALLOWED_ORIGINS="https://recon.example.test"
```

Only enable trusted proxy headers when the dashboard is behind a proxy you control. Never use a wildcard origin.

## After upgrading

Restart the dashboard, reload the page, and sign in again if an old browser tab still contains a stale CSRF token.
