# Recon Monitor 6.0.4

Maintenance release for Safari Safe Validation form submissions.

## Fixed

Safari on macOS may submit a local Safe Validation form with the literal header `Origin: null` while reporting `Sec-Fetch-Site: same-origin`. Earlier releases rejected that request before the validation plan could be created.

Recon Monitor 6.0.4 accepts this exact narrow case only when all of the following are true:

- the request path belongs to `/validation/`;
- `Sec-Fetch-Site` is exactly `same-origin`;
- proxy headers are not trusted for the request;
- the dashboard listener and browser client are both loopback;
- the submitted Host is loopback and its port matches the real listening socket;
- normal session and CSRF checks still pass when dashboard authentication is enabled.

`Origin: null` remains rejected for `same-site`, `cross-site`, remote clients, remote binds, different ports, non-validation POSTs and proxy-trusted deployments.

The dashboard also suppresses harmless `BrokenPipeError`/connection-reset tracebacks when a browser closes a response early.

Schema remains 15.
