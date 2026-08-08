# Recon Monitor 6.0.3

Maintenance release for Safari Safe Validation form submissions.

## Fix

Safari may submit a local form without `Origin` and without `Referer`, while reporting `Sec-Fetch-Site: same-site`. Recon Monitor now accepts that narrow case only when:

- the dashboard listening socket is loopback;
- the connected browser client is loopback;
- `Sec-Fetch-Site` is not `cross-site`;
- the session cookie is valid and SameSite=Strict;
- the per-session CSRF token is present and valid.

Explicit remote origins, remote clients, remote binds, different ports, malformed origins and invalid CSRF tokens remain blocked. Schema remains 15.
