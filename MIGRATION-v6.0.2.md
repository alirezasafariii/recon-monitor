# Recon Monitor 6.0.2

Maintenance release for local Dashboard Origin validation.

## Fix

Safe Validation POST requests now fall back to the actual loopback listening socket when a browser, privacy layer, or local proxy rewrites the `Host` header. The fallback remains restricted to:

- dashboard bound to a loopback address;
- Origin host also loopback;
- exact scheme match;
- exact real listening port;
- valid session CSRF token.

External origins, remote binds, different ports, different schemes, malformed origins, and stale CSRF tokens remain rejected.

Schema remains 15.
