# Safari `Origin: null` Safe Validation fix

Recon Monitor 6.0.4 addresses a Safari behavior observed on macOS where a local HTML form POST is sent with:

```text
Origin: null
Sec-Fetch-Site: same-origin
Host: 127.0.0.1:<dashboard-port>
```

The exception is intentionally restricted to Safe Validation routes. It is accepted only when the client and actual dashboard listener are loopback, the Host is loopback on the real listening port, proxy-header trust is disabled, and Fetch Metadata explicitly reports `same-origin`.

This does not turn off Origin validation. The following remain rejected:

- `Origin: null` with `same-site`, `cross-site` or missing Fetch Metadata;
- requests to non-validation POST routes;
- remote browser clients or non-loopback dashboard binds;
- a Host port different from the actual dashboard port;
- trusted reverse-proxy mode;
- invalid session or CSRF values when session authentication is enabled.

Browser disconnects during page rendering are also treated as normal client disconnects and no longer generate repeated `BrokenPipeError` tracebacks.
