# Recon Final Transport Hardening

This hardening pass closes the highest-value remaining transport gaps in the Recon collection path without changing the authorization model or enabling new active behavior.

## JavaScript and source-map downloads

JavaScript and source-map collection no longer uses a direct `urllib` opener in `stages.py`.

Downloads now use the shared pinned transport boundary:

- the URL must remain inside the target policy;
- DNS is resolved once per hop;
- any non-public resolution fails closed;
- the connection is made directly to the selected validated IP;
- HTTP Host and TLS SNI keep the original hostname;
- environment proxies are disabled;
- response bytes are bounded;
- redirects are limited;
- each redirect is followed only when the next URL remains in scope;
- every accepted redirect hop is resolved and pinned again before connecting.

Request budget accounting runs before every download hop, so an in-scope redirect consumes an additional request instead of bypassing the budget.

Policy headers are treated as credentials regardless of their names. They are sent only by the in-process pinned transport and only to HTTPS URLs. HTTPS-to-HTTP redirects fail closed. Same-origin HTTPS redirects may retain policy headers; cross-origin redirects forward only a small non-sensitive header allowlist. Policy headers are not delegated to `httpx`, Katana, or Nuclei subprocesses, so their independent redirect and DNS behavior cannot expose target credentials.

## Origin liveness

Origin probing still starts with a pinned `HEAD` request.

When HEAD is inconclusive or method-specific (`0`, `405`, or `501`) and the transport did not stop for safety, Recon Monitor performs one bounded pinned `GET` with `Range: bytes=0-0`.

A scope/non-public/rate-limit safety stop never triggers this fallback.

## TLS certificate collection

TLS metadata collection no longer opens a socket to the hostname from `stages.py`.

The shared transport module now:

1. verifies that the HTTPS URL is in scope;
2. resolves and rejects any non-public answer;
3. connects to the pinned IP;
4. keeps the original hostname for TLS SNI and certificate verification.

The fingerprint record retains the pinned transport version/address metadata alongside the certificate-derived fields.

## Katana external crawler envelope

Katana remains an external crawler and therefore does not inherit Python's socket pinning.

This pass narrows its exposure before execution:

- only origins that passed the origin-probe stage are written to Katana input;
- `-cs` restricts traversal to those exact scheme/host/port origins;
- `-p 1` prevents parallel input amplification;
- concurrency is capped;
- retries are disabled;
- response size is bounded;
- crawl duration is bounded;
- rate and duration are computed from a conservative per-origin request envelope;
- the HTTP request budget is reserved **before** launching Katana instead of estimated from output lines afterward.

The plan guarantees that the configured `rate × duration × selected origins` envelope does not exceed the reserved budget. Actual internal crawler behavior remains owned by Katana, so this is a conservative containment mechanism, not DNS pinning.

## Tool compatibility

Katana compatibility checks now require the safety flags used by the collector:

`-jc -rl -cs -ct -mrs -retry -c -p`

An older Katana build that lacks these capabilities is surfaced by `doctor` instead of silently losing the hardening controls.

## Remaining transport caveats

This pass intentionally does not claim that all external tools are DNS-pinned.

Remaining external-process surfaces include ProjectDiscovery `httpx` and Katana themselves. Their inputs and outputs remain scope-filtered and budget/rate constrained, but their internal DNS resolution happens outside the Python pinned transport.

A later hardening pass can decide whether to replace more external probing with the shared transport or add stronger process-level network isolation.
