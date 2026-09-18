# Recon Transport Hardening Final Pass

This pass closes two remaining collection-path weaknesses without changing the authorization model or adding new active behavior.

## 1. Pinned JavaScript / source-map downloads

JavaScript and source-map downloads no longer use a direct `urllib` opener in `stages.py`.

Every request now goes through the shared pinned transport:

- resolve the target hostname once;
- reject any non-global address;
- connect to the validated address directly;
- preserve the original Host header and TLS SNI;
- ignore environment proxy configuration;
- do not auto-follow redirects.

Recon still supports redirects, but the stage follows them explicitly and defensively. Each redirect hop is:

1. resolved independently;
2. scope-checked before the next request;
3. issued through the pinned transport again.

Redirects outside the authorized URL scope are blocked. Redirect chains are bounded to prevent loops.

The previous download-size budget remains fail-closed. Partial oversized content is not treated as a successful JavaScript/source-map download.

## 2. Origin-probe HEAD fallback

The live-origin probe still prefers `HEAD` because it avoids response-body transfer.

Some applications return `405 Method Not Allowed` or `501 Not Implemented` for HEAD even though normal GET requests are available. Those responses previously produced a false negative or misleading origin classification.

For only these two statuses, Recon now performs one fallback request:

- method: `GET`;
- header: `Range: bytes=0-0`;
- maximum response observation: 1024 bytes;
- same pinned transport, public-address validation and scope checks;
- separately charged against the HTTP request budget.

No fallback is performed for out-of-scope redirects.

## Shared transport change

`safe_transport.py` is now version 1.2.0 and accepts a caller-bounded timeout. Existing Safe Validation callers keep the previous default timeout; Recon downloads pass their existing bounded stage timeout explicitly.

## Unchanged safety boundaries

This pass does not:

- enable active Recon;
- weaken target scope checks;
- allow private, loopback, link-local or other non-global addresses;
- follow redirects automatically;
- use environment proxies;
- change Successful Snapshot eligibility;
- change Analysis, Admission, Potential Findings or Validation behavior.

## Remaining external-tool boundary

Katana and httpx are still external processes and therefore do not use the Python pinned socket transport internally. Their inputs remain scope-filtered and rate-limited, and their outputs are filtered again before entering canonical Recon state. Pinning or sandboxing those external processes is a separate hardening problem and is not claimed by this pass.
