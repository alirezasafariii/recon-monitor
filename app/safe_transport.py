from __future__ import annotations

"""Pinned transport for bounded Safe Validation requests.

The transport resolves the target once, rejects any non-public address, and
connects directly to one validated address while preserving the original HTTP
Host header and TLS SNI hostname. Environment proxies are disabled. This closes
the DNS-rebinding / time-of-check-time-of-use gap that exists when a hostname is
validated and then independently resolved again by the HTTP client.
"""

import http.client
import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

SAFE_TRANSPORT_VERSION = "1.0.0"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def resolve_public_addresses(host: str, port: int | None = None) -> tuple[bool, list[str]]:
    """Resolve once and fail closed if any result is non-public."""
    addresses: list[str] = []
    try:
        rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False, []

    for row in rows:
        address = str(row[4][0])
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        return False, []

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False, addresses
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False, addresses
    return True, addresses


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, pinned_ip: str, **kwargs: Any) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = self._create_connection(
            (self._pinned_ip, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, pinned_ip: str, **kwargs: Any) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = self._create_connection(
            (self._pinned_ip, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.host
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=server_hostname,
        )


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pinned_ip: str) -> None:
        super().__init__()
        self._pinned_ip = pinned_ip

    def http_open(self, req: urllib.request.Request) -> Any:
        pinned_ip = self._pinned_ip

        def factory(host: str, **kwargs: Any) -> _PinnedHTTPConnection:
            return _PinnedHTTPConnection(host, pinned_ip, **kwargs)

        return self.do_open(factory, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_ip: str) -> None:
        super().__init__()
        self._pinned_ip = pinned_ip

    def https_open(self, req: urllib.request.Request) -> Any:
        pinned_ip = self._pinned_ip

        def factory(host: str, **kwargs: Any) -> _PinnedHTTPSConnection:
            return _PinnedHTTPSConnection(host, pinned_ip, **kwargs)

        return self.do_open(factory, req, context=self._context)


def build_pinned_opener(pinned_ip: str) -> urllib.request.OpenerDirector:
    """Build a direct-only opener that cannot re-resolve the target hostname."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        _PinnedHTTPHandler(pinned_ip),
        _PinnedHTTPSHandler(pinned_ip),
    )


def _annotate_resolution(
    item: dict[str, Any],
    addresses: list[str],
    pinned_ip: str,
) -> dict[str, Any]:
    item["resolved_addresses"] = list(addresses)
    item["pinned_address"] = pinned_ip
    item["dns_rebinding_protection"] = "resolution_pinned"
    item["environment_proxy_used"] = False
    item["safe_transport_version"] = SAFE_TRANSPORT_VERSION
    return item


def perform_pinned_request(
    item: dict[str, Any],
    policy: Any,
    *,
    safe_methods: set[str],
    url_safety: Callable[[str, Any], tuple[bool, str]],
    observation: Callable[[str, str, int, Any, bytes, str], dict[str, Any]],
    max_response_bytes: int,
    validation_version: str,
) -> tuple[dict[str, Any], str]:
    """Execute one bounded request against a prevalidated pinned address."""
    method = str(item.get("method") or "GET").upper()
    url = str(item.get("url") or "")

    if method not in safe_methods:
        return observation(method, url, 0, {}, b"", "unsafe_method_blocked"), "stopped_for_safety"

    allowed, reason = url_safety(url, policy)
    if not allowed:
        return observation(method, url, 0, {}, b"", reason), "stopped_for_safety"

    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    public, addresses = resolve_public_addresses(host, port)
    if not public:
        blocked = observation(method, url, 0, {}, b"", "non_public_resolution_blocked")
        blocked["resolved_addresses"] = addresses
        blocked["dns_rebinding_protection"] = "blocked_before_connect"
        blocked["environment_proxy_used"] = False
        blocked["safe_transport_version"] = SAFE_TRANSPORT_VERSION
        return blocked, "stopped_for_safety"

    pinned_ip = addresses[0]
    headers = {
        "User-Agent": f"Recon-Monitor-Safe-Validation/{validation_version}",
        "Accept": "application/json,text/plain,*/*",
    }
    headers.update({str(k): str(v) for k, v in dict(item.get("headers") or {}).items()})
    request = urllib.request.Request(url=url, headers=headers, method=method)
    opener = build_pinned_opener(pinned_ip)

    try:
        with opener.open(request, timeout=8) as response:
            body = response.read(max_response_bytes + 1) if method != "HEAD" else b""
            if len(body) > max_response_bytes:
                result = observation(
                    method,
                    url,
                    int(response.status),
                    response.headers,
                    body[:max_response_bytes],
                    "response_budget_exceeded",
                )
                return _annotate_resolution(result, addresses, pinned_ip), "stopped_for_safety"

            result = observation(method, url, int(response.status), response.headers, body)
            location = result.get("headers", {}).get("location", "")
            if location:
                redirected = urllib.parse.urljoin(url, location)
                if not policy.url_in_scope(redirected):
                    result["redirect_outside_scope"] = True
            return _annotate_resolution(result, addresses, pinned_ip), "ok"

    except urllib.error.HTTPError as exc:
        body = exc.read(max_response_bytes + 1) if method != "HEAD" else b""
        if len(body) > max_response_bytes:
            body = body[:max_response_bytes]
        result = observation(method, url, int(exc.code), exc.headers, body, "http_error")
        location = result.get("headers", {}).get("location", "")
        if location:
            redirected = urllib.parse.urljoin(url, location)
            result["redirect_outside_scope"] = not policy.url_in_scope(redirected)
        result = _annotate_resolution(result, addresses, pinned_ip)
        if exc.code == 429:
            return result, "stopped_for_safety"
        return result, "ok"

    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result = observation(method, url, 0, {}, b"", str(exc)[:500])
        return _annotate_resolution(result, addresses, pinned_ip), "error"
