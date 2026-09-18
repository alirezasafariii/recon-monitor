from __future__ import annotations

"""Pinned transport for bounded Safe Validation requests.

The transport resolves the target once, rejects any non-public address, and
connects directly to one validated address while preserving the original HTTP
Host header and TLS SNI hostname. Environment proxies are disabled. This closes
the DNS-rebinding / time-of-check-time-of-use gap that exists when a hostname is
validated and then independently resolved again by the HTTP client.
"""

import contextlib
import http.client
import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

SAFE_TRANSPORT_VERSION = "1.2.0"


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
        # Positive allow-list: only globally routable addresses may be
        # connected. This also rejects shared CGNAT (100.64.0.0/10),
        # documentation/reserved ranges and future special-purpose space that a
        # blacklist can miss.
        if not ip.is_global:
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


_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_CROSS_ORIGIN_FORWARD_HEADERS = {
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "if-modified-since",
    "if-none-match",
    "range",
}


def _effective_port(parsed: urllib.parse.SplitResult) -> int:
    return parsed.port or (443 if parsed.scheme.lower() == "https" else 80)


def _same_origin(left: str, right: str) -> bool:
    try:
        a=urllib.parse.urlsplit(left)
        b=urllib.parse.urlsplit(right)
        return (
            a.scheme.lower()==b.scheme.lower()
            and (a.hostname or "").lower()==(b.hostname or "").lower()
            and _effective_port(a)==_effective_port(b)
        )
    except ValueError:
        return False


def _redirect_headers(
    headers: dict[str, str],
    *,
    previous_url: str,
    next_url: str,
) -> dict[str, str]:
    if _same_origin(previous_url,next_url):
        return dict(headers)
    return {
        str(key):str(value)
        for key,value in headers.items()
        if str(key).strip().lower() in _CROSS_ORIGIN_FORWARD_HEADERS
    }


def _header_dict(headers: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not headers:
        return result
    try:
        items = headers.items()
    except AttributeError:
        return result
    for key, value in items:
        result[str(key)] = str(value)
    return result


def _transport_result(
    *,
    original_url: str,
    final_url: str,
    status_code: int,
    headers: Any,
    data: bytes = b"",
    error: str = "",
    transport_status: str = "ok",
    resolved_addresses: list[str] | None = None,
    pinned_address: str = "",
    transport_hops: list[dict[str, Any]] | None = None,
    redirect_outside_scope: bool = False,
) -> dict[str, Any]:
    return {
        "url": original_url,
        "final_url": final_url,
        "status_code": int(status_code or 0),
        "headers": _header_dict(headers),
        "data": data,
        "error": str(error or ""),
        "transport_status": transport_status,
        "resolved_addresses": list(resolved_addresses or []),
        "pinned_address": pinned_address,
        "transport_hops": list(transport_hops or []),
        "redirect_outside_scope": bool(redirect_outside_scope),
        "dns_rebinding_protection": (
            "resolution_pinned_each_hop"
            if transport_status != "stopped_for_safety"
            else "blocked_before_unsafe_connect"
        ),
        "environment_proxy_used": False,
        "safe_transport_version": SAFE_TRANSPORT_VERSION,
    }


def perform_pinned_download(
    url: str,
    policy: Any,
    *,
    headers: dict[str, str] | None = None,
    max_response_bytes: int,
    timeout: float = 8.0,
    max_redirects: int = 3,
    user_agent: str = "Recon-Monitor-Pinned-Download/1",
    before_request: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Perform a bounded GET with scope checks and fresh pinning on every redirect hop.

    Redirects are followed only when the next absolute URL remains authorized.
    Every hop is resolved once, rejected if any resolution is non-public, and
    connected through a direct pinned opener with environment proxies disabled.
    """
    original_url = str(url or "").strip()
    current_url = original_url
    active_headers = {str(k): str(v) for k, v in dict(headers or {}).items()}
    max_bytes = max(0, int(max_response_bytes))
    redirect_limit = max(0, min(int(max_redirects), 10))
    hop_log: list[dict[str, Any]] = []

    for redirect_index in range(redirect_limit + 1):
        parsed = urllib.parse.urlsplit(current_url)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or not policy.url_in_scope(current_url)
        ):
            return _transport_result(
                original_url=original_url,
                final_url=current_url,
                status_code=0,
                headers={},
                error="outside_scope_or_invalid_url",
                transport_status="stopped_for_safety",
                transport_hops=hop_log,
            )

        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        public, addresses = resolve_public_addresses(host, port)
        if not public:
            hop_log.append(
                {
                    "url": current_url,
                    "resolved_addresses": addresses,
                    "pinned_address": "",
                    "status_code": 0,
                    "result": "non_public_resolution_blocked",
                }
            )
            return _transport_result(
                original_url=original_url,
                final_url=current_url,
                status_code=0,
                headers={},
                error="non_public_resolution_blocked",
                transport_status="stopped_for_safety",
                resolved_addresses=addresses,
                transport_hops=hop_log,
            )

        pinned_ip = addresses[0]
        if before_request is not None:
            before_request(current_url)

        request_headers = {
            "User-Agent": user_agent,
            "Accept": "*/*",
        }
        request_headers.update(active_headers)
        request = urllib.request.Request(
            url=current_url,
            headers=request_headers,
            method="GET",
        )
        opener = build_pinned_opener(pinned_ip)

        try:
            with opener.open(request, timeout=max(0.1, float(timeout))) as response:
                response_headers = response.headers
                content_length = str(response_headers.get("Content-Length", "") or "").strip()
                if content_length:
                    try:
                        declared_length = int(content_length)
                    except ValueError:
                        declared_length = -1
                    if declared_length > max_bytes:
                        hop_log.append(
                            {
                                "url": current_url,
                                "resolved_addresses": addresses,
                                "pinned_address": pinned_ip,
                                "status_code": int(getattr(response, "status", 0) or 0),
                                "result": "response_budget_exceeded",
                            }
                        )
                        return _transport_result(
                            original_url=original_url,
                            final_url=current_url,
                            status_code=int(getattr(response, "status", 0) or 0),
                            headers=response_headers,
                            error="response_budget_exceeded",
                            transport_status="stopped_for_safety",
                            resolved_addresses=addresses,
                            pinned_address=pinned_ip,
                            transport_hops=hop_log,
                        )
                data = response.read(max_bytes + 1)
                if len(data) > max_bytes:
                    data = data[:max_bytes]
                    hop_log.append(
                        {
                            "url": current_url,
                            "resolved_addresses": addresses,
                            "pinned_address": pinned_ip,
                            "status_code": int(getattr(response, "status", 0) or 0),
                            "result": "response_budget_exceeded",
                        }
                    )
                    return _transport_result(
                        original_url=original_url,
                        final_url=current_url,
                        status_code=int(getattr(response, "status", 0) or 0),
                        headers=response_headers,
                        data=data,
                        error="response_budget_exceeded",
                        transport_status="stopped_for_safety",
                        resolved_addresses=addresses,
                        pinned_address=pinned_ip,
                        transport_hops=hop_log,
                    )
                status_code = int(getattr(response, "status", 0) or 0)
                hop_log.append(
                    {
                        "url": current_url,
                        "resolved_addresses": addresses,
                        "pinned_address": pinned_ip,
                        "status_code": status_code,
                        "result": "response",
                    }
                )
                return _transport_result(
                    original_url=original_url,
                    final_url=current_url,
                    status_code=status_code,
                    headers=response_headers,
                    data=data,
                    transport_status="ok",
                    resolved_addresses=addresses,
                    pinned_address=pinned_ip,
                    transport_hops=hop_log,
                )

        except urllib.error.HTTPError as exc:
            status_code = int(exc.code or 0)
            response_headers = exc.headers or {}
            location = str(response_headers.get("Location", "") or "").strip()
            if status_code in _REDIRECT_STATUSES and location:
                next_url = urllib.parse.urljoin(current_url, location)
                in_scope = bool(policy.url_in_scope(next_url))
                current_parts = urllib.parse.urlsplit(current_url)
                next_parts = urllib.parse.urlsplit(next_url)
                downgrade = (
                    current_parts.scheme.lower()=="https"
                    and next_parts.scheme.lower()=="http"
                )
                hop_log.append(
                    {
                        "url": current_url,
                        "resolved_addresses": addresses,
                        "pinned_address": pinned_ip,
                        "status_code": status_code,
                        "location": location,
                        "next_url": next_url,
                        "result": (
                            "redirect_scheme_downgrade"
                            if downgrade
                            else (
                                "redirect_in_scope"
                                if in_scope
                                else "redirect_outside_scope"
                            )
                        ),
                    }
                )
                with contextlib.suppress(Exception):
                    exc.close()
                if not in_scope:
                    return _transport_result(
                        original_url=original_url,
                        final_url=current_url,
                        status_code=status_code,
                        headers=response_headers,
                        error="redirect_outside_scope",
                        transport_status="stopped_for_safety",
                        resolved_addresses=addresses,
                        pinned_address=pinned_ip,
                        transport_hops=hop_log,
                        redirect_outside_scope=True,
                    )
                if downgrade:
                    return _transport_result(
                        original_url=original_url,
                        final_url=current_url,
                        status_code=status_code,
                        headers=response_headers,
                        error="redirect_scheme_downgrade_blocked",
                        transport_status="stopped_for_safety",
                        resolved_addresses=addresses,
                        pinned_address=pinned_ip,
                        transport_hops=hop_log,
                    )
                if redirect_index >= redirect_limit:
                    return _transport_result(
                        original_url=original_url,
                        final_url=current_url,
                        status_code=status_code,
                        headers=response_headers,
                        error="redirect_limit_exceeded",
                        transport_status="stopped_for_safety",
                        resolved_addresses=addresses,
                        pinned_address=pinned_ip,
                        transport_hops=hop_log,
                    )
                active_headers = _redirect_headers(
                    active_headers,
                    previous_url=current_url,
                    next_url=next_url,
                )
                current_url = next_url
                continue

            body = b""
            if max_bytes:
                with contextlib.suppress(Exception):
                    body = exc.read(max_bytes + 1)
                if len(body) > max_bytes:
                    body = body[:max_bytes]
            with contextlib.suppress(Exception):
                exc.close()
            hop_log.append(
                {
                    "url": current_url,
                    "resolved_addresses": addresses,
                    "pinned_address": pinned_ip,
                    "status_code": status_code,
                    "result": "http_error",
                }
            )
            return _transport_result(
                original_url=original_url,
                final_url=current_url,
                status_code=status_code,
                headers=response_headers,
                data=body,
                error="http_error",
                transport_status="stopped_for_safety" if status_code == 429 else "ok",
                resolved_addresses=addresses,
                pinned_address=pinned_ip,
                transport_hops=hop_log,
            )

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            hop_log.append(
                {
                    "url": current_url,
                    "resolved_addresses": addresses,
                    "pinned_address": pinned_ip,
                    "status_code": 0,
                    "result": "transport_error",
                }
            )
            return _transport_result(
                original_url=original_url,
                final_url=current_url,
                status_code=0,
                headers={},
                error=str(exc)[:500],
                transport_status="error",
                resolved_addresses=addresses,
                pinned_address=pinned_ip,
                transport_hops=hop_log,
            )

    return _transport_result(
        original_url=original_url,
        final_url=current_url,
        status_code=0,
        headers={},
        error="redirect_limit_exceeded",
        transport_status="stopped_for_safety",
        transport_hops=hop_log,
    )


def fetch_pinned_tls_peer(
    url: str,
    policy: Any,
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Return the TLS peer certificate after scope/public-IP validation and IP pinning."""
    candidate = str(url or "").strip()
    parsed = urllib.parse.urlsplit(candidate)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or not policy.url_in_scope(candidate)
    ):
        return {
            "certificate": {},
            "error": "outside_scope_or_not_https",
            "environment_proxy_used": False,
            "safe_transport_version": SAFE_TRANSPORT_VERSION,
        }

    host = parsed.hostname
    port = parsed.port or 443
    public, addresses = resolve_public_addresses(host, port)
    if not public:
        return {
            "certificate": {},
            "error": "non_public_resolution_blocked",
            "resolved_addresses": addresses,
            "pinned_address": "",
            "dns_rebinding_protection": "blocked_before_connect",
            "environment_proxy_used": False,
            "safe_transport_version": SAFE_TRANSPORT_VERSION,
        }

    pinned_ip = addresses[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection(
            (pinned_ip, port),
            timeout=max(0.1, float(timeout)),
        ) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                certificate = dict(sock.getpeercert() or {})
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        return {
            "certificate": {},
            "error": str(exc)[:500],
            "resolved_addresses": addresses,
            "pinned_address": pinned_ip,
            "dns_rebinding_protection": "resolution_pinned",
            "environment_proxy_used": False,
            "safe_transport_version": SAFE_TRANSPORT_VERSION,
        }

    return {
        "certificate": certificate,
        "error": "",
        "resolved_addresses": addresses,
        "pinned_address": pinned_ip,
        "dns_rebinding_protection": "resolution_pinned",
        "environment_proxy_used": False,
        "safe_transport_version": SAFE_TRANSPORT_VERSION,
    }
