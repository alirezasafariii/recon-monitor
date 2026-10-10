"""Experimental fail-closed completion reader; not wired into stage_urls."""
import json
from pathlib import Path
from urllib.parse import urlsplit

CONTRACT = "recon.katana.standard.completion.v1"
COUNTERS = ("attempted_requests", "failed_requests", "limited_requests",
            "pending_items", "active_items")
FIELDS = {"contract", "origin", "stop_reason", *COUNTERS}
REASONS = {"queue_exhausted", "deadline", "cancelled", "page_limit",
           "request_errors", "unknown"}


def origin_key(value):
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("origin must be text")
    url = urlsplit(value)
    if (url.scheme not in {"http", "https"} or not url.hostname
            or url.username is not None or url.password is not None
            or url.path not in {"", "/"} or url.query or url.fragment):
        raise ValueError("invalid origin")
    port = url.port
    if port == 0:
        raise ValueError("invalid port")
    host = url.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    suffix = f":{port}" if port and port != (443 if url.scheme == "https" else 80) else ""
    return f"{url.scheme}://{host}{suffix}"


def unique_fields(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def read_completion(path, origins, *, returncode, timed_out):
    """A complete event is evidence of bounded queue exhaustion, not all pages."""
    expected = {origin_key(origin) for origin in origins}
    unknown = lambda reason: {
        key: {"status": "unknown", "stop_reason": reason} for key in sorted(expected)
    }
    if type(returncode) is not int or type(timed_out) is not bool or returncode != 0 or timed_out:
        return unknown("process_incomplete")
    try:
        raw = Path(path).read_bytes()
        if not raw or len(raw) > 1024 * 1024:
            return unknown("artifact_empty_or_oversized")
        lines = raw.decode("utf-8").splitlines()
        if len(lines) > 256:
            return unknown("artifact_oversized")
        records = {}
        for line in lines:
            if not line.strip():
                continue
            row = json.loads(line, object_pairs_hook=unique_fields)
            if not isinstance(row, dict) or set(row) != FIELDS or row["contract"] != CONTRACT:
                raise ValueError("unsupported completion schema")
            key = origin_key(row["origin"])
            if key not in expected or key in records:
                raise ValueError("unexpected or duplicate origin")
            for field in COUNTERS:
                if type(row[field]) is not int or not 0 <= row[field] <= 10**9:
                    raise ValueError("invalid counter")
            reason = row["stop_reason"]
            if reason not in REASONS or row["failed_requests"] > row["attempted_requests"]:
                raise ValueError("invalid outcome")
            if reason == "queue_exhausted" and (
                row["attempted_requests"] == 0
                or any(row[field] != 0 for field in COUNTERS[1:])
            ):
                raise ValueError("inconsistent completion")
            if reason == "request_errors" and row["failed_requests"] == 0:
                raise ValueError("missing request error evidence")
            if reason == "page_limit" and row["limited_requests"] == 0:
                raise ValueError("missing page limit evidence")
            records[key] = {"status": "completed" if reason == "queue_exhausted" else "partial",
                            "stop_reason": reason, "counters": {f: row[f] for f in COUNTERS}}
        return {key: records.get(key, {"status": "unknown", "stop_reason": "origin_event_missing"})
                for key in sorted(expected)}
    except (OSError, UnicodeError, ValueError, TypeError):
        return unknown("artifact_invalid_or_unavailable")
