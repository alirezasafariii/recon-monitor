"""Conservative, local-only Katana retry decisions.

The crawler owns its checkpoint. This module never acknowledges pending URLs and
never retries inside an HTTP 429 cooldown. Keep it independent of app imports so
the decision rules can be regression tested without network access.
"""
from __future__ import annotations

import json
import math
import re
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

# Treat a 429 as a host-level throttle, including http/https variants.
# The custom Katana JSONL error artifact does not currently expose Retry-After.
# This is a floor, not permission to violate a target's published limits.
THROTTLE_COOLDOWN_SECONDS = 3600
_THROTTLE_MAX_SECONDS = 86400
_HTTP_429 = re.compile(r"\bHTTP\s+429\b|\bstatus(?:_code)?\s*[:=]\s*429\b", re.I)


def katana_host(origin: str) -> str:
    try:
        return (urlsplit(origin).hostname or "").lower()
    except ValueError:
        return ""


def load_throttle_state(path: Path, *, now: float | None = None) -> dict[str, dict]:
    """Return active host cooldowns; malformed or expired entries are ignored."""
    now = time.time() if now is None else now
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("version") != 1:
        return {}
    result: dict[str, dict] = {}
    entries = data.get("hosts")
    if not isinstance(entries, dict):
        return {}
    for host, item in entries.items():
        if not isinstance(host, str) or not isinstance(item, dict):
            continue
        try:
            until = float(item["retry_not_before"])
        except (KeyError, TypeError, ValueError, OverflowError):
            continue
        if (math.isfinite(until) and now < until <= now + _THROTTLE_MAX_SECONDS
                and katana_host("https://" + host) == host):
            result[host] = {"retry_not_before": until, "reason": "http_429"}
    return result


def classify_katana_request_errors(path: Path, batch_origins: list[str]) -> dict:
    """Use only JSONL `error`, never endpoint text, to identify a throttle.

    If a line's endpoint cannot safely identify a member of the batch, defer
    every batch host. This is deliberately conservative for non-checkpoint Katana.
    """
    counts: Counter[str] = Counter()
    throttled: set[str] = set()
    allowed = {katana_host(origin) for origin in batch_origins} - {""}
    # A capped iterator avoids loading an arbitrarily large external artifact.
    # Truncation fails closed: assume any uninspected tail might contain a 429.
    try:
        stream = path.open(encoding="utf-8", errors="replace")
    except OSError:
        return {"counts": {}, "throttled_hosts": []}
    with stream:
        for index, line in enumerate(stream):
            if index >= 10000:
                counts["error_log_truncated"] += 1
                throttled.update(allowed)
                break
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                counts["malformed"] += 1
                continue
            if not isinstance(obj, dict):
                counts["malformed"] += 1
                continue
            error = str(obj.get("error") or "")[:2048]
            if _HTTP_429.search(error):
                counts["http_429"] += 1
                host = katana_host(str(obj.get("endpoint") or ""))
                throttled.update([host] if host in allowed else allowed)
            elif "no address found for host" in error.lower() or "no such host" in error.lower():
                counts["dns_failure"] += 1
            elif "context canceled" in error.lower() or "context cancelled" in error.lower():
                counts["cancelled"] += 1
            elif re.search(r"timeout|deadline exceeded|timed out", error, re.I):
                counts["timeout"] += 1
            elif re.search(r"connection reset|refused|broken pipe|eof", error, re.I):
                counts["connection"] += 1
            elif error:
                counts["other"] += 1
    return {"counts": dict(counts), "throttled_hosts": sorted(throttled)}


def register_throttling(state: dict[str, dict], hosts: list[str], *, now: float) -> None:
    for host in hosts:
        if not host:
            continue
        current = state.get(host, {})
        state[host] = {
            "reason": "http_429",
            "retry_not_before": max(
                float(current.get("retry_not_before") or 0),
                now + THROTTLE_COOLDOWN_SECONDS,
            ),
        }


def frontier_reduction_observed(old_outcomes: list[dict], new_outcomes: list[dict]) -> bool:
    """Recognize proven progress inside an unchanged set of pending origins.

    Counts are snapshots, not request counters: a decreasing pending frontier is
    proof of progress; an equal/increased frontier is *not* proof of no progress.
    """
    def latest(outcomes: list[dict]) -> dict[str, int]:
        state: dict[str, int] = {}
        for batch in outcomes:
            if not isinstance(batch, dict):
                continue
            completions = batch.get("origin_completion") or {}
            if not isinstance(completions, dict):
                continue
            for key, item in completions.items():
                if not isinstance(item, dict):
                    continue
                counters = item.get("counters") or {}
                if not isinstance(counters, dict):
                    continue
                try:
                    pending = int(counters["pending_items"])
                    active = int(counters.get("active_items", 0))
                except (KeyError, ValueError, TypeError, OverflowError):
                    continue
                if pending >= 0 and active >= 0:
                    state[str(key)] = pending + active
        return state

    before = latest(old_outcomes)
    after = latest(new_outcomes)
    return any(after[key] < before[key] for key in before.keys() & after.keys())
