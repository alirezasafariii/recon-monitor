from __future__ import annotations

import difflib
import re
import urllib.parse
from typing import Any, Iterable, Mapping

from core import extract_js_indicators, semantic_js_normalize

_ENDPOINT_RULES: list[tuple[str, re.Pattern[str], int]] = [
    ("authentication", re.compile(r"(?:^|[/_.?-])(auth|oauth|sso|login|logout|signin|signup|register|token|session|password|mfa|2fa)(?:$|[/_.?=&-])", re.I), 92),
    ("authorization", re.compile(r"(?:^|[/_.?-])(permission|permissions|role|roles|acl|policy|authorize|entitlement)(?:$|[/_.?=&-])", re.I), 88),
    ("admin", re.compile(r"(?:^|[/_.?-])(admin|administrator|management|manage|backoffice|console)(?:$|[/_.?=&-])", re.I), 94),
    ("debug", re.compile(r"(?:^|[/_.?-])(debug|trace|diagnostic|health|metrics|actuator|swagger|openapi|graphiql)(?:$|[/_.?=&-])", re.I), 90),
    ("upload", re.compile(r"(?:^|[/_.?-])(upload|attachment|file|media|avatar|import)(?:$|[/_.?=&-])", re.I), 82),
    ("export", re.compile(r"(?:^|[/_.?-])(export|download|backup|dump|report|csv|pdf)(?:$|[/_.?=&-])", re.I), 86),
    ("payment", re.compile(r"(?:^|[/_.?-])(payment|payments|billing|checkout|invoice|subscription|card|wallet)(?:$|[/_.?=&-])", re.I), 92),
    ("personal_data", re.compile(r"(?:^|[/_.?-])(profile|account|user|users|customer|customers|address|identity|pii)(?:$|[/_.?=&-])", re.I), 78),
    ("internal", re.compile(r"(?:^|[/_.?-])(internal|private|staff|employee|corp|staging|stage|uat|preprod|dev)(?:$|[/_.?=&-])", re.I), 88),
    ("graphql", re.compile(r"(?:^|[/_.?-])(graphql|graphiql)(?:$|[/_.?=&-])", re.I), 96),
    ("websocket", re.compile(r"^(?:wss?://)|(?:^|[/_.?-])(socket|websocket|ws)(?:$|[/_.?=&-])", re.I), 90),
    ("webhook", re.compile(r"(?:^|[/_.?-])(webhook|callback|hook)(?:$|[/_.?=&-])", re.I), 84),
    ("api", re.compile(r"(?:^|[/_.?-])(api|rest|v\d+)(?:$|[/_.?=&-])", re.I), 76),
]


def classify_endpoint(value: str, *, kind: str = "endpoint", context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    context = context or {}
    text = value.strip()
    categories: list[dict[str, Any]] = []
    for name, pattern, confidence in _ENDPOINT_RULES:
        if pattern.search(text):
            categories.append({"category": name, "confidence": confidence, "reason": f"Matched {name} path pattern"})
    if kind == "graphql_operation":
        categories.insert(0, {"category": "graphql", "confidence": 98, "reason": "Extracted GraphQL operation"})
    elif kind == "absolute_url":
        try:
            parsed = urllib.parse.urlsplit(text)
            if parsed.scheme in {"ws", "wss"}:
                categories.insert(0, {"category": "websocket", "confidence": 98, "reason": "WebSocket URL scheme"})
        except ValueError:
            pass
    if context.get("redacted"):
        categories.insert(0, {"category": "sensitive", "confidence": 95, "reason": "Sensitive value was redacted"})
    if not categories:
        categories.append({"category": "general", "confidence": 55, "reason": "No specialized endpoint pattern matched"})
    # Keep the strongest category first, then unique categories.
    categories.sort(key=lambda item: int(item["confidence"]), reverse=True)
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in categories:
        if item["category"] not in seen:
            unique.append(item)
            seen.add(str(item["category"]))
    primary = unique[0]
    return {
        "primary_category": primary["category"],
        "confidence": int(primary["confidence"]),
        "reasons": [str(item["reason"]) for item in unique],
        "categories": unique,
    }


def technology_confidence(technology: str, record: Mapping[str, Any]) -> dict[str, Any]:
    tech = technology.strip()
    haystack = " ".join(
        str(record.get(key) or "") for key in ("title", "webserver", "content_type", "cdn", "final_url")
    ).lower()
    confidence = 78
    reasons = ["Detected by ProjectDiscovery httpx technology detection"]
    token = re.sub(r"[^a-z0-9]+", " ", tech.lower()).strip()
    if token and any(part and part in haystack for part in token.split()):
        confidence += 12
        reasons.append("Technology name is corroborated by response metadata")
    if record.get("body_hash"):
        confidence += 3
        reasons.append("Response body fingerprint was available")
    if record.get("favicon_hash"):
        confidence += 3
        reasons.append("Favicon fingerprint was available")
    if record.get("webserver"):
        confidence += 2
        reasons.append("Web server metadata was available")
    confidence = min(99, confidence)
    label = "high" if confidence >= 85 else "medium" if confidence >= 65 else "low"
    return {"technology": tech, "confidence": confidence, "confidence_label": label, "reasons": reasons}


def _indicator_map(text: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for kind, value, _redacted in extract_js_indicators(text):
        result.setdefault(kind, set()).add(value)
    return result


def _redact_diff_text(text: str) -> str:
    text = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_AWS_ACCESS_KEY]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b", "[REDACTED_JWT]", text)
    text = re.sub(
        r"(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)(\s*[:=]\s*)([\"'][^\"']{3,}[\"'])",
        lambda m: f"{m.group(1)}{m.group(2)}\"[REDACTED]\"",
        text,
    )
    return text


def build_js_diff(old_text: str, new_text: str, *, max_diff_lines: int = 1200) -> tuple[str, dict[str, Any]]:
    old_normalized = semantic_js_normalize(_redact_diff_text(old_text))
    new_normalized = semantic_js_normalize(_redact_diff_text(new_text))
    # Add strategic line breaks so minified files still produce a useful diff.
    def lines(value: str) -> list[str]:
        value = re.sub(r"([;{}])", r"\1\n", value)
        return [line.strip() for line in value.splitlines() if line.strip()]

    diff_lines = list(
        difflib.unified_diff(
            lines(old_normalized),
            lines(new_normalized),
            fromfile="previous.js",
            tofile="current.js",
            lineterm="",
            n=3,
        )
    )
    truncated = len(diff_lines) > max_diff_lines
    visible = diff_lines[:max_diff_lines]
    if truncated:
        visible.append(f"... diff truncated after {max_diff_lines} lines ...")
    diff_text = "\n".join(visible) + ("\n" if visible else "")

    old_indicators = _indicator_map(old_text)
    new_indicators = _indicator_map(new_text)
    indicator_changes: dict[str, dict[str, list[str]]] = {}
    for kind in sorted(set(old_indicators) | set(new_indicators)):
        added = sorted(new_indicators.get(kind, set()) - old_indicators.get(kind, set()))
        removed = sorted(old_indicators.get(kind, set()) - new_indicators.get(kind, set()))
        if added or removed:
            indicator_changes[kind] = {"added": added[:500], "removed": removed[:500]}

    endpoint_kinds = {"endpoint", "absolute_url", "graphql_operation"}
    added_endpoints: list[dict[str, Any]] = []
    removed_endpoints: list[dict[str, Any]] = []
    for kind in endpoint_kinds:
        changes = indicator_changes.get(kind, {})
        for value in changes.get("added", []):
            added_endpoints.append({"kind": kind, "value": value, **classify_endpoint(value, kind=kind)})
        for value in changes.get("removed", []):
            removed_endpoints.append({"kind": kind, "value": value, **classify_endpoint(value, kind=kind)})

    additions = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
    removals = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
    summary = {
        "additions": additions,
        "removals": removals,
        "diff_lines": len(diff_lines),
        "truncated": truncated,
        "indicator_changes": indicator_changes,
        "added_endpoints": added_endpoints,
        "removed_endpoints": removed_endpoints,
        "meaningful": bool(indicator_changes or additions or removals),
    }
    return diff_text, summary


def endpoint_risk_bonus(classification: Mapping[str, Any]) -> tuple[int, list[str]]:
    category = str(classification.get("primary_category") or "general")
    confidence = int(classification.get("confidence") or 0)
    base = {
        "sensitive": 35,
        "admin": 28,
        "authentication": 25,
        "authorization": 25,
        "debug": 24,
        "payment": 24,
        "internal": 22,
        "export": 18,
        "upload": 16,
        "personal_data": 15,
        "graphql": 14,
        "websocket": 12,
        "webhook": 12,
        "api": 8,
        "general": 0,
    }.get(category, 0)
    scaled = round(base * min(100, confidence) / 100)
    reasons = [f"Endpoint classification {category} ({confidence}% confidence): +{scaled}"] if scaled else []
    return scaled, reasons
