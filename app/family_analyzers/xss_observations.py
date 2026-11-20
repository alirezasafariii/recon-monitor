"""Classify stored XSS marker captures without performing target requests.

A reflection is discovery context. Execution and persistence require separate,
explicit browser/request evidence; neither is inferred from HTML keywords.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Mapping
from urllib.parse import urlsplit

from .remaining_common import observations, truth

XSS_OBSERVATION_VERSION = "1.1.0"


class _Contexts(HTMLParser):
    def __init__(self, marker: str):
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.stack: list[str] = []
        self.contexts: set[str] = set()

    def handle_starttag(self, tag, attrs):
        if any(self.marker in (value or "") for _, value in attrs):
            self.contexts.add("html_attribute")
        if tag in {"script", "style", "textarea", "title"}:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.stack:
            self.stack = self.stack[:self.stack.index(tag)]

    def handle_data(self, data):
        if self.marker in data:
            self.contexts.add(self.stack[-1] if self.stack else "html_text")

    def handle_comment(self, data):
        if self.marker in data:
            self.contexts.add("html_comment")


def _origin(url: str) -> tuple | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    except (TypeError, ValueError):
        return None


def normalize_xss_observations(family: str, endpoint: str, details: Mapping[str, Any]) -> tuple[dict, dict]:
    """Translate bounded, request-bound stored captures into canonical signals.

    Legacy signal envelopes remain supported. Structured marker captures add
    context, never an execution claim based solely on reflected text.
    """
    result = dict(details)
    key = family + "_observations"
    records = observations(details, key, "phase2_family_observations", "security_behavior_observations")
    summaries = []
    normalized = []
    spec_prefix = "reflected" if family == "reflected_xss" else "stored"
    direct = spec_prefix + "_script_execution_observed"
    controls = ("contextual_output_encoding_observed", "stored_output_encoding_observed",
                "stored_sanitization_observed", "csp_blocks_inline_execution", "input_not_reflected")
    for record in records[:50]:
        item = dict(record)
        # Conflicting claims in one capture must not override its own control.
        if any(truth(item.get(control)) is True for control in controls):
            item.pop(direct, None)
        marker = item.get("marker")
        body = item.get("response_text")
        if marker is not None or body is not None:
            # Captures use inert unique alphanumeric markers, not executable payloads.
            valid = (isinstance(marker, str) and re.fullmatch(r"[A-Za-z0-9_-]{12,128}", marker)
                     and isinstance(body, str)
                     and bool(item.get("request_id")) and bool(item.get("input_name"))
                     and item.get("request_url") == endpoint
                     and _origin(endpoint) is not None
                     and _origin(str(item.get("response_url") or "")) == _origin(endpoint))
            # Structured claims must bind the exact marker to its source input.
            valid = bool(valid and item.get("input_marker") == marker)
            contexts: set[str] = set()
            media = str(item.get("content_type") or "").split(";", 1)[0].strip().lower()
            if valid and marker in body and media == "text/html":
                parser = _Contexts(marker)
                parser.feed(body)
                contexts = parser.contexts
            runtime_bound = (valid and item.get("execution_marker") == marker
                             and bool(item.get("browser_capture_id"))
                             and _origin(str(item.get("execution_url") or "")) == _origin(endpoint)
                             and any(truth(item.get(k)) is True for k in ("controlled_test_context", "authorized_test_context", "controlled_observation"))
                             and any(truth(item.get(k)) is True for k in ("benign_test_marker", "safe_test_marker", "non_destructive_test", "harmless_test"))
                             and truth(item.get(direct)) is True)
            # Encoded or JSON response data may be decoded/rendered by the browser.
            # These flags alone never establish execution without the bound callback.
            if (not contexts and runtime_bound and truth(item.get("encoded_input_reflected")) is True
                    and truth(item.get("request_carried_input")) is True):
                contexts.add("browser_rendered_value")
            persisted = (bool(item.get("write_request_id"))
                         and item.get("write_request_id") != item.get("request_id")
                         and item.get("write_marker") == marker
                         and truth(item.get("read_request_contains_marker")) is False)
            eligible = bool(contexts and (family == "reflected_xss" or persisted))
            if eligible:
                result["reflected_input_surface" if family == "reflected_xss"
                       else "persistent_user_content_surface"] = True
            # A browser execution observation must identify the same marker and origin.
            execution = (eligible and item.get("execution_marker") == marker
                         and bool(item.get("browser_capture_id"))
                         and _origin(str(item.get("execution_url") or "")) == _origin(endpoint)
                         and any(truth(item.get(k)) is True for k in (
                             "controlled_test_context", "authorized_test_context", "controlled_observation"))
                         and any(truth(item.get(k)) is True for k in (
                             "benign_test_marker", "safe_test_marker", "non_destructive_test", "harmless_test"))
                         and truth(item.get(direct)) is True)
            if not execution:
                item.pop(direct, None)
            summaries.append({"request_id": str(item.get("request_id") or "")[:160],
                              "contexts": sorted(contexts), "capture_valid": valid,
                              "persistence_established": bool(eligible and family == "stored_xss"),
                              "execution_established": bool(execution)})
        # Response bodies and marker values are never copied into analyzer metadata.
        normalized.append({k: v for k, v in item.items() if k not in {
            "response_text", "marker", "input_marker", "write_marker", "execution_marker"}})
    for name in (key, "phase2_family_observations", "security_behavior_observations"):
        result.pop(name, None)
    result[key] = normalized
    if any(truth(result.get(control)) is True for control in controls):
        result.pop(direct, None)
    return result, {"xss_observation_version": XSS_OBSERVATION_VERSION,
                    "xss_capture_summaries": summaries,
                    "reflection_alone_is_execution": False}
