from __future__ import annotations

"""Keep evidence facts separate from their independent score contributions."""

from collections import defaultdict
from typing import Any, Iterable, Mapping

from core import parse_int


def source_group(item: Mapping[str, Any]) -> str:
    return str(item.get("source_group") or item.get("source") or item.get("type") or "rule").strip().lower()


def independent_representatives(items: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """One scoring contribution per source; never use this list for fact checks."""
    groups: dict[str, Mapping[str, Any]] = {}
    for item in items:
        group = source_group(item)
        current = groups.get(group)
        rank = (abs(parse_int(item.get("weight"), 0)), parse_int(item.get("trust_score"), 0))
        if current is None or rank > (abs(parse_int(current.get("weight"), 0)), parse_int(current.get("trust_score"), 0)):
            groups[group] = item
    return list(groups.values())


def independent_evidence(items: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Retain all facts while reporting the number of independent sources.

    Different types, observations and polarities can carry necessary facts even
    when they share provenance. Correlation limits score contributions, not the
    evidence made available to prerequisite and contradiction checks.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in items:
        item = dict(raw)
        group = source_group(item)
        item["source_group"] = group
        grouped[group].append(item)
    retained: list[dict[str, Any]] = []
    for values in grouped.values():
        for item in values:
            item["correlated_signal_count"] = len(values)
            retained.append(item)
    retained.sort(key=lambda value: abs(parse_int(value.get("weight"), 0)), reverse=True)
    metadata = {
        "independent_groups": len(grouped),
        "raw_signals": len(retained),
        "retained_facts": len(retained),
        "groups": {group: len(values) for group, values in grouped.items()},
        # Compatibility key: these are suppressed extra score contributions;
        # the corresponding distinct facts remain in the returned evidence.
        "double_counted_signals_suppressed": len(retained) - len(grouped),
    }
    return retained, metadata
