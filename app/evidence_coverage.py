from __future__ import annotations

"""Diagnostic evidence-coverage projection for Analysis Brain families.

Evidence Coverage answers a narrow question: for each canonical family evidence
signal, was target evidence observed, not observed in fully collected passive
inputs, not collected because a relevant collector was incomplete, or still
unknown?

This module is intentionally non-evidentiary. Coverage state must never satisfy
admission, promote candidates, or turn missing collection into proof that a
vulnerability is absent.
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from core import atomic_write_text, json_dumps, utc_now
from family_reasoning import (
    FAMILY_ORDER,
    FAMILY_REASONING,
    FAMILY_REASONING_RULE_VERSION,
    FAMILY_REASONING_VERSION,
)

EVIDENCE_COVERAGE_VERSION = "1.0.0"
EVIDENCE_COVERAGE_RULE_VERSION = "2026.08.16.1"

EVIDENCE_STATUSES = {"observed", "not_observed", "not_collected", "unknown"}
INCOMPLETE_COLLECTION_STATUSES = {
    "partial",
    "degraded",
    "failed",
    "skipped",
    "unavailable",
}

# Signals with these markers normally require a live, behavioral, differential,
# or controlled observation. Passive collection completeness cannot prove they
# were "not observed", so missing records stay unknown.
_BEHAVIORAL_MARKERS = (
    "_observed",
    "_accepted",
    "_rejected",
    "_denied",
    "_success",
    "_differential",
    "_mismatch",
    "_conflict",
    "_violation",
    "_mutated",
    "_enforced",
    "_bypass",
    "_reached",
    "_confirmed",
    "_exposed",
    "_executed",
    "_triggered",
    "_leaked",
    "_access",
    "unauthorized_",
    "cross_identity_",
    "cross_tenant_",
    "out_of_root_",
    "without_secondary_guard",
    "validation_absent",
    "token_not_rotated",
    "session_reuse",
    "recovery_bypass",
    "runtime_unreachable",
)

# These markers identify passive client/static evidence that can be affected by
# the JavaScript collector represented by Collection Quality v1.
_JAVASCRIPT_MARKERS = (
    "dataflow",
    "source_sink",
    "postmessage",
    "message_handler",
    "javascript",
    "source_map",
    "navigation_context",
    "client_operation",
    "dom_",
    "server_fetch_semantic",
    "server_request_function",
)

# These markers identify endpoint/schema/surface evidence that can be affected
# by URL discovery coverage. Mapping is generic by signal shape, not by family,
# so Family Reasoning remains the sole vulnerability-policy source.
_URL_MARKERS = (
    "url_",
    "_url",
    "endpoint",
    "parameter",
    "identifier",
    "graphql_",
    "authentication_surface",
    "identity_lookup",
    "file_input",
    "filename_field",
    "path_",
    "storage_path",
    "body_schema",
    "privileged_property",
    "privileged_fields",
    "role_property",
    "write_method",
    "_operation",
    "privileged_function",
    "privileged_classification",
    "remote_destination",
    "server_feature",
    "state_change",
)

_DNS_MARKERS = (
    "dns_",
    "cname",
    "nameserver",
    "host_resolution",
    "domain_resolution",
)


def _loads_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        raw = value
    else:
        try:
            raw = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
    if not isinstance(raw, list):
        return []
    return [dict(item) for item in raw if isinstance(item, Mapping)]


def _family_order() -> list[str]:
    ordered = [str(family) for family in FAMILY_ORDER if str(family) in FAMILY_REASONING]
    extras = sorted(str(family) for family in FAMILY_REASONING if str(family) not in ordered)
    return [*ordered, *extras]


def _signal_is_behavioral(signal: str) -> bool:
    value = str(signal or "").strip().lower()
    return any(marker in value for marker in _BEHAVIORAL_MARKERS)


def _signal_dimensions(signal: str) -> tuple[str, ...]:
    """Return Collection Quality v1 dimensions that can affect one signal.

    Empty means current Collection Quality cannot justify an absence statement.
    """
    value = str(signal or "").strip().lower()
    if not value or _signal_is_behavioral(value):
        return ()

    dimensions: set[str] = set()
    if any(marker in value for marker in _DNS_MARKERS):
        dimensions.add("dns")
    if any(marker in value for marker in _JAVASCRIPT_MARKERS):
        dimensions.add("javascript")
    if any(marker in value for marker in _URL_MARKERS):
        dimensions.add("urls")

    # Several structural server/client semantics are commonly discoverable from
    # either endpoint metadata or static client references. Requiring both
    # dimensions to be complete before saying "not observed" is conservative.
    if value in {
        "server_feature",
        "remote_destination",
        "redirect_parameter",
        "file_input",
        "privileged_function",
        "privileged_classification",
        "authentication_surface",
        "identity_lookup",
    }:
        dimensions.update({"urls", "javascript"})

    return tuple(sorted(dimensions))


def _dimension_status(collection_quality: Mapping[str, Any], dimension: str) -> str:
    dimensions = collection_quality.get("dimensions", {})
    if not isinstance(dimensions, Mapping):
        return "unknown"
    raw = dimensions.get(dimension, {})
    if not isinstance(raw, Mapping):
        return "unknown"
    return str(raw.get("status") or "unknown").strip().lower()


def _observation_index(
    rows: Iterable[Mapping[str, Any]],
) -> tuple[
    dict[str, dict[str, dict[str, Any]]],
    dict[str, int],
]:
    """Index typed target evidence by family and signal type."""
    by_family: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    hypothesis_counts: dict[str, int] = defaultdict(int)

    for row in rows:
        family = str(row.get("bug_family") or "").strip()
        if not family:
            continue
        hypothesis_counts[family] += 1
        for channel, key in (
            ("support", "supporting_evidence_json"),
            ("contradict", "contradicting_evidence_json"),
        ):
            for item in _loads_list(row.get(key)):
                signal = str(item.get("type") or "").strip()
                if not signal:
                    continue
                record = by_family[family].setdefault(
                    signal,
                    {
                        "support": 0,
                        "contradict": 0,
                        "source_groups": set(),
                    },
                )
                record[channel] += 1
                source_group = str(
                    item.get("source_group")
                    or item.get("source")
                    or item.get("type")
                    or ""
                ).strip()
                if source_group:
                    record["source_groups"].add(source_group)

    return by_family, dict(hypothesis_counts)


def _signal_coverage(
    signal: str,
    observations: Mapping[str, Mapping[str, Any]],
    collection_quality: Mapping[str, Any],
) -> dict[str, Any]:
    observed = observations.get(signal, {})
    support_count = int(observed.get("support") or 0) if isinstance(observed, Mapping) else 0
    contradict_count = int(observed.get("contradict") or 0) if isinstance(observed, Mapping) else 0
    source_groups = sorted(
        str(value)
        for value in (
            observed.get("source_groups", set())
            if isinstance(observed, Mapping)
            else set()
        )
        if str(value).strip()
    )
    dimensions = list(_signal_dimensions(signal))
    collection_states = {
        dimension: _dimension_status(collection_quality, dimension)
        for dimension in dimensions
    }

    if support_count or contradict_count:
        channel = (
            "both"
            if support_count and contradict_count
            else "support"
            if support_count
            else "contradict"
        )
        return {
            "signal": signal,
            "status": "observed",
            "observation_channel": channel,
            "support_count": support_count,
            "contradict_count": contradict_count,
            "source_groups": source_groups,
            "collection_dimensions": dimensions,
            "collection_status": collection_states,
            "reason": "Typed target evidence for this signal exists in the current analysis.",
            "not_proof_of_absence": True,
        }

    if not dimensions:
        return {
            "signal": signal,
            "status": "unknown",
            "observation_channel": "none",
            "support_count": 0,
            "contradict_count": 0,
            "source_groups": [],
            "collection_dimensions": [],
            "collection_status": {},
            "reason": (
                "Current Collection Quality cannot justify an absence statement for "
                "this behavioral or unmapped evidence signal."
            ),
            "not_proof_of_absence": True,
        }

    states = list(collection_states.values())
    if any(state in INCOMPLETE_COLLECTION_STATUSES for state in states):
        return {
            "signal": signal,
            "status": "not_collected",
            "observation_channel": "none",
            "support_count": 0,
            "contradict_count": 0,
            "source_groups": [],
            "collection_dimensions": dimensions,
            "collection_status": collection_states,
            "reason": (
                "At least one relevant passive collection dimension was incomplete; "
                "absence of this signal cannot be interpreted as a negative observation."
            ),
            "not_proof_of_absence": True,
        }

    if any(state == "unknown" for state in states):
        return {
            "signal": signal,
            "status": "unknown",
            "observation_channel": "none",
            "support_count": 0,
            "contradict_count": 0,
            "source_groups": [],
            "collection_dimensions": dimensions,
            "collection_status": collection_states,
            "reason": (
                "Collection completeness is unknown for at least one relevant passive "
                "dimension."
            ),
            "not_proof_of_absence": True,
        }

    if states and all(state == "complete" for state in states):
        return {
            "signal": signal,
            "status": "not_observed",
            "observation_channel": "none",
            "support_count": 0,
            "contradict_count": 0,
            "source_groups": [],
            "collection_dimensions": dimensions,
            "collection_status": collection_states,
            "reason": (
                "No typed target evidence for this passive signal was emitted while all "
                "mapped collection dimensions were complete."
            ),
            "not_proof_of_absence": True,
        }

    return {
        "signal": signal,
        "status": "unknown",
        "observation_channel": "none",
        "support_count": 0,
        "contradict_count": 0,
        "source_groups": [],
        "collection_dimensions": dimensions,
        "collection_status": collection_states,
        "reason": "Coverage state could not be determined conservatively.",
        "not_proof_of_absence": True,
    }


def _group_coverage(
    signals: Iterable[str],
    observations: Mapping[str, Mapping[str, Any]],
    collection_quality: Mapping[str, Any],
) -> dict[str, Any]:
    signal_rows = [
        _signal_coverage(str(signal), observations, collection_quality)
        for signal in sorted({str(signal) for signal in signals if str(signal).strip()})
    ]
    support_observed = [
        item["signal"]
        for item in signal_rows
        if item["status"] == "observed"
        and int(item.get("support_count") or 0) > 0
    ]
    statuses = {str(item.get("status") or "unknown") for item in signal_rows}

    if support_observed:
        status = "observed"
        reason = (
            "Canonical OR-group has supporting target evidence: "
            + ", ".join(support_observed)
            + "."
        )
    elif "not_collected" in statuses:
        status = "not_collected"
        reason = "At least one alternative in this canonical evidence group was not fully collected."
    elif "unknown" in statuses:
        status = "unknown"
        reason = "At least one alternative requires evidence that current Collection Quality cannot assess."
    elif signal_rows and statuses == {"not_observed"}:
        status = "not_observed"
        reason = "No alternative in this passive canonical evidence group was observed."
    else:
        status = "unknown"
        reason = "Canonical evidence-group coverage is unknown."

    return {
        "status": status,
        "signals": signal_rows,
        "support_observed": support_observed,
        "not_proof_of_absence": True,
        "reason": reason,
    }


def _family_status(groups: Iterable[Mapping[str, Any]]) -> str:
    values = [str(group.get("status") or "unknown") for group in groups]
    if not values:
        return "unknown"
    if all(value == "observed" for value in values):
        return "observed"
    if any(value == "not_collected" for value in values):
        return "not_collected"
    if any(value == "unknown" for value in values):
        return "unknown"
    if any(value == "not_observed" for value in values):
        return "not_observed"
    return "unknown"


def snapshot_evidence_coverage(
    ctx: Any,
    *,
    analysis_id: str,
    collection_quality: Mapping[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Project current typed evidence onto canonical Family Reasoning contracts."""

    quality = dict(collection_quality or {})
    rows = ctx.db.all(
        "SELECT bug_family,supporting_evidence_json,contradicting_evidence_json "
        "FROM analysis_hypotheses WHERE analysis_id=? AND target=?",
        (analysis_id, ctx.policy.name),
    )
    normalized_rows = [dict(row) for row in rows]
    observations_by_family, hypothesis_counts = _observation_index(normalized_rows)

    families: dict[str, Any] = {}
    signal_status_counts = {status: 0 for status in sorted(EVIDENCE_STATUSES)}
    family_status_counts = {status: 0 for status in sorted(EVIDENCE_STATUSES)}

    for family in _family_order():
        contract = FAMILY_REASONING.get(family, {})
        observations = observations_by_family.get(family, {})

        promotion_groups = [
            _group_coverage(group, observations, quality)
            for group in contract.get("promotion_required", ())
        ]
        confirmation_groups = [
            _group_coverage(group, observations, quality)
            for group in contract.get("confirmation_required", ())
        ]

        blocking_signals = [
            _signal_coverage(signal, observations, quality)
            for signal in sorted(contract.get("blocking_contradictions", ()))
        ]
        override_signals = [
            _signal_coverage(signal, observations, quality)
            for signal in sorted(contract.get("override_signals", ()))
        ]

        unique_signal_rows: dict[str, dict[str, Any]] = {}
        for group in [*promotion_groups, *confirmation_groups]:
            for item in group["signals"]:
                unique_signal_rows[str(item["signal"])] = item
        for item in [*blocking_signals, *override_signals]:
            unique_signal_rows[str(item["signal"])] = item

        for item in unique_signal_rows.values():
            status = str(item.get("status") or "unknown")
            signal_status_counts[status if status in signal_status_counts else "unknown"] += 1

        promotion_status = _family_status(promotion_groups)
        family_status_counts[
            promotion_status if promotion_status in family_status_counts else "unknown"
        ] += 1

        families[family] = {
            "label": str(contract.get("label") or family),
            "category": str(contract.get("category") or "unknown"),
            "hypothesis_count": int(hypothesis_counts.get(family, 0)),
            "promotion_coverage_status": promotion_status,
            "promotion_required": promotion_groups,
            "confirmation_required": confirmation_groups,
            "blocking_contradictions": blocking_signals,
            "override_signals": override_signals,
            "min_independent_sources": int(contract.get("min_independent_sources", 1)),
            "validation_level": str(contract.get("validation_level") or "offline"),
            "policy_source": "family_reasoning",
        }

    result: dict[str, Any] = {
        "version": EVIDENCE_COVERAGE_VERSION,
        "rule_version": EVIDENCE_COVERAGE_RULE_VERSION,
        "generated_at": utc_now(),
        "run_id": str(ctx.run_id),
        "analysis_id": str(analysis_id),
        "target": str(ctx.policy.name),
        "family_reasoning_version": FAMILY_REASONING_VERSION,
        "family_reasoning_rule_version": FAMILY_REASONING_RULE_VERSION,
        "family_count": len(families),
        "families": families,
        "signal_status_counts": signal_status_counts,
        "family_promotion_status_counts": family_status_counts,
        "collection_quality_status": str(quality.get("status") or "unknown"),
        "diagnostic_only": True,
        "affects_admission": False,
        "affects_candidate_promotion": False,
        "numeric_score": None,
        "absence_semantics": (
            "not_observed means no typed target evidence was emitted for a passively "
            "observable signal while mapped collection was complete; it is not proof "
            "that the vulnerability behavior is absent. not_collected and unknown are "
            "never negative target evidence."
        ),
    }

    if persist:
        output = Path(ctx.run_dir) / "evidence-coverage.json"
        result["output"] = str(output)
        atomic_write_text(output, json_dumps(result, pretty=True) + "\n")
    return result
