from __future__ import annotations

"""Evidence-preserving helpers for OWASP expansion phase 1.

No helper in this module sends traffic, generates attack payloads, executes a
command/query/template, or turns OWASP knowledge into target evidence. It only
normalizes already-collected endpoint metadata and authorized stored
observations into the canonical Family Reasoning vocabulary.
"""

import re
from typing import Any, Iterable, Mapping, Sequence

from .remaining_common import add_unique, finalize_result, observations, scalar, truth


def _fields(*groups: Iterable[str]) -> list[str]:
    result: list[str] = []
    for group in groups:
        for value in group:
            text = str(value or "").strip()
            if text and text not in result:
                result.append(text)
    return result


def _has_keyword(text: str, keywords: Sequence[str]) -> list[str]:
    lowered = str(text or "").lower()
    return [word for word in keywords if word.lower() in lowered]


def _flag(details: Mapping[str, Any], *keys: str) -> bool:
    return any(truth(details.get(key)) is True for key in keys)


def _controlled_benign(obs: Mapping[str, Any]) -> bool:
    controlled = truth(scalar(obs, ("controlled_test_context", "authorized_test_context", "controlled_observation"))) is True
    benign = truth(scalar(obs, ("benign_test_marker", "safe_test_marker", "non_destructive_test", "harmless_test"))) is True
    return bool(controlled and benign)


def analyze_injection_family(*, analyzer: Any, family: str, variant: str, endpoint: str, method: str,
    body_fields: Iterable[str], query_fields: Iterable[str], path_fields: Iterable[str], details: Mapping[str, Any] | None,
    semantic_text: str, input_type: str, sink_type: str, input_keywords: Sequence[str], sink_keywords: Sequence[str],
    unsafe_types: Sequence[str], direct_types: Sequence[str], contradiction_types: Sequence[str], observation_keys: Sequence[str],
    taxonomy: Mapping[str, Sequence[str]], methodology: Sequence[Mapping[str, Any]], false_positive_checks: Sequence[str],
    writeup_patterns: Sequence[Mapping[str, Any]], rule_ids: Sequence[str], summary: str, base: int) -> dict[str, Any] | None:
    del method
    details = dict(details or {})
    fields = _fields(body_fields, query_fields, path_fields)
    field_text = " ".join(fields)
    all_text = " ".join((str(endpoint or ""), str(semantic_text or ""), field_text)).lower()
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []

    if _has_keyword(field_text, input_keywords) or _flag(details, input_type, f"{family}_input", "user_controlled_input"):
        add_unique(support, {"type": input_type, "source": "request_schema", "source_group": "request_schema", "weight": 16,
            "text": f"Structured or explicitly tagged user input is present for {family} analysis."})
    if _has_keyword(all_text, sink_keywords) or _flag(details, sink_type, f"{family}_sink", "server_interpreter_sink"):
        add_unique(support, {"type": sink_type, "source": "server_sink_context", "source_group": "server_sink_context", "weight": 18,
            "text": f"Collected server-side context indicates a relevant interpreter/query sink for {family}."})

    for evidence_type in unsafe_types:
        if _flag(details, evidence_type):
            add_unique(support, {"type": evidence_type, "source": "stored_code_or_behavior", "source_group": "stored_code_or_behavior", "weight": 28,
                "text": f"Stored target evidence records {evidence_type.replace('_', ' ')}."})
    for evidence_type in contradiction_types:
        if _flag(details, evidence_type):
            add_unique(contradict, {"type": evidence_type, "source": "stored_enforcement_evidence", "source_group": "stored_enforcement_evidence", "weight": -44,
                "text": f"Stored target evidence records {evidence_type.replace('_', ' ')}."})

    runtime = observations(details, *observation_keys)
    for index, obs in enumerate(runtime[:50]):
        group = f"controlled_injection_observation:{index}"
        for evidence_type in contradiction_types:
            if truth(scalar(obs, (evidence_type,))) is True:
                add_unique(contradict, {"type": evidence_type, "source": "stored_controlled_observation", "source_group": group, "weight": -48,
                    "text": f"Stored behavior demonstrates {evidence_type.replace('_', ' ')}."})
        if not _controlled_benign(obs):
            continue
        for evidence_type in direct_types:
            if truth(scalar(obs, (evidence_type,))) is True:
                add_unique(support, {"type": evidence_type, "source": "stored_controlled_observation", "source_group": group, "weight": 60,
                    "text": f"A benign controlled stored observation demonstrates {evidence_type.replace('_', ' ')}."})

    if not support and not contradict:
        return None
    observed = {str(item.get("type") or "") for item in support}
    decisive = next((item for item in direct_types if item in observed), "")
    resolved_variant = decisive or (variant if input_type in observed and sink_type in observed else f"{variant}_surface")
    return finalize_result(analyzer=analyzer, family=family, variant=resolved_variant, support=support, contradict=contradict,
        taxonomy=taxonomy, methodology=methodology, false_positive_checks=false_positive_checks, writeup_patterns=writeup_patterns,
        direct_types=set(direct_types), rule_ids=rule_ids, summary=summary, base=base,
        extra_meta={"runtime_observation_count": len(runtime), "payload_generated": False, "active_request_performed": False,
            "dangerous_payload_used": False, "state_changing_action_performed": False})


def controlled_observation(obs: Mapping[str, Any], *, reversible: bool = False, bounded: bool = False) -> bool:
    if truth(scalar(obs, ("controlled_test_context", "authorized_test_context"))) is not True:
        return False
    if reversible and truth(scalar(obs, ("reversible_test_data", "test_owned_data", "safe_test_data"))) is not True:
        return False
    if bounded:
        if truth(scalar(obs, ("bounded_test", "bounded_observation"))) is not True:
            return False
        if truth(scalar(obs, ("within_authorized_budget", "within_resource_budget"))) is not True:
            return False
    return True
