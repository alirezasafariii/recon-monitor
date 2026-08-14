from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"expected patch anchor missing in {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_admission() -> None:
    path = "app/hypothesis_admission.py"
    old = '''    source_ok = len(sources) >= int(policy.get("min_independent_sources", 1))
    blocking = sorted(set(policy.get("blocking_contradictions", set())) & contradiction_types)
    override = bool(set(policy.get("override_signals", set())) & types)
    blocked = bool(blocking) and not override
    complete = not missing and source_ok and not blocked
'''
    new = '''    required_sources = int(policy.get("min_independent_sources", 1))
    source_ok_by_count = len(sources) >= required_sources
    condition_group = set(policy.get("required", [])[-1]) if policy.get("required") else set()
    decisive_condition_types = condition_group | set(policy.get("override_signals", set()))
    direct_decisive_observation = any(
        str(item.get("type") or "") in decisive_condition_types
        and bool(item.get("direct") or item.get("analysis_632_reconstruction"))
        and str(item.get("source") or "") not in {"knowledge", "standards", "writeup", "owasp", "wstg", "cwe"}
        for item in support_items
    )
    # Analysis 6.32: one direct stored observation may satisfy the source gate
    # only after every required family group is present. Surface/semantic-only
    # evidence still requires the configured multi-source corroboration.
    single_direct_observation_override = bool(not missing and direct_decisive_observation)
    source_ok = source_ok_by_count or single_direct_observation_override
    blocking = sorted(set(policy.get("blocking_contradictions", set())) & contradiction_types)
    override = bool(set(policy.get("override_signals", set())) & types)
    blocked = bool(blocking) and not override
    complete = not missing and source_ok and not blocked
'''
    replace(path, old, new)
    old = '''        "independent_sources": len(sources),
        "decisive_signals": sorted(decisive),
        "blocking_contradictions": blocking,
'''
    new = '''        "independent_sources": len(sources),
        "required_independent_sources": required_sources,
        "source_ok_by_count": source_ok_by_count,
        "direct_decisive_observation": direct_decisive_observation,
        "single_direct_observation_override": single_direct_observation_override,
        "decisive_signals": sorted(decisive),
        "blocking_contradictions": blocking,
'''
    replace(path, old, new)


def patch_execution() -> None:
    path = "app/family_detectors/execution.py"
    replace(path, 'from raw_condition_reconstruction import reconstruct_raw_evidence\n', 'from raw_condition_reconstruction import reconstruct_raw_evidence\nfrom analysis_632_evidence import reconstruct_asserted_evidence\n')
    old = '''    for family, packet in reconstructed.items():
        target_packet = _packet_for(result, family)
        for side in ("support", "contradict"):
            for item in packet.get(side) or []:
                _add(target_packet, side, dict(item))
    return {family: packet for family, packet in result.items() if packet["support"] or packet["contradict"]}
'''
    new = '''    for family, packet in reconstructed.items():
        target_packet = _packet_for(result, family)
        for side in ("support", "contradict"):
            for item in packet.get(side) or []:
                _add(target_packet, side, dict(item))
    asserted = reconstruct_asserted_evidence(
        target=str(target or ""), endpoint=str(endpoint or ""), method=str(method or "UNKNOWN"),
        endpoint_schema=endpoint_schema, details=details, category=str(category or ""),
        business_context=str(business_context or "general"),
    )
    for family, packet in asserted.items():
        target_packet = _packet_for(result, family)
        for side in ("support", "contradict"):
            for item in packet.get(side) or []:
                _add(target_packet, side, dict(item))
    return {family: packet for family, packet in result.items() if packet["support"] or packet["contradict"]}
'''
    replace(path, old, new)


def patch_reasoning() -> None:
    path = "app/security_reasoning.py"
    replace(path, 'from security_family_ranker import production_family_rankings\n', 'from security_family_ranker import production_family_rankings\nfrom researcher_logic import researcher_logic_for_family\n')
    old = '''            "knowledge_context": {"role": "detection_guidance_only_not_target_evidence", "references": knowledge_for_family(family)},
            "scores": {
'''
    new = '''            "researcher_logic": researcher_logic_for_family(family),
            "knowledge_context": {
                "role": "reasoning_guidance_only_not_target_evidence",
                "reference_count": len(knowledge_for_family(family)),
                "provenance_hidden_from_normal_reasoning": True,
            },
            "scores": {
'''
    replace(path, old, new)


def main() -> None:
    patch_admission()
    patch_execution()
    patch_reasoning()
    print("Analysis 6.32 safe production calibration patch applied")


if __name__ == "__main__":
    main()
