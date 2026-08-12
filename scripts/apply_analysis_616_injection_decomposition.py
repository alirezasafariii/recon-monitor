from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing replacement anchor in {path}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# Version lineage: execution/reconstruction semantics are unchanged; only candidate
# orchestration and physical collector ownership change in this phase.
replace_once(
    "app/bug_candidates.py",
    'CANDIDATE_ENGINE_VERSION = "6.14.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.14"',
    'CANDIDATE_ENGINE_VERSION = "6.16.0"\nCANDIDATE_RULE_VERSION = "2026.08.12.6.16"',
)
replace_once(
    "app/analysis_engine.py",
    'ENGINE_VERSION = "6.14.0"\nRULE_VERSION = "2026.08.12.6.14"',
    'ENGINE_VERSION = "6.16.0"\nRULE_VERSION = "2026.08.12.6.16"',
)
replace_once(
    "app/security_reasoning.py",
    'REASONING_ENGINE_VERSION = "6.14.0"\nREASONING_RULE_VERSION = "2026.08.12.6.14"',
    'REASONING_ENGINE_VERSION = "6.16.0"\nREASONING_RULE_VERSION = "2026.08.12.6.16"',
)

replace_once(
    "app/bug_candidates.py",
    'from family_detectors import detector_rule_ids, evaluate_family_detector, execute_detector_intelligence, execution_rule_ids\n',
    'from family_detectors import detector_rule_ids, evaluate_family_detector, execute_detector_intelligence, execution_rule_ids\nfrom raw_family_collectors import collect_injection_observations\n',
)

path = Path("app/bug_candidates.py")
text = path.read_text(encoding="utf-8")

# Physically route the five injection families through their dedicated collector
# contracts. emit() still merges the authoritative execution packet and applies the
# existing detector firewall, hidden-hypothesis ledger, admission gate, and candidate
# quality guard unchanged.
bola_marker = "    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.\n"
if bola_marker not in text:
    raise SystemExit("missing BOLA insertion marker")
injection_loop = '''    # Analysis 6.16 — physical raw collector ownership for server-side injection families.\n    # The collector contributes emission metadata only; target evidence is still owned\n    # by execute_detector_intelligence() and merged inside emit().\n    for observation in collect_injection_observations(execution_map):\n        emit(\n            observation.family,\n            observation.variant,\n            observation.base,\n            [],\n            [],\n            list(observation.missing),\n            list(observation.rules),\n            observation.summary,\n            direct=observation.direct,\n            impact=observation.impact,\n        )\n\n'''
text = text.replace(bola_marker, injection_loop + bola_marker, 1)

# Delete the physically duplicated legacy SQL/NoSQL/Command/SSTI/LDAP collector block.
start_marker = "    # Analysis 6.1 — OWASP A03 Injection coverage. Surface clues remain hidden\n"
end_marker = "    # API4:2023 — resource consumption.\n"
start = text.find(start_marker)
end = text.find(end_marker, start + 1)
if start < 0 or end < 0 or end <= start:
    raise SystemExit("could not locate legacy injection collector block")
replacement = '''    # Analysis 6.16: SQL/NoSQL/Command/SSTI/LDAP legacy collection was physically\n    # removed from this orchestrator. Dedicated raw_family_collectors now own emission\n    # metadata while detector execution/reconstruction owns all target evidence.\n\n'''
text = text[:start] + replacement + text[end:]
path.write_text(text, encoding="utf-8")

print("Analysis 6.16 injection collector decomposition applied")
