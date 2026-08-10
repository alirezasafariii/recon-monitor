from __future__ import annotations

from pathlib import Path

path = Path("app/family_reasoners.py")
text = path.read_text(encoding="utf-8")

anchor = '''FAMILY_REASONER_PROFILES: dict[str, FamilyReasonerProfile] = {\n'''
if anchor not in text:
    raise SystemExit("profile registry anchor missing")

mapping = '''# Required identity groups before a family may participate in ranking when\n# decisive condition evidence is still absent. This prevents generic clues\n# (for example, merely having an input parameter) from mixing injection families.\nFAMILY_IDENTITY_GATES: dict[str, tuple[int, ...]] = {\n    "broken_object_authorization": (0, 1),\n    "broken_function_authorization": (0, 1),\n    "mass_assignment": (1,),\n    "authentication_session": (0,),\n    "account_enumeration": (0,),\n    "dom_xss": (0, 1),\n    "postmessage_trust": (0,),\n    "open_redirect": (0, 1),\n    "ssrf": (0,),\n    "file_upload": (0, 1),\n    "path_traversal": (0, 1),\n    "information_disclosure": (0,),\n    "graphql_authorization": (0, 1),\n    "graphql_data_exposure": (0, 1),\n    "websocket_authorization": (0, 1),\n    "cors_misconfiguration": (0,),\n    "sensitive_caching": (0, 1),\n    "business_logic": (0,),\n    "race_condition": (0, 1),\n    "sql_injection": (1,),\n    "nosql_injection": (1,),\n    "command_injection": (1,),\n    "server_side_template_injection": (1,),\n    "ldap_injection": (1,),\n    "unrestricted_resource_consumption": (0,),\n    "sensitive_business_flow_abuse": (0,),\n    "security_misconfiguration": (0,),\n    "improper_inventory_management": (0,),\n    "unsafe_api_consumption": (0,),\n    "source_map_exposure": (0,),\n    "secret_exposure": (0, 1),\n}\n\n\n'''
text = text.replace(anchor, mapping + anchor, 1)

old = '''    policy_families = set(FAMILY_ADMISSION_POLICIES)\n    profile_families = set(FAMILY_REASONER_PROFILES)\n    if policy_families != profile_families:\n'''
new = '''    policy_families = set(FAMILY_ADMISSION_POLICIES)\n    profile_families = set(FAMILY_REASONER_PROFILES)\n    gate_families = set(FAMILY_IDENTITY_GATES)\n    if policy_families != profile_families:\n'''
if old not in text:
    raise SystemExit("profile validation anchor missing")
text = text.replace(old, new, 1)

old = '''        errors.append(f"reasoner coverage mismatch missing={missing} extra={extra}")\n    for family, profile in FAMILY_REASONER_PROFILES.items():\n'''
new = '''        errors.append(f"reasoner coverage mismatch missing={missing} extra={extra}")\n    if policy_families != gate_families:\n        missing = sorted(policy_families - gate_families)\n        extra = sorted(gate_families - policy_families)\n        errors.append(f"identity-gate coverage mismatch missing={missing} extra={extra}")\n    for family, profile in FAMILY_REASONER_PROFILES.items():\n'''
if old not in text:
    raise SystemExit("coverage insertion anchor missing")
text = text.replace(old, new, 1)

old = '''        if family in profile.confounders:\n            errors.append(f"{family}: cannot confound with itself")\n    return errors\n'''
new = '''        if family in profile.confounders:\n            errors.append(f"{family}: cannot confound with itself")\n        gates = FAMILY_IDENTITY_GATES.get(family, ())\n        invalid_gates = [index for index in gates if index < 0 or index >= len(required)]\n        if invalid_gates:\n            errors.append(f"{family}: invalid identity gate indices {invalid_gates}")\n    return errors\n'''
if old not in text:
    raise SystemExit("gate validation anchor missing")
text = text.replace(old, new, 1)

old = '''    identity_groups = group_results[:-1]\n    identity_hits = sum(1 for row in identity_groups if row["hit"])\n    if not own_condition_present and identity_hits == 0:\n        score = 0.0\n\n    controls = list(assessment.get("blocking_contradictions") or [])\n'''
new = '''    identity_groups = group_results[:-1]\n    identity_hits = sum(1 for row in identity_groups if row["hit"])\n    identity_gate = FAMILY_IDENTITY_GATES[family]\n    identity_gate_satisfied = all(group_results[index]["hit"] for index in identity_gate)\n    if not own_condition_present and not identity_gate_satisfied:\n        score = 0.0\n\n    controls = list(assessment.get("blocking_contradictions") or [])\n'''
if old not in text:
    raise SystemExit("identity scoring anchor missing")
text = text.replace(old, new, 1)

old = '''        "identity_group_hits": identity_hits,\n        "condition_hits": condition_hits,\n'''
new = '''        "identity_group_hits": identity_hits,\n        "identity_gate": list(identity_gate),\n        "identity_gate_satisfied": identity_gate_satisfied,\n        "condition_hits": condition_hits,\n'''
if old not in text:
    raise SystemExit("result metadata anchor missing")
text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
