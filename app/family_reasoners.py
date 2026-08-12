from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission
from family_evidence_extractors import filter_evidence_for_family

FAMILY_REASONER_VERSION = "1.1.0"
FAMILY_REASONER_RULE_VERSION = "2026.08.10.6.8"


@dataclass(frozen=True)
class FamilyReasonerProfile:
    question: str
    group_weights: tuple[float, ...]
    confounders: tuple[str, ...] = ()
    source_weight: float = 0.08
    admission_bonus: float = 0.12
    confounder_penalty: float = 0.18


# Every family owns an explicit analytical question, evidence weighting, and
# confusion boundary. The weights are intentionally not inferred from a shared
# vulnerability class: they encode what is identity-defining for that family.
# Required identity groups before a family may participate in ranking when
# decisive condition evidence is still absent. This prevents generic clues
# (for example, merely having an input parameter) from mixing injection families.
FAMILY_IDENTITY_GATES: dict[str, tuple[int, ...]] = {
    "broken_object_authorization": (0, 1),
    "broken_function_authorization": (0, 1),
    "mass_assignment": (1,),
    "authentication_session": (0,),
    "account_enumeration": (0,),
    "dom_xss": (0, 1),
    "postmessage_trust": (0,),
    "open_redirect": (0, 1),
    "ssrf": (0,),
    "file_upload": (0, 1),
    "path_traversal": (0, 1),
    "information_disclosure": (0,),
    "graphql_authorization": (0, 1),
    "graphql_data_exposure": (0, 1),
    "websocket_authorization": (0, 1),
    "cors_misconfiguration": (0,),
    "sensitive_caching": (0, 1),
    "business_logic": (0,),
    "race_condition": (0, 1),
    "sql_injection": (1,),
    "nosql_injection": (1,),
    "command_injection": (1,),
    "server_side_template_injection": (1,),
    "ldap_injection": (1,),
    "unrestricted_resource_consumption": (0,),
    "sensitive_business_flow_abuse": (0,),
    "security_misconfiguration": (0,),
    "improper_inventory_management": (0,),
    "unsafe_api_consumption": (0,),
    "source_map_exposure": (0,),
    "secret_exposure": (0, 1),
    "software_supply_chain_failure": (0,),
    "cryptographic_failure": (0,),
    "software_data_integrity_failure": (0,),
    "security_logging_alerting_failure": (0,),
    "exceptional_condition_mishandling": (0,),
}


FAMILY_REASONER_PROFILES: dict[str, FamilyReasonerProfile] = {
    "broken_object_authorization": FamilyReasonerProfile(
        "Can this caller operate on this specific object despite an object/tenant ownership boundary?",
        (0.22, 0.24, 0.34),
        ("broken_function_authorization", "mass_assignment", "graphql_authorization"),
        confounder_penalty=0.20,
    ),
    "broken_function_authorization": FamilyReasonerProfile(
        "Can a lower-privileged caller execute a function reserved for a stronger role?",
        (0.26, 0.22, 0.32),
        ("broken_object_authorization", "business_logic", "mass_assignment"),
        confounder_penalty=0.20,
    ),
    "mass_assignment": FamilyReasonerProfile(
        "Can the caller write a privileged object property that should not be client-writable?",
        (0.18, 0.30, 0.32),
        ("broken_object_authorization", "broken_function_authorization", "business_logic"),
        confounder_penalty=0.20,
    ),
    "authentication_session": FamilyReasonerProfile(
        "Does authentication or session lifecycle validation fail at the identity boundary?",
        (0.30, 0.50),
        ("account_enumeration", "secret_exposure", "information_disclosure"),
    ),
    "account_enumeration": FamilyReasonerProfile(
        "Can an observer distinguish whether a tested account identity exists?",
        (0.34, 0.46),
        ("authentication_session", "information_disclosure"),
    ),
    "dom_xss": FamilyReasonerProfile(
        "Does attacker-controlled browser data reach an executable DOM sink without an effective sanitizer?",
        (0.22, 0.24, 0.34),
        ("postmessage_trust", "open_redirect"),
        confounder_penalty=0.20,
    ),
    "postmessage_trust": FamilyReasonerProfile(
        "Can an attacker-controlled cross-window message trigger sensitive behavior without strict message trust validation?",
        (0.24, 0.24, 0.32),
        ("dom_xss", "open_redirect"),
        confounder_penalty=0.20,
    ),
    "open_redirect": FamilyReasonerProfile(
        "Can attacker-controlled navigation leave the intended origin/domain boundary?",
        (0.20, 0.24, 0.36),
        ("ssrf", "dom_xss"),
        confounder_penalty=0.22,
    ),
    "ssrf": FamilyReasonerProfile(
        "Can attacker-controlled destination data cause the server itself to make an outbound request?",
        (0.28, 0.52),
        ("open_redirect", "unsafe_api_consumption"),
        confounder_penalty=0.22,
    ),
    "file_upload": FamilyReasonerProfile(
        "Does a real upload/import operation accept or store a file in an unsafe way?",
        (0.18, 0.24, 0.38),
        ("path_traversal", "unsafe_api_consumption"),
        confounder_penalty=0.22,
    ),
    "path_traversal": FamilyReasonerProfile(
        "Can attacker-controlled path material escape the intended filesystem confinement during a file operation?",
        (0.20, 0.24, 0.36),
        ("file_upload",),
        confounder_penalty=0.22,
    ),
    "information_disclosure": FamilyReasonerProfile(
        "Is genuinely sensitive/debug information exposed to a public or unintended authorization context?",
        (0.32, 0.48),
        ("secret_exposure", "source_map_exposure", "security_misconfiguration", "graphql_data_exposure"),
        confounder_penalty=0.20,
    ),
    "graphql_authorization": FamilyReasonerProfile(
        "Does a GraphQL resolver/object operation cross an object or role authorization boundary?",
        (0.20, 0.22, 0.38),
        ("graphql_data_exposure", "broken_object_authorization", "broken_function_authorization"),
        confounder_penalty=0.20,
    ),
    "graphql_data_exposure": FamilyReasonerProfile(
        "Does the current GraphQL role actually receive sensitive fields outside its field policy?",
        (0.18, 0.24, 0.38),
        ("graphql_authorization", "information_disclosure", "mass_assignment"),
        confounder_penalty=0.20,
    ),
    "websocket_authorization": FamilyReasonerProfile(
        "Can a caller subscribe to or receive messages from a WebSocket channel outside its identity scope?",
        (0.20, 0.24, 0.36),
        ("broken_object_authorization", "graphql_authorization", "broken_function_authorization"),
        confounder_penalty=0.20,
    ),
    "cors_misconfiguration": FamilyReasonerProfile(
        "Does an unsafe CORS origin policy expose credentialed or sensitive cross-origin data?",
        (0.30, 0.50),
        ("information_disclosure", "security_misconfiguration"),
        confounder_penalty=0.20,
    ),
    "sensitive_caching": FamilyReasonerProfile(
        "Can a shared cache reuse a sensitive/authenticated response without the required isolation key?",
        (0.20, 0.24, 0.36),
        ("information_disclosure", "security_misconfiguration"),
        confounder_penalty=0.20,
    ),
    "business_logic": FamilyReasonerProfile(
        "Does the server accept a workflow, value, or state transition that violates the intended business invariant?",
        (0.26, 0.54),
        ("race_condition", "sensitive_business_flow_abuse", "broken_function_authorization"),
        confounder_penalty=0.20,
    ),
    "race_condition": FamilyReasonerProfile(
        "Does concurrent execution break a single-use, balance, uniqueness, or atomicity invariant?",
        (0.16, 0.22, 0.42),
        ("business_logic", "sensitive_business_flow_abuse"),
        confounder_penalty=0.22,
    ),
    "sql_injection": FamilyReasonerProfile(
        "Does user input alter SQL query structure, execution semantics, errors, booleans, or database timing?",
        (0.10, 0.28, 0.42),
        ("nosql_injection", "ldap_injection", "command_injection", "server_side_template_injection"),
        confounder_penalty=0.24,
    ),
    "nosql_injection": FamilyReasonerProfile(
        "Does structured user input become a NoSQL operator or alter a document-query result?",
        (0.10, 0.30, 0.40),
        ("sql_injection", "ldap_injection"),
        confounder_penalty=0.24,
    ),
    "command_injection": FamilyReasonerProfile(
        "Does user input influence operating-system/process execution and produce a command-specific effect?",
        (0.10, 0.28, 0.42),
        ("server_side_template_injection", "sql_injection"),
        confounder_penalty=0.24,
    ),
    "server_side_template_injection": FamilyReasonerProfile(
        "Is attacker-controlled template syntax evaluated by a server-side template/expression engine?",
        (0.10, 0.28, 0.42),
        ("command_injection", "dom_xss", "sql_injection"),
        confounder_penalty=0.24,
    ),
    "ldap_injection": FamilyReasonerProfile(
        "Does user input change an LDAP filter/search/authentication operation?",
        (0.10, 0.30, 0.40),
        ("sql_injection", "nosql_injection"),
        confounder_penalty=0.24,
    ),
    "unrestricted_resource_consumption": FamilyReasonerProfile(
        "Can a caller amplify size, frequency, processing time, provider cost, or resource use without an effective limit?",
        (0.24, 0.56),
        ("sensitive_business_flow_abuse", "race_condition"),
        confounder_penalty=0.20,
    ),
    "sensitive_business_flow_abuse": FamilyReasonerProfile(
        "Can a sensitive business flow be automated or repeated beyond the intended per-user/business restriction?",
        (0.30, 0.50),
        ("unrestricted_resource_consumption", "business_logic", "race_condition"),
        confounder_penalty=0.20,
    ),
    "security_misconfiguration": FamilyReasonerProfile(
        "Is an insecure deployment/application configuration directly observable rather than merely inferred?",
        (0.28, 0.52),
        ("information_disclosure", "cors_misconfiguration", "improper_inventory_management"),
        confounder_penalty=0.18,
    ),
    "improper_inventory_management": FamilyReasonerProfile(
        "Is a legacy, undocumented, retired, or non-production API surface still active with security-relevant drift?",
        (0.30, 0.50),
        ("security_misconfiguration",),
        confounder_penalty=0.18,
    ),
    "unsafe_api_consumption": FamilyReasonerProfile(
        "Does trusting an upstream/third-party API create an unsafe transport, validation, redirect, auth, or resource boundary?",
        (0.30, 0.50),
        ("ssrf", "unrestricted_resource_consumption"),
        confounder_penalty=0.22,
    ),
    "source_map_exposure": FamilyReasonerProfile(
        "Is a meaningful source map publicly reachable and does it disclose actual internal source content?",
        (0.18, 0.28, 0.34),
        ("information_disclosure", "secret_exposure"),
        confounder_penalty=0.18,
    ),
    "secret_exposure": FamilyReasonerProfile(
        "Is non-placeholder credential material exposed in a production client/runtime context?",
        (0.18, 0.20, 0.42),
        ("information_disclosure", "source_map_exposure", "authentication_session"),
        confounder_penalty=0.20,
    ),
    "software_supply_chain_failure": FamilyReasonerProfile(
        "Does a deployed dependency, artifact, registry, or privileged build path rely on a vulnerable, unmaintained, untrusted, or compromised supply-chain component?",
        (0.30, 0.50),
        ("unsafe_api_consumption", "improper_inventory_management", "software_data_integrity_failure", "security_misconfiguration"),
        confounder_penalty=0.22,
    ),
    "cryptographic_failure": FamilyReasonerProfile(
        "Does a security-sensitive cryptographic or transport boundary actually use weak, predictable, reused, downgraded, or plaintext protection?",
        (0.30, 0.50),
        ("security_misconfiguration", "authentication_session", "secret_exposure", "sensitive_caching"),
        confounder_penalty=0.20,
    ),
    "software_data_integrity_failure": FamilyReasonerProfile(
        "Does untrusted code, update material, or serialized data cross an integrity boundary without effective authenticity/integrity verification?",
        (0.28, 0.52),
        ("software_supply_chain_failure", "mass_assignment", "command_injection", "unsafe_api_consumption"),
        confounder_penalty=0.22,
    ),
    "security_logging_alerting_failure": FamilyReasonerProfile(
        "Do stored logging, telemetry, or configuration artifacts show that a security event is missed, unsafe to log, not alerted, or not integrity-protected?",
        (0.30, 0.50),
        ("information_disclosure", "security_misconfiguration", "exceptional_condition_mishandling"),
        confounder_penalty=0.20,
    ),
    "exceptional_condition_mishandling": FamilyReasonerProfile(
        "Does an exceptional condition produce an unsafe fail-open, crash, state corruption, partial commit, or control-bypass outcome?",
        (0.28, 0.52),
        ("information_disclosure", "security_misconfiguration", "business_logic", "race_condition", "security_logging_alerting_failure"),
        confounder_penalty=0.22,
    ),
}


def _profile_errors() -> list[str]:
    errors: list[str] = []
    policy_families = set(FAMILY_ADMISSION_POLICIES)
    profile_families = set(FAMILY_REASONER_PROFILES)
    gate_families = set(FAMILY_IDENTITY_GATES)
    if policy_families != profile_families:
        missing = sorted(policy_families - profile_families)
        extra = sorted(profile_families - policy_families)
        errors.append(f"reasoner coverage mismatch missing={missing} extra={extra}")
    if policy_families != gate_families:
        missing = sorted(policy_families - gate_families)
        extra = sorted(gate_families - policy_families)
        errors.append(f"identity-gate coverage mismatch missing={missing} extra={extra}")
    for family, profile in FAMILY_REASONER_PROFILES.items():
        required = FAMILY_ADMISSION_POLICIES[family].get("required", [])
        if len(profile.group_weights) != len(required):
            errors.append(
                f"{family}: group_weights={len(profile.group_weights)} required_groups={len(required)}"
            )
        total = sum(profile.group_weights) + profile.source_weight + profile.admission_bonus
        if abs(total - 1.0) > 1e-9:
            errors.append(f"{family}: reasoner weights must sum to 1.0, got {total:.6f}")
        unknown = sorted(set(profile.confounders) - policy_families)
        if unknown:
            errors.append(f"{family}: unknown confounders {unknown}")
        if family in profile.confounders:
            errors.append(f"{family}: cannot confound with itself")
        gates = FAMILY_IDENTITY_GATES.get(family, ())
        invalid_gates = [index for index in gates if index < 0 or index >= len(required)]
        if invalid_gates:
            errors.append(f"{family}: invalid identity gate indices {invalid_gates}")
    return errors


_PROFILE_ERRORS = _profile_errors()
if _PROFILE_ERRORS:
    raise RuntimeError("Family reasoner registry is invalid: " + "; ".join(_PROFILE_ERRORS))


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def _signal_types(items: Iterable[Mapping[str, Any]]) -> set[str]:
    return {str(item.get("type") or "").strip() for item in items if str(item.get("type") or "").strip()}


def _policy_support_signals(family: str) -> set[str]:
    policy = FAMILY_ADMISSION_POLICIES[family]
    result: set[str] = set()
    for group in policy.get("required", []):
        result.update(str(value) for value in group)
    result.update(str(value) for value in policy.get("override_signals", set()))
    return result


def _policy_control_signals(family: str) -> set[str]:
    return {str(value) for value in FAMILY_ADMISSION_POLICIES[family].get("blocking_contradictions", set())}


def _evidence_source_key(item: Mapping[str, Any]) -> str:
    group = str(item.get("source_group") or "").strip()
    if group:
        return f"group:{group}"
    source = str(item.get("source") or "").strip()
    if source:
        return f"source:{source}"
    return ""


def _scoped_source_count(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]],
) -> tuple[int, int]:
    recognized = _policy_support_signals(family) | _policy_control_signals(family)
    scoped: set[str] = set()
    unscoped = 0
    for item in [*support, *contradict]:
        signal = str(item.get("type") or "").strip()
        key = _evidence_source_key(item)
        if signal in recognized:
            if key:
                scoped.add(key)
        elif signal:
            unscoped += 1
    return len(scoped), unscoped


def condition_confidence(assessment: Mapping[str, Any]) -> float:
    if assessment.get("admitted"):
        return 0.96
    state = str(assessment.get("state") or "")
    if state == "shadow_contradicted":
        return 0.04
    satisfied = len(assessment.get("required_satisfied") or [])
    missing = len(assessment.get("required_missing") or [])
    coverage = satisfied / max(1, satisfied + missing)
    if state == "shadow_partial":
        return round(min(0.28, 0.06 + 0.24 * coverage), 6)
    return 0.04


def _confounder_evidence(family: str, observed_support: set[str]) -> list[dict[str, Any]]:
    profile = FAMILY_REASONER_PROFILES[family]
    rows: list[dict[str, Any]] = []
    for other in profile.confounders:
        required = FAMILY_ADMISSION_POLICIES[other].get("required", [])
        condition_group = set(required[-1]) if required else set()
        hits = sorted(observed_support & condition_group)
        if hits:
            rows.append({"family": other, "condition_hits": hits})
    return rows


def reason_family(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if family not in FAMILY_REASONER_PROFILES:
        raise KeyError(f"unknown family reasoner: {family}")

    support_items = filter_evidence_for_family(family, support)
    contradict_items = filter_evidence_for_family(family, contradict or [])
    support_types = _signal_types(support_items)
    profile = FAMILY_REASONER_PROFILES[family]
    policy = FAMILY_ADMISSION_POLICIES[family]
    required = list(policy.get("required", []))
    assessment = assess_admission(family, support_items, contradict_items)

    group_results: list[dict[str, Any]] = []
    weighted_coverage = 0.0
    for index, group in enumerate(required):
        hits = sorted(support_types & set(group))
        hit = bool(hits)
        weight = float(profile.group_weights[index])
        if hit:
            weighted_coverage += weight
        group_results.append({
            "index": index,
            "role": "condition" if index == len(required) - 1 else "identity",
            "weight": round(weight, 6),
            "hit": hit,
            "hits": hits,
        })

    condition_hits = group_results[-1]["hits"] if group_results else []
    own_condition_present = bool(condition_hits)
    confounder_rows = _confounder_evidence(family, support_types)
    confounder_penalty = 0.0
    if confounder_rows and not own_condition_present:
        confounder_penalty = float(profile.confounder_penalty)

    scoped_sources, unscoped_evidence_count = _scoped_source_count(
        family, support_items, contradict_items
    )
    required_sources = max(1, int(policy.get("min_independent_sources", 1)))
    source_ratio = min(1.0, scoped_sources / required_sources)

    score = weighted_coverage + profile.source_weight * source_ratio
    if assessment.get("admitted"):
        score += profile.admission_bonus
    score -= confounder_penalty
    score = _clamp(score)

    identity_groups = group_results[:-1]
    identity_hits = sum(1 for row in identity_groups if row["hit"])
    identity_gate = FAMILY_IDENTITY_GATES[family]
    identity_gate_satisfied = all(group_results[index]["hit"] for index in identity_gate)
    if not own_condition_present and not identity_gate_satisfied:
        score = 0.0

    controls = list(assessment.get("blocking_contradictions") or [])
    return {
        "family": family,
        "primary_question": profile.question,
        "family_fit_score": round(score, 6),
        "score": round(score, 6),
        "weighted_group_coverage": round(weighted_coverage, 6),
        "group_results": group_results,
        "identity_group_hits": identity_hits,
        "identity_gate": list(identity_gate),
        "identity_gate_satisfied": identity_gate_satisfied,
        "condition_hits": condition_hits,
        "condition_confidence": condition_confidence(assessment),
        "control_evidence": controls,
        "confounder_evidence": confounder_rows,
        "confounder_penalty": round(confounder_penalty, 6),
        "scoped_independent_sources": scoped_sources,
        "unscoped_evidence_count": unscoped_evidence_count,
        "source_ratio": round(source_ratio, 6),
        "assessment": assessment,
        "family_reasoner_version": FAMILY_REASONER_VERSION,
        "family_reasoner_rule_version": FAMILY_REASONER_RULE_VERSION,
    }


def rank_with_family_reasoners(
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in (contradict or [])]
    rows = [
        reason_family(family, support_items, contradict_items)
        for family in FAMILY_ADMISSION_POLICIES
    ]
    rows.sort(
        key=lambda item: (
            float(item["family_fit_score"]),
            bool(item["assessment"].get("admitted")),
            len(item.get("condition_hits") or []),
            int(item.get("identity_group_hits") or 0),
            float(item.get("source_ratio") or 0.0),
            str(item["family"]),
        ),
        reverse=True,
    )
    return rows
