from __future__ import annotations

"""Dedicated Business Logic analyzer with offline workflow mining.

Workflow keywords do not constitute a vulnerability. The analyzer combines the
current endpoint contract with an offline same-analysis workflow catalog and
explicit stored invariant/transition observations. Direct evidence is accepted
only for reversible, controlled test data with a documented expected invariant.
No workflow action is executed by this module.
"""

from typing import Any, Iterable, Mapping

from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import add_unique, finalize_result, list_value, observations, scalar, truth
from .workflow_intelligence import SERVER_VALUE_MARKERS, STATEFUL_METHODS, marker_set, mine_workflow_context


BUSINESS_LOGIC_FAMILY_ANALYZER_VERSION = "1.0.0"
BUSINESS_LOGIC_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

BUSINESS_LOGIC_TAXONOMY = {
    "owasp": ["A04:2021 Insecure Design", "Business Logic Security"],
    "wstg": ["WSTG-BUSL-01", "WSTG-BUSL-03", "WSTG-BUSL-06"],
    "cwe": ["CWE-841"],
    "related_cwe": ["CWE-837", "CWE-472", "CWE-602"],
}

BUSINESS_LOGIC_METHOD = (
    {
        "id": "BUSL-01-workflow-model",
        "basis": ["WSTG-BUSL-06", "CWE-841"],
        "principle": "Build an offline workflow model from related stored endpoints, state-changing methods and business markers before evaluating a single operation.",
    },
    {
        "id": "BUSL-02-server-invariants",
        "basis": ["WSTG-BUSL-01", "WSTG-BUSL-03"],
        "principle": "Identify values and transitions that must be server-controlled, such as price/amount/state/order, without assuming client-visible fields are overrideable.",
    },
    {
        "id": "BUSL-03-controlled-transition",
        "basis": ["WSTG-BUSL-06", "OWASP Business Logic Security Cheat Sheet"],
        "principle": "Direct evidence requires a documented expected invariant and a stored controlled observation using reversible test data showing an invalid transition or invariant violation.",
    },
    {
        "id": "BUSL-04-enforcement-contradictions",
        "basis": ["CWE-841"],
        "principle": "Observed workflow-state enforcement and rejection of invalid transitions are contradiction evidence on the relevant workflow path.",
    },
)

BUSINESS_LOGIC_FALSE_POSITIVE_CHECKS = (
    "Words such as checkout, coupon, order, refund, transfer, balance or confirm are workflow discovery markers only.",
    "A POST/PUT/PATCH/DELETE method proves statefulness, not a logic flaw.",
    "Client-visible price, quantity, amount or state fields do not prove the server trusts those values.",
    "Different workflow endpoints may legitimately permit different transitions; the expected state machine must be explicit.",
    "Direct evidence requires reversible test data and a controlled test context; real financial/user assets are outside this analyzer contract.",
    "Race conditions are a neighboring family and require concurrency/atomicity evidence; workflow misuse alone is not a race condition.",
)

BUSINESS_LOGIC_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-busl-06-workflow-circumvention",
        "source": "OWASP WSTG",
        "ref": "WSTG-BUSL-06 / Testing for the Circumvention of Work Flows",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows",
        "principle": "Applications should enforce required workflow steps, ordering and repetition limits rather than trusting client progression.",
        "signals": ["workflow_markers", "stateful_operation", "invalid_transition_accepted"],
    },
    {
        "id": "owasp-business-logic-security-state-machine",
        "source": "OWASP Cheat Sheet Series",
        "ref": "Business Logic Security Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html",
        "principle": "Security-relevant values should be re-derived server-side and workflows should be enforced as explicit state machines.",
        "signals": ["workflow_invariant_violation", "server_value_override_observed"],
    },
)


def _explicit_markers(details: Mapping[str, Any]) -> list[str]:
    values = list_value(details.get("workflow_markers"))
    if values:
        return sorted({str(value).strip().lower() for value in values if str(value).strip()})
    return []


def analyze_business_logic_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str,
    body_fields: Iterable[str] = (),
    query_fields: Iterable[str] = (),
    path_fields: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
    semantic_text: str = "",
) -> dict[str, Any] | None:
    details = dict(details or {})
    method = str(method or "UNKNOWN").upper()
    markers = set(_explicit_markers(details)) | marker_set(" ".join([endpoint, semantic_text]))
    fields = [str(value) for value in [*body_fields, *query_fields, *path_fields]]
    stateful = method in STATEFUL_METHODS or truth(details.get("stateful_operation")) is True
    workflow = mine_workflow_context(
        db,
        analysis_id=analysis_id,
        target=target,
        endpoint=endpoint,
        semantic_text=semantic_text,
    )
    catalog_markers = set(workflow.get("catalog_markers", []))
    if not markers and not catalog_markers and not observations(details, "workflow_observations", "business_logic_observations"):
        return None

    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    current_group = f"workflow_endpoint:{endpoint}:{method}"
    effective_markers = sorted(markers or catalog_markers)
    if effective_markers:
        add_unique(support, {
            "type": "workflow_markers", "source": "endpoint_semantics", "source_group": current_group, "weight": 14,
            "text": f"Business workflow markers are present: {', '.join(effective_markers[:8])}.",
        })
    if stateful:
        add_unique(support, {
            "type": "stateful_operation", "source": "endpoint_contract", "source_group": current_group, "weight": 14,
            "text": f"The workflow surface includes a state-changing {method} operation.",
        })

    if int(workflow.get("related_endpoint_count") or 0) >= 2 and len(catalog_markers) >= 2:
        add_unique(support, {
            "type": "workflow_sequence_context", "source": "offline_workflow_miner", "source_group": "workflow_sequence_catalog", "weight": 17,
            "text": f"Offline correlation links {workflow['related_endpoint_count']} stored endpoints into the same business-workflow marker cluster.",
        })
        if not effective_markers:
            add_unique(support, {
                "type": "workflow_markers", "source": "offline_workflow_miner", "source_group": "workflow_sequence_catalog", "weight": 14,
                "text": f"Related stored endpoints share workflow markers: {', '.join(sorted(catalog_markers)[:8])}.",
            })

    server_fields = sorted({field for field in workflow.get("server_value_fields", []) if field})
    for field in fields:
        lowered = field.lower().replace("-", "_")
        if lowered in SERVER_VALUE_MARKERS and lowered not in server_fields:
            server_fields.append(lowered)
    expected = details.get("workflow_model") or details.get("expected_invariant") or details.get("business_invariant")
    if expected:
        add_unique(support, {
            "type": "workflow_model_context", "source": "stored_business_policy", "source_group": "workflow_invariant_policy", "weight": 16,
            "text": "Stored target context documents an expected workflow invariant or allowed transition model.",
        })

    runtime = observations(details, "workflow_observations", "business_logic_observations", "workflow_runtime_observations")
    for index, obs in enumerate(runtime[:50]):
        controlled = truth(scalar(obs, ("controlled_test_context", "authorized_test_context"))) is True
        reversible = truth(scalar(obs, ("reversible_test_data", "test_owned_data", "safe_test_data"))) is True
        invariant_known = truth(scalar(obs, ("expected_invariant_documented", "workflow_model_documented", "expected_transition_documented"))) is True
        group = f"workflow_behavior_observation:{index}"
        if truth(scalar(obs, ("workflow_invariant_enforced", "workflow_state_enforced"))) is True:
            add_unique(contradict, {
                "type": "workflow_invariant_enforced", "source": "stored_workflow_observation", "source_group": group, "weight": -42,
                "text": "Stored controlled behavior shows the documented workflow invariant is enforced.",
            })
        if truth(scalar(obs, ("invalid_transition_rejected", "out_of_order_transition_rejected"))) is True:
            add_unique(contradict, {
                "type": "invalid_transition_rejected", "source": "stored_workflow_observation", "source_group": group, "weight": -42,
                "text": "Stored controlled behavior rejects an invalid or out-of-order test transition.",
            })
        if not (controlled and reversible and invariant_known):
            continue
        if truth(scalar(obs, ("workflow_invariant_violation", "business_invariant_violation"))) is True:
            add_unique(support, {
                "type": "workflow_invariant_violation", "source": "stored_controlled_workflow_behavior", "source_group": group, "weight": 58,
                "text": "A reversible controlled workflow action violates the documented server-side business invariant.",
            })
        if truth(scalar(obs, ("invalid_transition_accepted", "out_of_order_transition_accepted", "skipped_step_accepted"))) is True:
            add_unique(support, {
                "type": "invalid_transition_accepted", "source": "stored_controlled_workflow_behavior", "source_group": group, "weight": 56,
                "text": "Stored controlled behavior accepts an invalid, skipped or out-of-order workflow transition against the documented state model.",
            })
        server_controlled = truth(scalar(obs, ("server_value_expected_controlled", "server_calculated_value"))) is True
        if server_controlled and truth(scalar(obs, ("server_value_override_observed", "client_value_override_persisted"))) is True:
            add_unique(support, {
                "type": "server_value_override_observed", "source": "stored_controlled_workflow_behavior", "source_group": group, "weight": 58,
                "text": "Stored controlled behavior shows a value documented as server-controlled can be overridden by reversible test input.",
            })

    observed = {item["type"] for item in support}
    if "workflow_invariant_violation" in observed:
        variant = "workflow_invariant_violation"
    elif "invalid_transition_accepted" in observed:
        variant = "invalid_transition_accepted"
    elif "server_value_override_observed" in observed:
        variant = "server_value_override"
    elif "workflow_sequence_context" in observed or "workflow_model_context" in observed:
        variant = "workflow_sequence_potential"
    else:
        variant = "workflow_surface"

    return finalize_result(
        analyzer=BusinessLogicFamilyAnalyzer(),
        family="business_logic",
        variant=variant,
        support=support,
        contradict=contradict,
        taxonomy=BUSINESS_LOGIC_TAXONOMY,
        methodology=BUSINESS_LOGIC_METHOD,
        false_positive_checks=BUSINESS_LOGIC_FALSE_POSITIVE_CHECKS,
        writeup_patterns=BUSINESS_LOGIC_WRITEUP_PATTERNS,
        direct_types={"workflow_invariant_violation", "invalid_transition_accepted", "server_value_override_observed"},
        rule_ids=("family-business-workflow-model", "family-business-server-invariant", "family-business-controlled-transition"),
        summary="Business Logic hypothesis based on an offline workflow sequence model, server-side invariant context and stored reversible behavioral evidence.",
        base=18,
        extra_meta={
            "family_rule_version": BUSINESS_LOGIC_FAMILY_ANALYZER_RULE_VERSION,
            "workflow_intelligence": workflow,
            "server_value_fields": server_fields[:20],
            "runtime_observation_count": len(runtime),
            "workflow_actions_executed": False,
            "state_changing_request_performed": False,
        },
    )


class BusinessLogicFamilyAnalyzer(FamilyAnalyzer):
    family = "business_logic"
    analyzer_version = BUSINESS_LOGIC_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_business_logic_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            details=context.details,
            business_context=context.business_context,
            **kwargs,
        )
