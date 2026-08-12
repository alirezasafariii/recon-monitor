from __future__ import annotations

"""Dedicated Race Condition / Duplicate Operation analyzer.

The analyzer is offline. It identifies single-use or balance/state-changing
workflow semantics and consumes only already-stored concurrency/atomicity
observations. It never launches concurrent requests. Direct evidence requires
explicit authorization for the prior concurrency test plus test-owned resources.
"""

from typing import Any, Iterable, Mapping

from core import Database
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import add_unique, finalize_result, observations, scalar, truth
from .workflow_intelligence import SINGLE_USE_MARKERS, STATEFUL_METHODS, marker_set, mine_workflow_context


RACE_CONDITION_FAMILY_ANALYZER_VERSION = "1.0.0"
RACE_CONDITION_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

RACE_CONDITION_TAXONOMY = {
    "owasp": ["A04:2021 Insecure Design", "Business Logic Security"],
    "wstg": ["WSTG-BUSL-04", "WSTG-BUSL-05"],
    "cwe": ["CWE-362"],
    "related_cwe": ["CWE-367", "CWE-837", "CWE-841"],
    "capec": ["CAPEC-26", "CAPEC-29"],
}

RACE_CONDITION_METHOD = (
    {
        "id": "RACE-01-single-use-surface",
        "basis": ["WSTG-BUSL-05", "CWE-837"],
        "principle": "Identify operations intended to be single-use, limited, balance-changing or reservation-like without assuming repeatability or a race window.",
    },
    {
        "id": "RACE-02-critical-section-model",
        "basis": ["CWE-362", "OWASP Business Logic Security Cheat Sheet"],
        "principle": "Model check-then-act, idempotency and atomicity expectations from stored workflow context before considering concurrency evidence.",
    },
    {
        "id": "RACE-03-authorized-concurrency-evidence",
        "basis": ["CWE-362", "WSTG-BUSL-04"],
        "principle": "Direct evidence is accepted only from an already-authorized stored concurrency observation involving test-owned resources; the analyzer never creates concurrency itself.",
    },
    {
        "id": "RACE-04-controls",
        "basis": ["CWE-362"],
        "principle": "Observed idempotency enforcement or atomic state transition behavior is contradiction evidence on the relevant operation.",
    },
)

RACE_CONDITION_FALSE_POSITIVE_CHECKS = (
    "Redeem, claim, transfer, refund, booking, reserve or confirm semantics are watchlist signals only.",
    "A missing idempotency-key field in client code does not prove a race condition; servers can enforce uniqueness or transactions internally.",
    "Repeated sequential success is not automatically a race condition unless the operation is documented as single-use or state-limited.",
    "Direct evidence requires a prior explicitly authorized concurrency test using test-owned resources; this analyzer never launches parallel requests.",
    "Rate-limit behavior is not the same as atomicity or idempotency enforcement.",
    "Business Logic workflow bypass is neighboring evidence but does not confirm concurrent execution or a non-atomic critical section.",
)

RACE_CONDITION_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-busl-05-function-use-limits",
        "source": "OWASP WSTG",
        "ref": "WSTG-BUSL-05 / Test Number of Times a Function Can Be Used Limits",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits",
        "principle": "Security-relevant functions may require strict usage limits or single-use enforcement.",
        "signals": ["single_use_semantics", "duplicate_operation_observed"],
    },
    {
        "id": "cwe-362-shared-resource-race",
        "source": "MITRE CWE",
        "ref": "CWE-362 / Race Condition",
        "url": "https://cwe.mitre.org/data/definitions/362.html",
        "principle": "A race exists when a security-relevant critical sequence lacks required exclusivity or atomicity over shared state.",
        "signals": ["stateful_operation", "non_atomic_transition_observed"],
    },
)


def analyze_race_condition_signal(
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
    del body_fields, query_fields, path_fields, business_context
    details = dict(details or {})
    method = str(method or "UNKNOWN").upper()
    workflow = mine_workflow_context(db, analysis_id=analysis_id, target=target, endpoint=endpoint, semantic_text=semantic_text)
    markers = marker_set(" ".join([endpoint, semantic_text])) | set(workflow.get("catalog_markers", []))
    single_use = sorted((markers & SINGLE_USE_MARKERS) | set(workflow.get("single_use_markers", [])))
    stateful = method in STATEFUL_METHODS or truth(details.get("stateful_operation")) is True
    runtime = observations(details, "race_condition_observations", "concurrency_observations", "atomicity_observations")
    if not markers and not single_use and not runtime:
        return None

    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    structural_group = f"race_workflow_surface:{endpoint}:{method}"
    if markers:
        add_unique(support, {
            "type": "workflow_markers", "source": "offline_workflow_miner", "source_group": structural_group, "weight": 13,
            "text": f"Stored workflow context contains business markers relevant to repeated/limited operations: {', '.join(sorted(markers)[:8])}.",
        })
    if stateful:
        add_unique(support, {
            "type": "stateful_operation", "source": "endpoint_contract", "source_group": structural_group, "weight": 14,
            "text": f"The operation is state-changing ({method}) or explicitly marked stateful.",
        })
    if single_use:
        add_unique(support, {
            "type": "single_use_semantics", "source": "workflow_semantics", "source_group": structural_group, "weight": 16,
            "text": f"Stored semantics suggest a single-use, limited, reservation or balance-changing action: {', '.join(single_use[:8])}.",
        })

    policy = details.get("idempotency_policy") or details.get("atomicity_policy") or details.get("single_use_policy")
    if isinstance(policy, Mapping) and truth(policy.get("documented")) is True:
        add_unique(support, {
            "type": "single_use_policy_context", "source": "stored_business_policy", "source_group": "race_atomicity_policy", "weight": 15,
            "text": "Stored target policy documents a single-use, idempotency or atomicity requirement for the operation.",
        })

    for index, obs in enumerate(runtime[:50]):
        authorized = truth(scalar(obs, ("concurrency_test_authorized", "authorized_concurrency_evidence", "explicit_concurrency_authorization"))) is True
        test_owned = truth(scalar(obs, ("test_owned_resource", "controlled_test_resource", "test_owned_data"))) is True
        group = f"race_observation:{index}"
        if truth(scalar(obs, ("idempotency_enforced", "duplicate_prevented"))) is True:
            add_unique(contradict, {
                "type": "idempotency_enforced", "source": "stored_concurrency_observation", "source_group": group, "weight": -46,
                "text": "Stored authorized evidence shows idempotency or duplicate-operation prevention on the relevant action.",
            })
        if truth(scalar(obs, ("atomic_transition_observed", "atomicity_enforced"))) is True:
            add_unique(contradict, {
                "type": "atomic_transition_observed", "source": "stored_concurrency_observation", "source_group": group, "weight": -46,
                "text": "Stored authorized evidence shows the state transition behaves atomically for the controlled resource.",
            })
        if not (authorized and test_owned):
            continue
        if truth(scalar(obs, ("duplicate_operation_observed", "duplicate_effect_observed", "single_use_action_repeated"))) is True:
            add_unique(support, {
                "type": "duplicate_operation_observed", "source": "stored_authorized_concurrency_evidence", "source_group": group, "weight": 60,
                "text": "An explicitly authorized concurrency observation on a test-owned resource produced a duplicate effect where policy requires single-use behavior.",
            })
        if truth(scalar(obs, ("non_atomic_transition_observed", "atomicity_violation_observed", "check_then_act_race_observed"))) is True:
            add_unique(support, {
                "type": "non_atomic_transition_observed", "source": "stored_authorized_concurrency_evidence", "source_group": group, "weight": 60,
                "text": "Stored authorized concurrency evidence shows a non-atomic state transition on a test-owned resource.",
            })

    observed = {item["type"] for item in support}
    if "duplicate_operation_observed" in observed:
        variant = "duplicate_operation_observed"
    elif "non_atomic_transition_observed" in observed:
        variant = "non_atomic_transition_observed"
    elif "single_use_policy_context" in observed:
        variant = "single_use_atomicity_potential"
    else:
        variant = "single_use_race_surface"

    return finalize_result(
        analyzer=RaceConditionFamilyAnalyzer(),
        family="race_condition",
        variant=variant,
        support=support,
        contradict=contradict,
        taxonomy=RACE_CONDITION_TAXONOMY,
        methodology=RACE_CONDITION_METHOD,
        false_positive_checks=RACE_CONDITION_FALSE_POSITIVE_CHECKS,
        writeup_patterns=RACE_CONDITION_WRITEUP_PATTERNS,
        direct_types={"duplicate_operation_observed", "non_atomic_transition_observed"},
        rule_ids=("family-race-single-use-surface", "family-race-critical-section", "family-race-authorized-concurrency"),
        summary="Race-condition hypothesis based on offline single-use/atomicity modeling and explicitly authorized stored concurrency evidence.",
        base=18,
        extra_meta={
            "family_rule_version": RACE_CONDITION_FAMILY_ANALYZER_RULE_VERSION,
            "workflow_intelligence": workflow,
            "single_use_markers": single_use[:20],
            "runtime_observation_count": len(runtime),
            "concurrent_requests_performed": False,
            "state_changing_request_performed": False,
        },
    )


class RaceConditionFamilyAnalyzer(FamilyAnalyzer):
    family = "race_condition"
    analyzer_version = RACE_CONDITION_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_race_condition_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            details=context.details,
            business_context=context.business_context,
            **kwargs,
        )
