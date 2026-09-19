from __future__ import annotations

"""Explicit router for independently versioned family analyzers."""

from collections import OrderedDict
from typing import Any, Mapping
from family_reasoning import FAMILY_ORDER
from hypothesis_evidence_planner import plan_result_evidence
from .account_enumeration import AccountEnumerationFamilyAnalyzer
from .authentication_session import AuthenticationSessionFamilyAnalyzer
from .api_expansion import (
    ImproperInventoryManagementFamilyAnalyzer, SecurityMisconfigurationFamilyAnalyzer,
    SensitiveBusinessFlowAbuseFamilyAnalyzer, UnrestrictedResourceConsumptionFamilyAnalyzer,
    UnsafeApiConsumptionFamilyAnalyzer,
)
from .base import FamilyAnalyzer
from .bfla import BflaFamilyAnalyzer
from .bola import BolaFamilyAnalyzer
from .business_logic import BusinessLogicFamilyAnalyzer
from .command_injection import CommandInjectionFamilyAnalyzer
from .cors_misconfiguration import CorsMisconfigurationFamilyAnalyzer
from .dom_xss import DomXssFamilyAnalyzer
from .file_upload import FileUploadFamilyAnalyzer
from .graphql_authorization import GraphqlAuthorizationFamilyAnalyzer
from .graphql_data_exposure import GraphqlDataExposureFamilyAnalyzer
from .information_disclosure import InformationDisclosureFamilyAnalyzer
from .ldap_injection import LdapInjectionFamilyAnalyzer
from .mass_assignment import MassAssignmentFamilyAnalyzer
from .nosql_injection import NoSqlInjectionFamilyAnalyzer
from .open_redirect import OpenRedirectFamilyAnalyzer
from .path_traversal import PathTraversalFamilyAnalyzer
from .phase2_expansion import PHASE2_ANALYZER_TYPES
from .postmessage_trust import PostMessageTrustFamilyAnalyzer
from .race_condition import RaceConditionFamilyAnalyzer
from .secret_exposure import SecretExposureFamilyAnalyzer
from .sensitive_caching import SensitiveCachingFamilyAnalyzer
from .source_map_exposure import SourceMapExposureFamilyAnalyzer
from .sql_injection import SqlInjectionFamilyAnalyzer
from .ssrf import SsrfFamilyAnalyzer
from .ssti import SstiFamilyAnalyzer
from .websocket_authorization import WebsocketAuthorizationFamilyAnalyzer

FAMILY_ANALYZER_ROUTER_VERSION = "4.2.0"
RAW_ANALYZER_BUDGET_VERSION = "1.1.0"
RAW_ANALYZER_INVOCATION_LIMIT = 200_000
_RAW_BUDGET_CACHE_MAX = 64
_RAW_BUDGETS: "OrderedDict[str, dict[str, Any]]" = OrderedDict()

_ANALYZERS: dict[str, type[FamilyAnalyzer]] = {
    "broken_object_authorization": BolaFamilyAnalyzer,
    "broken_function_authorization": BflaFamilyAnalyzer,
    "mass_assignment": MassAssignmentFamilyAnalyzer,
    "authentication_session": AuthenticationSessionFamilyAnalyzer,
    "account_enumeration": AccountEnumerationFamilyAnalyzer,
    "dom_xss": DomXssFamilyAnalyzer,
    "postmessage_trust": PostMessageTrustFamilyAnalyzer,
    "open_redirect": OpenRedirectFamilyAnalyzer,
    "ssrf": SsrfFamilyAnalyzer,
    "file_upload": FileUploadFamilyAnalyzer,
    "path_traversal": PathTraversalFamilyAnalyzer,
    "information_disclosure": InformationDisclosureFamilyAnalyzer,
    "source_map_exposure": SourceMapExposureFamilyAnalyzer,
    "secret_exposure": SecretExposureFamilyAnalyzer,
    "graphql_authorization": GraphqlAuthorizationFamilyAnalyzer,
    "graphql_data_exposure": GraphqlDataExposureFamilyAnalyzer,
    "business_logic": BusinessLogicFamilyAnalyzer,
    "race_condition": RaceConditionFamilyAnalyzer,
    "websocket_authorization": WebsocketAuthorizationFamilyAnalyzer,
    "cors_misconfiguration": CorsMisconfigurationFamilyAnalyzer,
    "sensitive_caching": SensitiveCachingFamilyAnalyzer,
    "sql_injection": SqlInjectionFamilyAnalyzer,
    "nosql_injection": NoSqlInjectionFamilyAnalyzer,
    "command_injection": CommandInjectionFamilyAnalyzer,
    "ssti": SstiFamilyAnalyzer,
    "ldap_injection": LdapInjectionFamilyAnalyzer,
    "unrestricted_resource_consumption": UnrestrictedResourceConsumptionFamilyAnalyzer,
    "sensitive_business_flow_abuse": SensitiveBusinessFlowAbuseFamilyAnalyzer,
    "security_misconfiguration": SecurityMisconfigurationFamilyAnalyzer,
    "improper_inventory_management": ImproperInventoryManagementFamilyAnalyzer,
    "unsafe_api_consumption": UnsafeApiConsumptionFamilyAnalyzer,
}
_ANALYZERS.update(PHASE2_ANALYZER_TYPES)


def _is_raw_surface_context(context: Any) -> bool:
    details = getattr(context, "details", None)
    return isinstance(details, Mapping) and bool(
        details.get("raw_surface_observation")
        or details.get("raw_finding_observation")
    )


def _budget_state(analysis_id: str) -> dict[str, Any]:
    state = _RAW_BUDGETS.get(analysis_id)
    if state is not None:
        _RAW_BUDGETS.move_to_end(analysis_id)
        return state
    state = {
        "version": RAW_ANALYZER_BUDGET_VERSION,
        "limit": int(RAW_ANALYZER_INVOCATION_LIMIT),
        "attempted": 0,
        "executed": 0,
        "skipped": 0,
        "exhausted": False,
        "audit_emitted": False,
        "families": {},
        "targets": {},
    }
    _RAW_BUDGETS[analysis_id] = state
    while len(_RAW_BUDGETS) > _RAW_BUDGET_CACHE_MAX:
        _RAW_BUDGETS.popitem(last=False)
    return state


def _consume_raw_budget(context: Any, family: str) -> bool:
    """Bound only raw-Recon fan-out; normal Alert/validation analysis is untouched."""

    if not _is_raw_surface_context(context):
        return True
    analysis_id = str(getattr(context, "analysis_id", "") or "")
    if not analysis_id:
        # A context without an analysis identity cannot participate in the
        # process-local budget safely, so preserve historical behavior.
        return True
    state = _budget_state(analysis_id)
    target = str(getattr(context, "target", "") or "*")
    target_state = state["targets"].setdefault(
        target,
        {
            "attempted": 0,
            "executed": 0,
            "skipped": 0,
            "exhausted": False,
            "families": {},
        },
    )
    state["attempted"] += 1
    target_state["attempted"] += 1
    if int(state["executed"]) >= int(RAW_ANALYZER_INVOCATION_LIMIT):
        state["skipped"] += 1
        state["exhausted"] = True
        target_state["skipped"] += 1
        target_state["exhausted"] = True
        if not state["audit_emitted"]:
            db = getattr(context, "db", None)
            audit = getattr(db, "audit", None)
            if callable(audit):
                try:
                    audit(
                        "raw_family_budget_exhausted",
                        target=str(getattr(context, "target", "") or "*"),
                        entity_type="analysis",
                        entity_value=analysis_id,
                        details={
                            "version": RAW_ANALYZER_BUDGET_VERSION,
                            "limit": int(RAW_ANALYZER_INVOCATION_LIMIT),
                            "attempted": int(state["attempted"]),
                            "executed": int(state["executed"]),
                            "skipped": int(state["skipped"]),
                            "family": str(family or ""),
                        },
                    )
                except Exception:
                    # Observability must never make the Analysis path fail.
                    pass
            state["audit_emitted"] = True
        return False
    state["executed"] += 1
    target_state["executed"] += 1
    family_key = str(family or "unknown")
    family_counts = state["families"]
    family_counts[family_key] = int(
        family_counts.get(family_key, 0)
    ) + 1
    target_families = target_state["families"]
    target_families[family_key] = int(
        target_families.get(family_key, 0)
    ) + 1
    return True


def _raw_result_is_promotion_ready(result: Mapping[str, Any]) -> bool:
    """Require analyzer-owned target evidence before raw Recon can promote.

    Newer analyzers expose an explicit promotion-readiness bit derived from the
    canonical Family Reasoning contract. Older specialized analyzers expose
    ``direct`` when they observed a concrete target-side boundary condition.
    Raw route names, keywords and passive surface structure alone therefore
    remain hypotheses rather than Potential Findings.
    """

    meta = result.get("family_analyzer")
    if isinstance(meta, Mapping) and "promotion_ready_from_stored_target_evidence" in meta:
        return bool(meta.get("promotion_ready_from_stored_target_evidence"))
    return bool(result.get("direct"))


def _demote_raw_context_support(result: Mapping[str, Any]) -> dict[str, Any]:
    """Keep raw discovery context auditable while making it non-decisive."""

    normalized = dict(result)
    original_support = [
        dict(item)
        for item in normalized.get("support", [])
        if isinstance(item, Mapping)
    ]
    if not original_support:
        return normalized

    context_support: list[dict[str, Any]] = []
    for item in original_support:
        contextual = dict(item)
        canonical_type = str(contextual.get("type") or "surface_context")
        contextual["canonical_type"] = canonical_type
        contextual["type"] = f"context_only:{canonical_type}"
        contextual["non_decisive"] = True
        contextual["raw_context_only"] = True
        context_support.append(contextual)
    normalized["support"] = context_support

    meta = dict(normalized.get("family_analyzer") or {})
    meta["raw_context_support"] = original_support[:100]
    meta["raw_context_only_promotion_blocked"] = True
    meta["raw_context_support_preserved"] = True
    normalized["family_analyzer"] = meta
    normalized["direct"] = False
    return normalized


def _attach_evidence_plan(result: Mapping[str, Any], family: str) -> dict[str, Any]:
    """Attach diagnostic next-evidence guidance without changing evidence."""

    normalized = dict(result)
    try:
        raw_missing = normalized.get("missing", [])
        missing = raw_missing if isinstance(raw_missing, (list, tuple, set)) else []
        plan = plan_result_evidence(family, missing)
    except Exception as exc:
        plan = {
            "version": "",
            "status": "degraded",
            "error_type": type(exc).__name__,
            "diagnostic_only": True,
            "network_requests": False,
            "creates_target_evidence": False,
            "changes_admission": False,
        }
    meta = dict(normalized.get("family_analyzer") or {})
    meta["evidence_acquisition_plan"] = plan
    normalized["family_analyzer"] = meta
    return normalized


def _detached_budget_metrics(
    state: Mapping[str, Any] | None,
) -> dict[str, Any]:
    data = state if isinstance(state, Mapping) else {}
    return {
        "attempted": int(data.get("attempted") or 0),
        "executed": int(data.get("executed") or 0),
        "skipped": int(data.get("skipped") or 0),
        "exhausted": bool(data.get("exhausted")),
        "families": dict(data.get("families") or {})
        if isinstance(data.get("families"), Mapping)
        else {},
    }


def raw_analysis_budget_snapshot(
    analysis_id: str,
    target: str | None = None,
) -> dict[str, Any]:
    """Return detached global and optional target-scoped budget telemetry."""

    state = _RAW_BUDGETS.get(str(analysis_id or ""))
    base = {
        "version": RAW_ANALYZER_BUDGET_VERSION,
        # The invocation ceiling remains analysis-wide. Target counters report
        # consumption of that shared budget, not independent per-target limits.
        "limit": int(RAW_ANALYZER_INVOCATION_LIMIT),
        "limit_scope": "analysis",
    }
    if state is None:
        return {
            **base,
            **_detached_budget_metrics(None),
            "by_target": {},
        }

    targets = state.get("targets")
    by_target = {
        str(name): {
            **base,
            **_detached_budget_metrics(metrics),
            "scope": "target",
            "target": str(name),
        }
        for name, metrics in (targets.items() if isinstance(targets, Mapping) else [])
    }
    if target is not None:
        scoped = dict(
            by_target.get(
                str(target),
                {
                    **base,
                    **_detached_budget_metrics(None),
                    "scope": "target",
                    "target": str(target),
                },
            )
        )
        scoped["analysis_total"] = {
            **base,
            **_detached_budget_metrics(state),
        }
        return scoped

    return {
        **base,
        **_detached_budget_metrics(state),
        "scope": "analysis",
        "by_target": by_target,
    }


def clear_raw_analysis_budget(analysis_id: str | None = None) -> None:
    if analysis_id is None:
        _RAW_BUDGETS.clear()
    else:
        _RAW_BUDGETS.pop(str(analysis_id), None)


def _install_raw_budget_guard(analyzer_type: type[FamilyAnalyzer]) -> None:
    original = analyzer_type.analyze
    if bool(getattr(original, "_raw_budget_guard", False)):
        return

    def guarded(self: FamilyAnalyzer, context: Any, **kwargs: Any) -> dict[str, Any] | None:
        raw_context = _is_raw_surface_context(context)
        if raw_context and not _consume_raw_budget(context, self.family):
            return None
        result = original(self, context, **kwargs)
        if not isinstance(result, Mapping):
            return result
        planned = _attach_evidence_plan(result, self.family)
        if not raw_context:
            return planned
        if _raw_result_is_promotion_ready(planned):
            return planned
        return _demote_raw_context_support(planned)

    guarded.__name__ = getattr(original, "__name__", "analyze")
    guarded.__doc__ = getattr(original, "__doc__", None)
    setattr(guarded, "_raw_budget_guard", True)
    analyzer_type.analyze = guarded  # type: ignore[method-assign]


# Install once at router import while preserving every concrete analyzer type.
for _analyzer_type in set(_ANALYZERS.values()):
    _install_raw_budget_guard(_analyzer_type)


def registered_families() -> tuple[str, ...]:
    return tuple(family for family in FAMILY_ORDER if family in _ANALYZERS)


def pending_families() -> tuple[str, ...]:
    return tuple(family for family in FAMILY_ORDER if family not in _ANALYZERS)


def analyzer_for_family(family: str) -> FamilyAnalyzer | None:
    analyzer_type = _ANALYZERS.get(str(family or ""))
    return analyzer_type() if analyzer_type else None


def router_status() -> dict[str, Any]:
    registered = registered_families()
    pending = pending_families()
    return {
        "version": FAMILY_ANALYZER_ROUTER_VERSION,
        "registered_count": len(registered),
        "registered": list(registered),
        "pending_count": len(pending),
        "pending": list(pending),
        "target_family_count": len(FAMILY_ORDER),
        "generic_family_analyzer_fallback": False,
        "raw_analyzer_budget": {
            "version": RAW_ANALYZER_BUDGET_VERSION,
            "invocation_limit_per_analysis": int(RAW_ANALYZER_INVOCATION_LIMIT),
            "active_analysis_snapshots": len(_RAW_BUDGETS),
            "raw_context_only": True,
        },
        "evidence_planner": {
            "attached_to_family_results": True,
            "diagnostic_only": True,
            "network_requests": False,
            "changes_admission": False,
        },
    }
