from __future__ import annotations

"""Explicit router for independently versioned family analyzers."""

from collections import OrderedDict
from typing import Any, Mapping
from family_reasoning import FAMILY_ORDER
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

FAMILY_ANALYZER_ROUTER_VERSION = "4.1.0"
RAW_ANALYZER_BUDGET_VERSION = "1.0.0"
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
    state["attempted"] += 1
    if int(state["executed"]) >= int(RAW_ANALYZER_INVOCATION_LIMIT):
        state["skipped"] += 1
        state["exhausted"] = True
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
    family_counts = state["families"]
    family_counts[str(family or "unknown")] = int(
        family_counts.get(str(family or "unknown"), 0)
    ) + 1
    return True


def raw_analysis_budget_snapshot(analysis_id: str) -> dict[str, Any]:
    """Return a detached operational snapshot for tests/diagnostics."""

    state = _RAW_BUDGETS.get(str(analysis_id or ""))
    if state is None:
        return {
            "version": RAW_ANALYZER_BUDGET_VERSION,
            "limit": int(RAW_ANALYZER_INVOCATION_LIMIT),
            "attempted": 0,
            "executed": 0,
            "skipped": 0,
            "exhausted": False,
            "families": {},
        }
    return {
        "version": str(state["version"]),
        "limit": int(RAW_ANALYZER_INVOCATION_LIMIT),
        "attempted": int(state["attempted"]),
        "executed": int(state["executed"]),
        "skipped": int(state["skipped"]),
        "exhausted": bool(state["exhausted"]),
        "families": dict(state["families"]),
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
        if not _consume_raw_budget(context, self.family):
            return None
        return original(self, context, **kwargs)

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
    }
