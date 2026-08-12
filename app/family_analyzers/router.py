from __future__ import annotations

"""Explicit router for independently versioned family analyzers."""

from typing import Any

from family_reasoning import FAMILY_ORDER

from .account_enumeration import AccountEnumerationFamilyAnalyzer
from .authentication_session import AuthenticationSessionFamilyAnalyzer
from .base import FamilyAnalyzer
from .bfla import BflaFamilyAnalyzer
from .bola import BolaFamilyAnalyzer
from .business_logic import BusinessLogicFamilyAnalyzer
from .cors_misconfiguration import CorsMisconfigurationFamilyAnalyzer
from .dom_xss import DomXssFamilyAnalyzer
from .file_upload import FileUploadFamilyAnalyzer
from .graphql_authorization import GraphqlAuthorizationFamilyAnalyzer
from .graphql_data_exposure import GraphqlDataExposureFamilyAnalyzer
from .information_disclosure import InformationDisclosureFamilyAnalyzer
from .mass_assignment import MassAssignmentFamilyAnalyzer
from .open_redirect import OpenRedirectFamilyAnalyzer
from .path_traversal import PathTraversalFamilyAnalyzer
from .postmessage_trust import PostMessageTrustFamilyAnalyzer
from .race_condition import RaceConditionFamilyAnalyzer
from .secret_exposure import SecretExposureFamilyAnalyzer
from .sensitive_caching import SensitiveCachingFamilyAnalyzer
from .source_map_exposure import SourceMapExposureFamilyAnalyzer
from .ssrf import SsrfFamilyAnalyzer
from .websocket_authorization import WebsocketAuthorizationFamilyAnalyzer


FAMILY_ANALYZER_ROUTER_VERSION = "2.0.0"

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
}


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
    }
