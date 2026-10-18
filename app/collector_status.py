from __future__ import annotations

"""Collection completeness shared by execution, resume and baseline checks."""

from typing import Any, Mapping


_LEGACY_MISSING_TOOLS = {
    "fingerprint": "httpx missing",
    "ports": "naabu missing",
    "nuclei": "nuclei missing",
}


def normalize_collection_metrics(stage: str, metrics: Mapping[str, Any]) -> dict[str, Any]:
    """Retain diagnostic fields while exposing known unavailable collection.

    Disabled modules, valid empty input and implemented fallback collectors are
    intentional outcomes. A missing optional source is not a missing stage.
    Only explicit legacy signatures are repaired; absent historical metrics do
    not establish which tool actually ran.
    """
    result = dict(metrics)
    missing = str(result.get("skipped") or "") == _LEGACY_MISSING_TOOLS.get(stage, "\0")
    no_discovery = (
        stage == "subdomains"
        and result.get("subdomain_tool_outcomes") == []
        and result.get("collection_status") in {"completed", "success"}
    )
    if missing or no_discovery or result.get("collection_status") == "unavailable":
        result["collection_status"] = "partial"
        reasons = result.get("collection_reasons")
        reasons = list(reasons) if isinstance(reasons, (list, tuple)) else []
        if missing:
            tool = _LEGACY_MISSING_TOOLS[stage].split()[0]
            result["missing_tools"] = [tool]
            reasons.append(tool + "_missing")
            result["stop_reason"] = "tool_missing"
        elif no_discovery:
            result["missing_tools"] = ["subfinder", "assetfinder"]
            reasons.append("subdomain_tools_missing")
            result["stop_reason"] = "tool_missing"
        else:
            reasons.append("collector_unavailable")
        result["collection_reasons"] = sorted(set(reasons))
    return result


def collection_incomplete(stage: str, metrics: Mapping[str, Any]) -> bool:
    return normalize_collection_metrics(stage, metrics).get("collection_status") == "partial"
