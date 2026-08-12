from __future__ import annotations

"""Dedicated Source-map Exposure analyzer.

A sourceMappingURL reference or .map-looking URL is only surface evidence. The
family becomes direct only from already-stored passive target observations that
show the map was fetched without credentials and contains internal source
structure, or from an explicit stored observation of sensitive source content.
The analyzer performs no request and never copies source contents into output.
"""

from typing import Any, Mapping

from core import Database
from family_reasoning import FAMILY_REASONING, confirmation_gaps

from .base import FamilyAnalyzer, FamilyAnalyzerContext


SOURCE_MAP_FAMILY_ANALYZER_VERSION = "1.0.0"
SOURCE_MAP_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

SOURCE_MAP_TAXONOMY = {
    "owasp": ["Information Leakage"],
    "wstg": ["WSTG-INFO-05"],
    "cwe": ["CWE-200"],
    "related_cwe": ["CWE-497", "CWE-540"],
}

SOURCE_MAP_METHOD = (
    {
        "id": "SMAP-01-reference-surface",
        "basis": ["WSTG-INFO-05"],
        "principle": "Treat sourceMappingURL directives and .map references as discovery surface only; a reference does not prove public reachability.",
    },
    {
        "id": "SMAP-02-passive-reachability",
        "basis": ["WSTG-INFO-05", "CWE-200"],
        "principle": "Use only stored passive collector evidence to establish that the source map was actually reachable without credentials.",
    },
    {
        "id": "SMAP-03-source-structure",
        "basis": ["WSTG-INFO-05", "CWE-497"],
        "principle": "Require internal source structure, paths, modules or equivalent implementation metadata before promoting a generic public map into this family.",
    },
    {
        "id": "SMAP-04-sensitive-content",
        "basis": ["CWE-200", "CWE-540"],
        "principle": "Sensitive source content is stronger evidence only when explicitly observed in stored data; never infer secrets from filenames and never echo raw source contents.",
    },
    {
        "id": "SMAP-05-contradiction-check",
        "basis": ["WSTG-INFO-05"],
        "principle": "A referenced map that was not publicly reachable, or a map with explicitly empty embedded source content when content exposure is the hypothesis, is contradiction evidence.",
    },
)

SOURCE_MAP_FALSE_POSITIVE_CHECKS = (
    "A sourceMappingURL directive or .map filename alone is only a reference surface.",
    "A map with only generated/minified filenames and no internal source structure is not promoted by this analyzer.",
    "A source map available only with authorized credentials is not treated as publicly exposed.",
    "Internal-looking filenames are implementation metadata, not automatically secrets or credentials.",
    "Secret/token material belongs to the dedicated Secret Exposure family and must remain redacted.",
    "Source contents are never copied into analyzer evidence; only counts, normalized categories and booleans are retained.",
)

SOURCE_MAP_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-info-05-source-maps",
        "source": "OWASP WSTG",
        "ref": "WSTG-INFO-05 / Review Web Page Content for Information Leakage",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage",
        "principle": "Production source maps can make original frontend source structure human-readable and expose implementation metadata or sensitive information.",
        "signals": ["source_map", "internal_sources", "source_map_publicly_reachable"],
    },
    {
        "id": "cwe-200-source-code-state",
        "source": "MITRE CWE",
        "ref": "CWE-200 / Exposure of Sensitive Information to an Unauthorized Actor",
        "url": "https://cwe.mitre.org/data/definitions/200.html",
        "principle": "Product code, internal state and system metadata can be sensitive information when exposed outside the intended audience.",
        "signals": ["source_map_publicly_reachable", "sensitive_source_content_observed"],
    },
)


def _truth(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "observed", "reachable", "public", "success", "present"}:
        return True
    if text in {"0", "false", "no", "not_observed", "unreachable", "private", "failed", "absent"}:
        return False
    return None


def _count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _add_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    key = (str(item.get("type") or ""), str(item.get("source_group") or ""), str(item.get("text") or ""))
    if any((str(row.get("type") or ""), str(row.get("source_group") or ""), str(row.get("text") or "")) == key for row in items):
        return
    items.append(item)


def analyze_source_map_exposure_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    source_map_url: str = "",
    js_url: str = "",
    source_count: int = 0,
    internal_source_count: int = 0,
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
) -> dict[str, Any] | None:
    del db, analysis_id, target, business_context
    details = dict(details or {})
    source_map_url = str(source_map_url or details.get("source_map_url") or "")
    js_url = str(js_url or details.get("js_url") or "")
    source_count = max(_count(source_count), _count(details.get("source_count")))
    internal_source_count = max(_count(internal_source_count), _count(details.get("internal_source_count")))

    referenced = bool(source_map_url or details.get("source_map_reference") or details.get("source_mapping_url"))
    if not referenced and not str(js_url).lower().endswith(".map"):
        return None

    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    _add_unique(support, {
        "type": "source_map",
        "source": "javascript_metadata",
        "source_group": "source_map_reference_surface",
        "weight": 18,
        "text": "A source-map reference is present in stored JavaScript metadata.",
    })

    if internal_source_count > 0:
        _add_unique(support, {
            "type": "internal_sources",
            "source": "stored_source_map_metadata",
            "source_group": "source_map_internal_structure",
            "weight": 24,
            "text": f"Stored source-map metadata contains {internal_source_count} internal-looking source entries; raw paths are not echoed.",
        })

    collector_success = _truth(details.get("collector_download_succeeded"))
    explicit_public = _truth(details.get("publicly_reachable"))
    public_reachable = explicit_public is True or (collector_success is True and source_count > 0)
    not_public = explicit_public is False or _truth(details.get("source_map_not_public")) is True
    sensitive_content = _truth(details.get("sensitive_source_content_observed")) is True
    sources_content_empty = _truth(details.get("sources_content_empty")) is True

    # Emit the canonical direct reachability signal only when the same stored map
    # also contains internal source structure. This prevents a harmless public map
    # with no meaningful source metadata from bypassing the family promotion gate.
    if public_reachable and internal_source_count > 0:
        _add_unique(support, {
            "type": "source_map_publicly_reachable",
            "source": "stored_passive_source_map_fetch",
            "source_group": "source_map_public_reachability",
            "weight": 44,
            "text": "The passive collector successfully retrieved and parsed the referenced source map without credentials, and the same map contains internal source structure.",
        })

    if sensitive_content:
        _add_unique(support, {
            "type": "sensitive_source_content_observed",
            "source": "stored_source_map_review",
            "source_group": "source_map_sensitive_content",
            "weight": 50,
            "text": "Stored redacted review metadata records sensitive source content in the map; no raw source or secret value is included here.",
        })

    if not_public:
        _add_unique(contradict, {
            "type": "source_map_not_public",
            "source": "stored_source_map_fetch",
            "source_group": "source_map_reachability_control",
            "weight": -40,
            "text": "Stored evidence indicates the referenced source map was not publicly reachable.",
        })
    if sources_content_empty:
        _add_unique(contradict, {
            "type": "sources_content_empty",
            "source": "stored_source_map_metadata",
            "source_group": "source_map_content_control",
            "weight": -24,
            "text": "Stored metadata records empty embedded source content for the source-content exposure hypothesis.",
        })

    observed = {str(item.get("type") or "") for item in support}
    blockers = {str(item.get("type") or "") for item in contradict}
    promotion_ready = "source_map_publicly_reachable" in observed or "sensitive_source_content_observed" in observed
    confirmation_ready = "source_map_publicly_reachable" in observed and not bool(blockers & {"source_map_not_public"})
    confirmation_missing = list(confirmation_gaps("source_map_exposure", observed))
    if confirmation_ready:
        confirmation_missing = []

    if "sensitive_source_content_observed" in observed:
        variant = "sensitive_source_content"
    elif "source_map_publicly_reachable" in observed:
        variant = "public_internal_source_map"
    elif "source_map_not_public" in blockers:
        variant = "referenced_not_public"
    elif internal_source_count > 0:
        variant = "internal_sources_unverified_reachability"
    else:
        variant = "source_map_reference_only"

    metadata = SourceMapExposureFamilyAnalyzer().metadata()
    metadata.update({
        "family_rule_version": SOURCE_MAP_FAMILY_ANALYZER_RULE_VERSION,
        "taxonomy": {key: list(value) for key, value in SOURCE_MAP_TAXONOMY.items()},
        "methodology": [dict(step) for step in SOURCE_MAP_METHOD],
        "false_positive_checks": list(SOURCE_MAP_FALSE_POSITIVE_CHECKS),
        "writeup_patterns": [dict(item, non_evidentiary=True) for item in SOURCE_MAP_WRITEUP_PATTERNS],
        "source_count": source_count,
        "internal_source_count": internal_source_count,
        "promotion_ready_from_stored_target_evidence": promotion_ready,
        "confirmation_ready_from_stored_target_evidence": confirmation_ready,
        "confirmation_missing": confirmation_missing,
        "knowledge_does_not_change_target_evidence": True,
        "active_request_performed": False,
        "credentialed_request_performed": False,
        "source_content_copied_to_output": False,
        "secret_validation_performed": False,
    })

    missing = list(FAMILY_REASONING["source_map_exposure"]["next_evidence"])
    if confirmation_ready:
        missing = []

    return {
        "family": "source_map_exposure",
        "variant": variant,
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": [
            "family-source-map-reference",
            "family-source-map-passive-reachability",
            "family-source-map-internal-structure",
            "family-source-map-sensitive-content",
            "family-source-map-contradiction-check",
        ],
        "summary": (
            "Stored passive target evidence shows a publicly reachable source map exposing internal source structure or sensitive source content."
            if confirmation_ready
            else "A source-map reference or internal source structure is retained as a hidden hypothesis until public reachability and meaningful exposure are established from stored evidence."
        ),
        "direct": promotion_ready,
        "family_analyzer": metadata,
    }


class SourceMapExposureFamilyAnalyzer(FamilyAnalyzer):
    family = "source_map_exposure"
    analyzer_version = SOURCE_MAP_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_source_map_exposure_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            source_map_url=str(kwargs.get("source_map_url") or context.endpoint or ""),
            js_url=str(kwargs.get("js_url") or ""),
            source_count=_count(kwargs.get("source_count")),
            internal_source_count=_count(kwargs.get("internal_source_count")),
            details=context.details,
            business_context=context.business_context,
        )
