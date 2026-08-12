from __future__ import annotations

"""Candidate Engine expansion surface for OWASP phase 1.

The proven 21-family integration remains isolated in ``bug_candidates_family21``.
This module extends the same hypothesis-first admission path to ten additional
OWASP Web/API families without creating a second Candidate Engine or bypassing
Family Reasoning. No new analyzer performs active validation.
"""

from typing import Any, Mapping
from urllib.parse import urlsplit

import bug_candidates_family21 as _family21_import
from family_analyzers.base import FamilyAnalyzerContext
from family_analyzers.router import analyzer_for_family
from family_reasoning import candidate_evidence_schema_map
from owasp_family_catalog import BUG_FAMILY_METADATA, DIRECT_TYPES, NEW_FAMILY_ORDER, SAFE_ACTIONS as OWASP_SAFE_ACTIONS

# Preserve the complete existing public surface first.
for _name, _value in vars(_family21_import).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

# Re-bind compatibility modules after re-exporting the legacy surface. The
# legacy module itself exposes private names such as `_legacy`/`_core`; doing
# this afterwards prevents those names from shadowing the modules used by this
# extension layer.
import bug_candidates_family21 as _legacy
import bug_candidates_core as _compat
import bug_candidates_legacy_core as _core

CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = "3.0.0"
_legacy.CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION

# Extend the historical metadata used by insertion/scoring. The dictionaries are
# mutated in place so all compatibility layers observe one catalog.
_core.BUG_FAMILIES.update(BUG_FAMILY_METADATA)
_core.SAFE_ACTIONS.update(OWASP_SAFE_ACTIONS)
_compat.BUG_FAMILIES = _core.BUG_FAMILIES
_compat.SAFE_ACTIONS = _core.SAFE_ACTIONS
_legacy.BUG_FAMILIES = _core.BUG_FAMILIES
_legacy.SAFE_ACTIONS = _core.SAFE_ACTIONS
BUG_FAMILIES = _core.BUG_FAMILIES
SAFE_ACTIONS = _core.SAFE_ACTIONS

_schema_map = candidate_evidence_schema_map()
_core.FAMILY_EVIDENCE_SCHEMAS = _schema_map
_compat.FAMILY_EVIDENCE_SCHEMAS = _schema_map
_legacy.FAMILY_EVIDENCE_SCHEMAS = _schema_map
FAMILY_EVIDENCE_SCHEMAS = _schema_map

_legacy._FAMILY_DIRECT_TYPES.update({family: set(values) for family, values in DIRECT_TYPES.items()})
_legacy._DEDICATED_ALERT_FAMILIES.update(NEW_FAMILY_ORDER)

_ORIGINAL_DEDICATED_FAMILY_RESULT = _legacy._dedicated_family_result
_ORIGINAL_ALERT_CANDIDATES = _core._alert_candidates


def _extension_analyzer_result(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    alert_id: int | None,
    endpoint: str,
    family: str,
) -> dict[str, Any] | None:
    if family not in NEW_FAMILY_ORDER:
        return None
    stored = _legacy._stored_family_context(
        db,
        analysis_id=analysis_id,
        target=target,
        alert_id=alert_id,
        endpoint=endpoint,
    )
    if not stored:
        return None
    analyzer = analyzer_for_family(family)
    if analyzer is None:
        return None
    context = FamilyAnalyzerContext(
        db=db,
        analysis_id=analysis_id,
        target=target,
        endpoint=stored["endpoint"],
        method=stored["method"],
        details=stored["details"],
        business_context=stored["business_context"],
    )
    return analyzer.analyze(
        context,
        body_fields=stored["body_fields"],
        query_fields=stored["query_fields"],
        path_fields=stored["path_fields"],
        semantic_text=stored["semantic_text"],
    )


def _dedicated_family_result_extended(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    alert_id: int | None,
    endpoint: str,
    family: str,
) -> dict[str, Any] | None:
    if family in NEW_FAMILY_ORDER:
        return _extension_analyzer_result(
            db,
            analysis_id=analysis_id,
            target=target,
            alert_id=alert_id,
            endpoint=endpoint,
            family=family,
        )
    return _ORIGINAL_DEDICATED_FAMILY_RESULT(
        db,
        analysis_id=analysis_id,
        target=target,
        alert_id=alert_id,
        endpoint=endpoint,
        family=family,
    )


_legacy._dedicated_family_result = _dedicated_family_result_extended


def _asset_for_endpoint(endpoint: str) -> str:
    if "://" not in endpoint:
        return ""
    try:
        return urlsplit(endpoint).hostname or ""
    except Exception:
        return ""


def _promote_extension_result(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    row: Mapping[str, Any],
    family: str,
    dedicated: Mapping[str, Any],
) -> bool:
    alert_id = int(row["alert_id"])
    target = str(row["target"])
    schema = _core._loads(row.get("endpoint_schema_json"), {})
    details = _core._loads(row.get("details_json"), {})
    endpoint = str(schema.get("endpoint") or row.get("item") or "")
    context = str(row.get("business_context") or "general")
    method = str(schema.get("method") or details.get("method") or "UNKNOWN").upper()
    source_ref = f"alert:{alert_id}"
    asset = _asset_for_endpoint(endpoint)

    family_meta = dict(dedicated.get("family_analyzer") or {})
    support = [dict(item) for item in dedicated.get("support", []) if isinstance(item, Mapping)]
    contradict = [dict(item) for item in dedicated.get("contradict", []) if isinstance(item, Mapping)]
    hypothesis = _legacy._ORIGINAL_RECORD_HYPOTHESIS(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=alert_id,
        asset=asset,
        endpoint=endpoint,
        source_ref=source_ref,
        family=family,
        variant=str(dedicated.get("variant") or "stored_surface"),
        support=support,
        contradict=contradict,
        missing=[str(item) for item in dedicated.get("missing", []) if str(item)],
        rule_ids=[str(item) for item in dedicated.get("rule_ids", []) if str(item)],
        summary=str(dedicated.get("summary") or f"{family} hypothesis."),
    )
    if family_meta:
        hypothesis = _legacy._persist_family_meta(db, hypothesis, family_meta)
    if not bool(hypothesis.get("assessment", {}).get("admitted")):
        return False

    support = hypothesis["support"]
    contradict = hypothesis["contradict"]
    direct = bool(dedicated.get("direct"))
    roots = {
        str(item.get("source_group") or item.get("source") or item.get("type") or "unknown")
        for item in support
    }
    if len(support) < 2 or (len(roots) < 2 and not direct):
        return False

    confidence = _core.parse_int(row.get("confidence"), 0)
    likelihood = _core._clamp(
        int(dedicated.get("base") or 18)
        + sum(_core.parse_int(item.get("weight"), 0) for item in support)
        + sum(_core.parse_int(item.get("weight"), 0) for item in contradict)
    )
    strength = _legacy._evidence_strength_with_family_directness(
        confidence,
        support,
        contradict,
        direct=direct,
    )
    candidate_id = _core._insert_candidate(
        db,
        analysis_id=analysis_id,
        source_run_id=run_id,
        target=target,
        alert_id=alert_id,
        asset=asset,
        endpoint=endpoint,
        source_ref=source_ref,
        family=family,
        variant=str(dedicated.get("variant") or "stored_surface"),
        likelihood=likelihood,
        evidence_strength=strength,
        impact_potential=_core._impact(_core.BUG_FAMILIES[family]["impact"], context, method),
        support=support,
        contradict=contradict,
        missing=hypothesis["missing"],
        rule_ids=hypothesis["rule_ids"],
        summary=str(dedicated.get("summary") or f"{family} hypothesis."),
    )
    _core.mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)
    return True


def _alert_candidates_with_owasp_expansion(
    db: Any,
    analysis_id: str,
    run_id: str,
    row: Mapping[str, Any],
) -> int:
    # Preserve every existing family path first.
    count = _ORIGINAL_ALERT_CANDIDATES(db, analysis_id, run_id, row)
    target = str(row["target"])
    schema = _core._loads(row.get("endpoint_schema_json"), {})
    category = str(row.get("category") or "")
    if schema.get("is_endpoint") is False or category in {"dns_change", "new_subdomain", "new_port"}:
        return count
    endpoint = str(schema.get("endpoint") or row.get("item") or "")
    alert_id = int(row["alert_id"])
    for family in NEW_FAMILY_ORDER:
        dedicated = _extension_analyzer_result(
            db,
            analysis_id=analysis_id,
            target=target,
            alert_id=alert_id,
            endpoint=endpoint,
            family=family,
        )
        if dedicated and _promote_extension_result(
            db,
            analysis_id=analysis_id,
            run_id=run_id,
            row=row,
            family=family,
            dedicated=dedicated,
        ):
            count += 1
    return count


# Functions in the historical Candidate Engine resolve _alert_candidates through
# its own module globals, so replacing it here extends the real generation path.
_core._alert_candidates = _alert_candidates_with_owasp_expansion
_compat._alert_candidates = _alert_candidates_with_owasp_expansion
_legacy._base._alert_candidates = _alert_candidates_with_owasp_expansion

# Keep existing hypothesis/evidence/static hooks from the 21-family layer.
record_hypothesis = _legacy.record_hypothesis
_evidence_strength = _legacy._evidence_strength
_static_candidates = _legacy._static_candidates

# Publish the mutated catalogs and preserve the existing 21-family hooks.
BUG_FAMILIES = _core.BUG_FAMILIES
SAFE_ACTIONS = _core.SAFE_ACTIONS
FAMILY_EVIDENCE_SCHEMAS = _schema_map
CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = "3.0.0"
record_hypothesis = _legacy.record_hypothesis
_evidence_strength = _legacy._evidence_strength
_static_candidates = _legacy._static_candidates

__all__ = [name for name in globals() if not name.startswith("__")]
