from __future__ import annotations

"""Candidate Engine expansion surface for OWASP phases 1 and 2.

The proven 21-family integration remains isolated in ``bug_candidates_family21``.
This module extends the same hypothesis-first admission path to the explicit
OWASP/WSTG expansion families without creating a second Candidate Engine or
bypassing Family Reasoning. No analyzer performs active validation.
"""

import re
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit

import bug_candidates_family21 as _family21_import
from family_analyzers.base import FamilyAnalyzerContext
from family_analyzers.router import analyzer_for_family
from family_reasoning import candidate_evidence_schema_map
from owasp_family_catalog import (
    BUG_FAMILY_METADATA,
    DIRECT_TYPES,
    NEW_FAMILY_ORDER,
    SAFE_ACTIONS as OWASP_SAFE_ACTIONS,
)
from owasp_phase2_catalog import (
    PHASE2_BUG_FAMILY_METADATA,
    PHASE2_DIRECT_TYPES,
    PHASE2_FAMILY_ORDER,
    PHASE2_SAFE_ACTIONS,
    PHASE2_FAMILY_SPECS,
)

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

CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = "4.0.0"
_legacy.CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION

EXTENSION_FAMILY_ORDER = tuple(NEW_FAMILY_ORDER) + tuple(PHASE2_FAMILY_ORDER)

# Extend the historical metadata used by insertion/scoring. The dictionaries are
# mutated in place so all compatibility layers observe one catalog.
_core.BUG_FAMILIES.update(BUG_FAMILY_METADATA)
_core.BUG_FAMILIES.update(PHASE2_BUG_FAMILY_METADATA)
_core.SAFE_ACTIONS.update(OWASP_SAFE_ACTIONS)
_core.SAFE_ACTIONS.update(PHASE2_SAFE_ACTIONS)
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

_all_direct_types = {family: set(values) for family, values in DIRECT_TYPES.items()}
_all_direct_types.update({family: set(values) for family, values in PHASE2_DIRECT_TYPES.items()})
_legacy._FAMILY_DIRECT_TYPES.update(_all_direct_types)
_legacy._DEDICATED_ALERT_FAMILIES.update(EXTENSION_FAMILY_ORDER)

_ORIGINAL_DEDICATED_FAMILY_RESULT = _legacy._dedicated_family_result
_ORIGINAL_ALERT_CANDIDATES = _core._alert_candidates
_ORIGINAL_STATIC_CANDIDATES = _legacy._static_candidates

RAW_SURFACE_FAMILY_ROUTER_VERSION = "1.0.0"
RAW_SURFACE_FAMILY_ROUTER_RULE_VERSION = "2026.08.14.1"
_RAW_SURFACE_LIMIT = 5000

# Core and phase-one analyzers are sufficiently specialized to abstain when a
# raw surface does not belong to them. Phase-two's larger catalog is pre-routed
# by its canonical context/keyword contract to keep baseline analysis bounded.
_RAW_ALWAYS_EVALUATED_FAMILIES = tuple(
    family for family in BUG_FAMILIES if family not in PHASE2_FAMILY_ORDER
)


def _extension_analyzer_result(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    alert_id: int | None,
    endpoint: str,
    family: str,
) -> dict[str, Any] | None:
    if family not in EXTENSION_FAMILY_ORDER:
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


def _surface_method_and_fields(endpoint: str) -> tuple[str, list[str], list[str]]:
    """Extract passive URL fields without guessing an HTTP operation."""

    try:
        parsed = urlsplit(
            endpoint
            if "://" in endpoint
            else f"https://placeholder.invalid/{endpoint.lstrip('/')}"
        )
    except ValueError:
        return "UNKNOWN", [], []
    query_fields = sorted(
        {
            str(name)
            for name, _value in parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )
            if str(name)
        }
    )
    path_fields = sorted(
        set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_.-]{0,120})\}", parsed.path))
    )
    return "UNKNOWN", query_fields, path_fields


def _phase2_families_for_surface(
    details: Mapping[str, Any],
    semantic_text: str,
) -> tuple[str, ...]:
    text = semantic_text.lower()
    selected: list[str] = []
    for family in PHASE2_FAMILY_ORDER:
        spec = PHASE2_FAMILY_SPECS[family]
        if any(bool(details.get(signal)) for signal in spec["context"]):
            selected.append(family)
            continue
        if any(str(keyword).lower() in text for keyword in spec["keywords"]):
            selected.append(family)
    return tuple(selected)


def _raw_surface_rows(
    db: Any,
    *,
    run_id: str,
    target: str | None,
) -> list[dict[str, Any]]:
    params: list[Any] = [run_id]
    target_clause = ""
    if target:
        target_clause = " AND target=?"
        params.append(target)

    endpoint_rows = db.all(
        "SELECT * FROM endpoint_intelligence WHERE last_run_id=?"
        f"{target_clause} ORDER BY confidence DESC,target,endpoint LIMIT {_RAW_SURFACE_LIMIT}",
        tuple(params),
    )
    fingerprint_rows = db.all(
        "SELECT * FROM fingerprints WHERE last_run_id=?"
        f"{target_clause} ORDER BY target,url LIMIT {_RAW_SURFACE_LIMIT}",
        tuple(params),
    )
    validation_rows = db.all(
        "SELECT * FROM endpoint_validations WHERE last_run_id=?"
        f"{target_clause} ORDER BY confidence DESC,target,endpoint LIMIT {_RAW_SURFACE_LIMIT}",
        tuple(params),
    )
    finding_rows = db.all(
        "SELECT * FROM findings WHERE last_run_id=?"
        f"{target_clause} ORDER BY "
        "CASE LOWER(severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 "
        "WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC,target,matched_at "
        f"LIMIT {_RAW_SURFACE_LIMIT}",
        tuple(params),
    )
    fingerprints = {
        (str(row["target"] or ""), str(row["url"] or "")): dict(row)
        for row in fingerprint_rows
    }
    validations: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in validation_rows:
        row = dict(raw)
        current_target = str(row.get("target") or "")
        for endpoint_key in (row.get("endpoint"), row.get("resolved_url")):
            endpoint_value = str(endpoint_key or "")
            if current_target and endpoint_value:
                validations[(current_target, endpoint_value)] = row

    priority_surfaces: list[dict[str, Any]] = []
    surfaces: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    severity_confidence = {
        "critical": 96,
        "high": 90,
        "medium": 78,
        "low": 64,
        "info": 52,
        "informational": 52,
    }
    for raw in finding_rows:
        row = dict(raw)
        current_target = str(row.get("target") or "")
        details = _core._loads(row.get("details_json"), {})
        if not isinstance(details, Mapping):
            details = {}
        details = dict(details)
        endpoint = str(
            row.get("matched_at")
            or details.get("matched_at")
            or details.get("url")
            or details.get("host")
            or ""
        )
        if not current_target or not endpoint:
            continue
        details.update(
            {
                "template_id": str(row.get("template_id") or ""),
                "title": str(row.get("name") or details.get("title") or ""),
                "severity": str(row.get("severity") or "info"),
                "raw_finding_observation": True,
                "active_request_performed": False,
            }
        )
        fingerprint = fingerprints.get((current_target, endpoint), {})
        validation = validations.get((current_target, endpoint), {})
        for key in (
            "method",
            "status_code",
            "content_type",
            "reachable",
            "resolved_url",
            "error",
        ):
            if validation.get(key) not in (None, ""):
                details[key] = validation[key]
        for key in (
            "status_code",
            "webserver",
            "content_type",
            "content_length",
            "cdn",
            "cname",
            "final_url",
            "http2",
            "tls_issuer",
            "tls_expiry",
            "tls_serial",
        ):
            if fingerprint.get(key) not in (None, ""):
                details[key] = fingerprint[key]
        details["technologies"] = _core._loads(
            fingerprint.get("technologies_json"), []
        )
        priority_surfaces.append(
            {
                "target": current_target,
                "endpoint": endpoint,
                "kind": "stored_finding",
                "confidence": severity_confidence.get(
                    str(row.get("severity") or "info").lower(),
                    55,
                ),
                "details": details,
                "source_ref": (
                    f"raw-finding:{current_target}:"
                    f"{_core.sha256_text(str(row.get('dedup_key') or endpoint))[:20]}"
                ),
            }
        )
        seen.add((current_target, endpoint))

    for raw in endpoint_rows:
        row = dict(raw)
        current_target = str(row.get("target") or "")
        endpoint = str(row.get("endpoint") or "")
        if not current_target or not endpoint:
            continue
        seen.add((current_target, endpoint))
        details = {
            "category": str(row.get("primary_category") or "general"),
            "endpoint_classification": {
                "primary_category": str(row.get("primary_category") or "general"),
                "confidence": _core.parse_int(row.get("confidence"), 0),
                "categories": _core._loads(row.get("categories_json"), []),
                "reasons": _core._loads(row.get("reasons_json"), []),
            },
            "recon_sources": _core._loads(row.get("sources_json"), []),
            "raw_surface_observation": True,
            "active_request_performed": False,
        }
        fingerprint = fingerprints.get((current_target, endpoint), {})
        validation = validations.get((current_target, endpoint), {})
        for key in (
            "method",
            "status_code",
            "content_type",
            "reachable",
            "resolved_url",
            "error",
        ):
            if validation.get(key) not in (None, ""):
                details[key] = validation[key]
        for key in (
            "status_code",
            "title",
            "webserver",
            "content_type",
            "content_length",
            "cdn",
            "cname",
            "final_url",
            "http2",
            "tls_issuer",
            "tls_expiry",
            "tls_serial",
        ):
            if fingerprint.get(key) not in (None, ""):
                details[key] = fingerprint[key]
        details["technologies"] = _core._loads(
            fingerprint.get("technologies_json"), []
        )
        surfaces.append(
            {
                "target": current_target,
                "endpoint": endpoint,
                "kind": str(row.get("kind") or "endpoint"),
                "confidence": _core.parse_int(row.get("confidence"), 0),
                "details": details,
                "source_ref": (
                    f"raw-endpoint:{current_target}:{row.get('kind') or 'endpoint'}:"
                    f"{_core.sha256_text(endpoint)[:20]}"
                ),
            }
        )

    # Preserve safe, stored endpoint-validation metadata even when an endpoint
    # has no classification row (for example a legacy replay database).
    for raw in validation_rows:
        row = dict(raw)
        current_target = str(row.get("target") or "")
        endpoint = str(row.get("resolved_url") or row.get("endpoint") or "")
        if not current_target or not endpoint or (current_target, endpoint) in seen:
            continue
        seen.add((current_target, endpoint))
        surfaces.append(
            {
                "target": current_target,
                "endpoint": endpoint,
                "kind": "endpoint_validation",
                "confidence": _core.parse_int(row.get("confidence"), 0),
                "details": {
                    "method": str(row.get("method") or "UNKNOWN"),
                    "status_code": row.get("status_code"),
                    "content_type": str(row.get("content_type") or ""),
                    "reachable": bool(row.get("reachable")),
                    "error": str(row.get("error") or ""),
                    "raw_surface_observation": True,
                    "active_request_performed": False,
                },
                "source_ref": (
                    f"raw-validation:{current_target}:"
                    f"{_core.sha256_text(endpoint)[:20]}"
                ),
            }
        )

    # A live HTTP fingerprint may not have been classified as an endpoint (for
    # example, the root URL). It is still useful passive family context.
    for (current_target, endpoint), fingerprint in fingerprints.items():
        if not current_target or not endpoint or (current_target, endpoint) in seen:
            continue
        details = {
            key: fingerprint[key]
            for key in (
                "status_code",
                "title",
                "webserver",
                "content_type",
                "content_length",
                "cdn",
                "cname",
                "final_url",
                "http2",
                "tls_issuer",
                "tls_expiry",
                "tls_serial",
            )
            if fingerprint.get(key) not in (None, "")
        }
        details.update(
            {
                "technologies": _core._loads(
                    fingerprint.get("technologies_json"), []
                ),
                "raw_surface_observation": True,
                "active_request_performed": False,
            }
        )
        surfaces.append(
            {
                "target": current_target,
                "endpoint": endpoint,
                "kind": "http_fingerprint",
                "confidence": 70,
                "details": details,
                "source_ref": (
                    f"raw-fingerprint:{current_target}:"
                    f"{_core.sha256_text(endpoint)[:20]}"
                ),
            }
        )

    # DNS CNAME observations are routed narrowly to Subdomain Takeover. They
    # establish dependency context only; claimability is never inferred.
    dns_rows = db.all(
        "SELECT target,host,rrtype,value FROM dns_records "
        "WHERE last_run_id=? AND is_current=1 AND rrtype='CNAME'"
        f"{target_clause} ORDER BY target,host LIMIT {_RAW_SURFACE_LIMIT}",
        tuple(params),
    )
    for raw in dns_rows:
        row = dict(raw)
        current_target = str(row.get("target") or "")
        host = str(row.get("host") or "")
        if not current_target or not host:
            continue
        surfaces.append(
            {
                "target": current_target,
                "endpoint": host,
                "kind": "dns_cname",
                "confidence": 70,
                "details": {
                    "rrtype": "CNAME",
                    "cname": str(row.get("value") or ""),
                    "raw_surface_observation": True,
                    "active_request_performed": False,
                },
                "source_ref": (
                    f"raw-cname:{current_target}:{_core.sha256_text(host)[:20]}"
                ),
            }
        )
    # Explicit stored findings receive priority, then the remaining bounded raw
    # inventory. Duplicate endpoints are still allowed across source kinds so
    # record_hypothesis can merge independent evidence roots by family/variant.
    return (priority_surfaces + surfaces)[:_RAW_SURFACE_LIMIT]


def _raw_surface_family_candidates(
    db: Any,
    *,
    analysis_id: str,
    run_id: str,
    target: str | None,
) -> int:
    promoted = 0
    for surface in _raw_surface_rows(db, run_id=run_id, target=target):
        endpoint = str(surface["endpoint"])
        current_target = str(surface["target"])
        method, query_fields, path_fields = _surface_method_and_fields(endpoint)
        context_method = str(surface["details"].get("method") or method or "UNKNOWN")
        semantic_text = " ".join(
            [
                endpoint,
                str(surface.get("kind") or ""),
                _core.json_dumps(surface["details"]),
                " ".join(query_fields + path_fields),
            ]
        )
        context = FamilyAnalyzerContext(
            db=db,
            analysis_id=analysis_id,
            target=current_target,
            endpoint=endpoint,
            method=str(context_method).upper(),
            details=surface["details"],
            business_context="general",
        )
        if surface.get("kind") == "dns_cname":
            families = ("subdomain_takeover",)
        else:
            families = (
                *_RAW_ALWAYS_EVALUATED_FAMILIES,
                *_phase2_families_for_surface(context.details, semantic_text),
            )
        for family in dict.fromkeys(families):
            analyzer = analyzer_for_family(family)
            if analyzer is None:
                continue
            analyzer_kwargs: dict[str, Any] = {
                "object_ids": [
                    value
                    for value in path_fields + query_fields
                    if value.lower() == "id" or value.lower().endswith("id")
                ],
                "structural_fields": path_fields + query_fields,
                "body_fields": [],
                "query_fields": query_fields,
                "path_fields": path_fields,
                "auth_hints": [],
                "semantic_text": semantic_text,
            }
            # Compatibility analyzers have intentionally different keyword
            # surfaces. Remove only an explicitly rejected keyword; propagate
            # every other TypeError so genuine analyzer defects remain visible.
            while True:
                try:
                    dedicated = analyzer.analyze(context, **analyzer_kwargs)
                    break
                except TypeError as exc:
                    match = re.search(
                        r"unexpected keyword argument ['\"]([^'\"]+)['\"]",
                        str(exc),
                    )
                    if not match or match.group(1) not in analyzer_kwargs:
                        raise
                    analyzer_kwargs.pop(match.group(1))
            if not dedicated:
                continue
            if _legacy._promote_static_family_result(
                db,
                analysis_id=analysis_id,
                run_id=run_id,
                target=current_target,
                endpoint=endpoint,
                source_ref=str(surface["source_ref"]),
                family=family,
                dedicated=dedicated,
                confidence=_core.parse_int(surface.get("confidence"), 0),
            ):
                promoted += 1
    return promoted


def _dedicated_family_result_extended(
    db: Any,
    *,
    analysis_id: str,
    target: str,
    alert_id: int | None,
    endpoint: str,
    family: str,
) -> dict[str, Any] | None:
    if family in EXTENSION_FAMILY_ORDER:
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


def _extension_families_for_alert(
    category: str,
    schema: Mapping[str, Any],
    details: Mapping[str, Any],
) -> tuple[str, ...]:
    """Return only families that can consume this stored observation safely.

    Endpoint observations keep the complete expansion family set. Infrastructure
    observations fail closed except for DNS CNAME changes, which are routed only
    to the Subdomain Takeover analyzer. A CNAME is discovery context, never
    takeover proof; Family Reasoning still requires independent target evidence
    before admission.
    """

    category = str(category or "")
    if category == "dns_change":
        rrtype = str(details.get("rrtype") or "").upper().strip()
        return ("subdomain_takeover",) if rrtype == "CNAME" else ()
    if schema.get("is_endpoint") is False or category in {"new_subdomain", "new_port"}:
        return ()
    return EXTENSION_FAMILY_ORDER


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
    details = _core._loads(row.get("details_json"), {})
    category = str(row.get("category") or "")
    families = _extension_families_for_alert(category, schema, details)
    if not families:
        return count
    endpoint = str(schema.get("endpoint") or row.get("item") or "")
    alert_id = int(row["alert_id"])
    for family in families:
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


def _static_candidates_with_raw_family_routing(
    db: Any,
    analysis_id: str,
    run_id: str,
    target: str | None,
) -> int:
    existing = _ORIGINAL_STATIC_CANDIDATES(db, analysis_id, run_id, target)
    return existing + _raw_surface_family_candidates(
        db,
        analysis_id=analysis_id,
        run_id=run_id,
        target=target,
    )


# Functions in the historical Candidate Engine resolve _alert_candidates through
# its own module globals, so replacing it here extends the real generation path.
_core._alert_candidates = _alert_candidates_with_owasp_expansion
_compat._alert_candidates = _alert_candidates_with_owasp_expansion
_compat._static_candidates = _static_candidates_with_raw_family_routing
_legacy._static_candidates = _static_candidates_with_raw_family_routing

# Keep existing hypothesis/evidence/static hooks from the 21-family layer.
record_hypothesis = _legacy.record_hypothesis
_evidence_strength = _legacy._evidence_strength
_static_candidates = _static_candidates_with_raw_family_routing

# Publish the mutated catalogs and preserve the existing 21-family hooks.
BUG_FAMILIES = _core.BUG_FAMILIES
SAFE_ACTIONS = _core.SAFE_ACTIONS
FAMILY_EVIDENCE_SCHEMAS = _schema_map
CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = "4.0.0"
record_hypothesis = _legacy.record_hypothesis
_evidence_strength = _legacy._evidence_strength
_static_candidates = _static_candidates_with_raw_family_routing

_ORIGINAL_GENERATE_BUG_CANDIDATES = _core.generate_bug_candidates


def generate_bug_candidates(
    db: Any,
    analysis_id: str,
    run_id: str,
    target: str | None = None,
) -> dict[str, Any]:
    """Run the canonical engine and expose raw-routing observability."""

    result = dict(
        _ORIGINAL_GENERATE_BUG_CANDIDATES(
            db,
            analysis_id,
            run_id,
            target,
        )
    )
    raw_hypotheses = int(
        db.one(
            "SELECT COUNT(*) count FROM analysis_hypotheses "
            "WHERE analysis_id=? AND source_ref LIKE 'raw-%'",
            (analysis_id,),
        )["count"]
    )
    raw_promoted = int(
        db.one(
            "SELECT COUNT(*) count FROM analysis_hypotheses "
            "WHERE analysis_id=? AND source_ref LIKE 'raw-%' "
            "AND state='promoted'",
            (analysis_id,),
        )["count"]
    )
    raw_families = int(
        db.one(
            "SELECT COUNT(DISTINCT bug_family) count FROM analysis_hypotheses "
            "WHERE analysis_id=? AND source_ref LIKE 'raw-%'",
            (analysis_id,),
        )["count"]
    )
    result["raw_surface_routing"] = {
        "version": RAW_SURFACE_FAMILY_ROUTER_VERSION,
        "rule_version": RAW_SURFACE_FAMILY_ROUTER_RULE_VERSION,
        "hypotheses": raw_hypotheses,
        "promoted": raw_promoted,
        "families": raw_families,
        "surface_limit": _RAW_SURFACE_LIMIT,
        "active_requests": 0,
    }
    return result

__all__ = [name for name in globals() if not name.startswith("__")]
