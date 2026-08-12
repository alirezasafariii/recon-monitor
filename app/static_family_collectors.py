from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from core import Database, parse_int
from family_detectors.registry import DETECTOR_SPECS

STATIC_SPECIALIZED_COLLECTOR_VERSION = "1.0.0"
STATIC_SPECIALIZED_COLLECTOR_RULE_VERSION = "2026.08.12.6.24"
STATIC_SPECIALIZED_FAMILIES = (
    "source_map_exposure",
    "secret_exposure",
    "graphql_authorization",
    "graphql_data_exposure",
    "websocket_authorization",
)


@dataclass(frozen=True)
class StaticFamilyObservation:
    target: str
    endpoint: str
    source_ref: str
    family: str
    variant: str
    likelihood: int
    evidence_strength: int
    impact: int
    support: tuple[dict[str, Any], ...]
    contradict: tuple[dict[str, Any], ...]
    missing: tuple[str, ...]
    rules: tuple[str, ...]
    summary: str


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def _strength(confidence: int, support: list[dict[str, Any]], contradict: list[dict[str, Any]], *, direct: bool = False) -> int:
    sources = {str(item.get("source") or item.get("type") or "rule") for item in support}
    value = 18 + min(32, confidence * 0.34) + min(30, len(support) * 8) + min(12, len(sources) * 4)
    if direct:
        value += 12
    value -= min(16, len(contradict) * 4)
    return _clamp(value, 10, 96)


def _list_json(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def validate_static_specialized_collectors() -> list[str]:
    errors: list[str] = []
    for family in STATIC_SPECIALIZED_FAMILIES:
        spec = DETECTOR_SPECS.get(family)
        if spec is None:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if not spec.wstg_ids:
            errors.append(f"static detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"static detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"static detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"static detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"static detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"static detector lacks condition contract: {family}")
    return errors


def collect_specialized_static_observations(db: Database, analysis_id: str, target: str | None = None) -> list[StaticFamilyObservation]:
    errors = validate_static_specialized_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.24 specialized static registry: " + "; ".join(errors))

    observations: list[StaticFamilyObservation] = []
    params: list[Any] = [analysis_id]
    target_clause = ""
    if target:
        target_clause = " AND target=?"
        params.append(target)

    for row in db.all(f"SELECT * FROM source_map_intelligence WHERE analysis_id=?{target_clause}", tuple(params)):
        internal_count = parse_int(row["internal_source_count"], 0)
        if internal_count <= 0:
            continue
        support = [
            {"type": "source_map", "source": "source_map_intelligence", "source_group": "source_map_surface", "weight": 22, "text": f"Referenced source map contains {parse_int(row['source_count'],0)} source entries."},
            {"type": "internal_sources", "source": "source_map_intelligence", "source_group": "source_map_contents", "weight": 16, "text": f"{internal_count} internal-looking source paths were identified in stored source-map intelligence."},
        ]
        observations.append(StaticFamilyObservation(
            target=str(row["target"]), endpoint=str(row["source_map_url"]), source_ref=f"source-map:{row['js_url']}",
            family="source_map_exposure", variant="internal_source_paths", likelihood=62, evidence_strength=78, impact=52,
            support=tuple(support), contradict=(),
            missing=("Verified public reachability of the source-map URL", "Whether sourcesContent or equivalent meaningful original source is exposed"),
            rules=("static-collector-specialized-v1", "candidate-source-map", "candidate-internal-source-path"),
            summary="A referenced source map contains internal-looking source metadata; promotion still requires meaningful source content and verified public reachability.",
        ))

    for row in db.all(f"SELECT * FROM secret_intelligence WHERE analysis_id=?{target_clause}", tuple(params)):
        assessment = str(row["assessment"]); confidence = parse_int(row["confidence"], 0)
        support = [
            {"type": "secret_pattern", "source": "secret_intelligence", "source_group": "secret_pattern", "weight": 26, "text": f"A redacted {row['secret_kind']} pattern was detected in production JavaScript."},
            {"type": "production_javascript", "source": "secret_intelligence", "source_group": "client_context", "weight": 10, "text": "The redacted secret-like material was observed in client-delivered JavaScript."},
        ]
        contradict: list[dict[str, Any]] = []
        if assessment == "likely_placeholder":
            contradict.append({"type": "placeholder", "source": "secret_intelligence", "source_group": "secret_assessment", "weight": -24, "text": "Stored secret intelligence classifies the value as a likely example/test/placeholder."})
        else:
            support.append({"type": "non_placeholder_secret", "source": "secret_intelligence", "source_group": "secret_assessment", "weight": 18, "text": "Secret intelligence did not classify the redacted value as a known placeholder."})
        likelihood = _clamp(24 + confidence * 0.5 + sum(parse_int(x.get("weight"), 0) for x in contradict))
        observations.append(StaticFamilyObservation(
            target=str(row["target"]), endpoint=str(row["js_url"]), source_ref=f"secret:{row['js_url']}:{row['value_fingerprint']}",
            family="secret_exposure", variant=str(row["secret_kind"]), likelihood=likelihood,
            evidence_strength=_strength(confidence, support, contradict, direct=True), impact=90,
            support=tuple(support), contradict=tuple(contradict),
            missing=("Whether the credential remains live", "Intended exposure and privilege", "Rotation or revocation status"),
            rules=("static-collector-specialized-v1", "candidate-secret-pattern", "candidate-client-secret"),
            summary="A redacted credential- or token-like value appears in production client JavaScript; no online credential validation is performed.",
        ))

    for row in db.all(f"SELECT * FROM graphql_intelligence WHERE analysis_id=?{target_clause}", tuple(params)):
        identifiers = [str(x) for x in _list_json(row["identifiers_json"])]
        sensitive = [str(x) for x in _list_json(row["sensitive_fields_json"])]
        confidence = parse_int(row["confidence"], 0)
        if identifiers:
            support = [
                {"type": "graphql_identifier", "source": "graphql_intelligence", "source_group": "graphql_identifier", "weight": 20, "text": f"GraphQL object identifiers observed: {', '.join(identifiers[:6])}."},
                {"type": "graphql_operation", "source": "graphql_intelligence", "source_group": "graphql_operation", "weight": 12, "text": f"Client-visible {row['operation_type']} operation is stored in GraphQL intelligence."},
            ]
            observations.append(StaticFamilyObservation(
                target=str(row["target"]), endpoint="/graphql", source_ref=f"graphql:{row['js_url']}:{row['operation_name']}",
                family="graphql_authorization", variant="object_boundary",
                likelihood=_clamp(32 + confidence * 0.35 + len(identifiers) * 3),
                evidence_strength=_strength(confidence, support, [], direct=True), impact=80,
                support=tuple(support), contradict=(),
                missing=("Resolver-level authorization failure evidence", "Expected object ownership/tenant boundary", "Controlled cross-identity or cross-tenant response comparison"),
                rules=("static-collector-specialized-v1", "candidate-graphql-identifier", "candidate-graphql-authorization"),
                summary="A client-visible GraphQL operation accepts object identifiers; resolver/object authorization failure remains unproven.",
            ))
        if sensitive:
            support = [
                {"type": "sensitive_fields", "source": "graphql_intelligence", "source_group": "graphql_fields", "weight": 20, "text": f"Sensitive GraphQL fields observed: {', '.join(sensitive[:8])}."},
                {"type": "client_operation", "source": "graphql_intelligence", "source_group": "graphql_operation", "weight": 10, "text": "Sensitive fields are referenced by a stored client GraphQL operation."},
            ]
            observations.append(StaticFamilyObservation(
                target=str(row["target"]), endpoint="/graphql", source_ref=f"graphql-data:{row['js_url']}:{row['operation_name']}",
                family="graphql_data_exposure", variant="sensitive_fields",
                likelihood=_clamp(24 + confidence * 0.32 + len(sensitive) * 2),
                evidence_strength=_strength(confidence, support, [], direct=True), impact=68,
                support=tuple(support), contradict=(),
                missing=("Actual response data for the current role", "Field-level authorization policy", "Evidence that sensitive fields cross the intended field policy"),
                rules=("static-collector-specialized-v1", "candidate-graphql-sensitive-field", "candidate-graphql-data"),
                summary="A GraphQL operation references sensitive fields; actual response exposure beyond the caller's field policy remains unproven.",
            ))

    ws_params: list[Any] = [analysis_id]
    ws_clause = ""
    if target:
        ws_clause = " AND target=?"
        ws_params.append(target)
    for row in db.all(f"SELECT * FROM js_dataflows WHERE analysis_id=? AND sink_kind='websocket'{ws_clause}", tuple(ws_params)):
        confidence = parse_int(row["confidence"], 0)
        support = [
            {"type": "websocket_url", "source": "javascript_dataflow", "source_group": "websocket_surface", "weight": 14, "text": "Stored JavaScript data-flow intelligence reaches WebSocket construction/messaging."},
        ]
        observations.append(StaticFamilyObservation(
            target=str(row["target"]), endpoint="", source_ref=f"js-dataflow:{row['js_url']}:{row['source_kind']}:websocket",
            family="websocket_authorization", variant="client_channel_construction",
            likelihood=_clamp(28 + confidence * 0.45 + 6), evidence_strength=_strength(confidence, support, [], direct=True), impact=76,
            support=tuple(support), contradict=({"type": "static_only", "source": "analysis_limit", "source_group": "static_limit", "weight": -8, "text": "Static WebSocket construction does not prove channel identity scope or subscription authorization failure."},),
            missing=("Actual channel/room/tenant identity relation", "Subscription/message authorization behavior", "Controlled out-of-scope subscription or message evidence"),
            rules=("static-collector-specialized-v1", "candidate-js-websocket", "candidate-websocket-authorization"),
            summary="Client JavaScript constructs or feeds a WebSocket channel surface; channel/identity authorization failure remains unproven.",
        ))

    return observations
